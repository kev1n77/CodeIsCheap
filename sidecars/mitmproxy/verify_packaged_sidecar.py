"""Exercise the packaged proxy, addon scrubber, and IPC transport end to end."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import gzip
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import brotli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


CANARIES = {
    "authorization": "Bearer header-canary",
    "header_api_key": "header-api-key-canary",
    "query": "query-canary",
    "body": "body-canary",
    "response_cookie": "response-cookie-canary",
    "response_body": "response-body-canary",
}
TARGET_CASES = ("gzip", "brotli", "sse")


class UpstreamHandler(BaseHTTPRequestHandler):
    received: dict[str, dict[str, Any]] = {}
    received_event = threading.Event()
    received_lock = threading.Lock()

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        case = parse_qs(urlsplit(self.path).query).get("case", [""])[0]
        if case not in TARGET_CASES:
            self.send_error(400)
            return
        received = {
            "path": self.path,
            "authorization": self.headers.get("authorization"),
            "x_api_key": self.headers.get("x-api-key"),
            "body": self.rfile.read(length).decode("utf-8"),
        }
        with type(self).received_lock:
            type(self).received[case] = received
            if len(type(self).received) == len(TARGET_CASES):
                type(self).received_event.set()
        self.send_response(200)
        if case == "sse":
            payload = (
                'event: message\ndata: {"delta":"done","access_token":"'
                + CANARIES["response_body"]
                + '"}\n\ndata: [DONE]\n\n'
            ).encode()
            content_type = "text/event-stream"
            content_encoding = None
        else:
            payload = json.dumps(
                {
                    "ok": True,
                    "case": case,
                    "access_token": CANARIES["response_body"],
                }
            ).encode()
            content_type = "application/json"
            if case == "gzip":
                payload = gzip.compress(payload)
                content_encoding = "gzip"
            else:
                payload = brotli.compress(payload)
                content_encoding = "br"
        self.send_header("content-type", content_type)
        if content_encoding:
            self.send_header("content-encoding", content_encoding)
        self.send_header("set-cookie", CANARIES["response_cookie"])
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class TunnelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received_event = threading.Event()

    def do_GET(self) -> None:
        type(self).received_event.set()
        payload = b"non-target tunnel preserved"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(payload)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def create_tls_server(root: Path) -> tuple[ThreadingHTTPServer, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = root / "tunnel-cert.pem"
    key_path = root / "tunnel-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), TunnelHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server, certificate.public_bytes(serialization.Encoding.DER)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_for_port(port: int, process: subprocess.Popen[bytes], timeout_seconds: float = 20) -> int:
    started = time.monotonic()
    deadline = started + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("packaged sidecar exited before accepting connections")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return int((time.monotonic() - started) * 1000)
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("packaged sidecar did not start in time")


def stop_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        process.wait(timeout=5)
        return

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def request_target_case(proxy_port: int, upstream_port: int, case: str) -> dict[str, Any]:
    body = json.dumps(
        {
            "api_key": CANARIES["body"],
            "messages": [{"role": "user", "content": f"preserved prompt {case}"}],
        }
    )
    target = (
        f"http://localhost:{upstream_port}/v1/chat/completions"
        f"?case={case}&access_token={CANARIES['query']}"
    )
    client = HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    client.request(
        "POST",
        target,
        body=body,
        headers={
            "authorization": CANARIES["authorization"],
            "x-api-key": CANARIES["header_api_key"],
            "content-type": "application/json",
        },
    )
    response = client.getresponse()
    payload = response.read()
    result = {
        "status": response.status,
        "content_type": response.getheader("content-type"),
        "content_encoding": response.getheader("content-encoding"),
        "cookie": response.getheader("set-cookie"),
        "body": payload,
    }
    client.close()
    return result


def request_non_target_tunnel(
    proxy_port: int, tunnel_port: int
) -> tuple[bytes, bytes]:
    connection = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    connection.sendall(
        (
            f"CONNECT 127.0.0.1:{tunnel_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{tunnel_port}\r\n\r\n"
        ).encode()
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("proxy closed the non-target CONNECT request")
        response += chunk
    if not response.startswith(b"HTTP/1.1 200"):
        raise RuntimeError("proxy rejected the non-target CONNECT request")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with context.wrap_socket(connection, server_hostname="127.0.0.1") as tls:
        peer_certificate = tls.getpeercert(binary_form=True)
        tls.sendall(
            b"GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        forwarded = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            forwarded += chunk
    return peer_certificate, forwarded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="codeischeap-sidecar-") as directory:
        root = Path(directory)
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        tunnel, tunnel_certificate = create_tls_server(root)
        tunnel_thread = threading.Thread(target=tunnel.serve_forever, daemon=True)
        tunnel_thread.start()

        ipc_listener = socket.socket()
        ipc_listener.bind(("127.0.0.1", 0))
        ipc_listener.listen(len(TARGET_CASES) * 2)
        ipc_frames: list[tuple[bytes, bytes]] = []

        def receive_ipc() -> None:
            for _ in range(len(TARGET_CASES) * 2):
                connection, _ = ipc_listener.accept()
                with connection:
                    stream = connection.makefile("rb")
                    ipc_frames.append((stream.readline(), stream.readline()))

        ipc_thread = threading.Thread(target=receive_ipc, daemon=True)
        ipc_thread.start()

        proxy_port = free_port()
        token = "synthetic-ipc-token"
        environment = os.environ.copy()
        environment.update(
            {
                "CIC_CAPTURE_HOSTS": "localhost",
                "CIC_CAPTURE_IPC_ADDR": f"127.0.0.1:{ipc_listener.getsockname()[1]}",
                "CIC_CAPTURE_IPC_TOKEN": token,
            }
        )
        confdir = root / "conf"
        confdir.mkdir()
        process = subprocess.Popen(
            [
                str(arguments.executable),
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(proxy_port),
                "--set",
                f"confdir={confdir}",
                "--set",
                "termlog_verbosity=error",
                "--allow-hosts",
                r"^localhost:\d+$",
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            startup_ms = wait_for_port(proxy_port, process)
            forwarded_responses = {
                case: request_target_case(proxy_port, upstream.server_port, case)
                for case in TARGET_CASES
            }
            if not UpstreamHandler.received_event.wait(5):
                raise TimeoutError("upstream did not receive every forwarded request")
            ipc_thread.join(timeout=5)
            if ipc_thread.is_alive() or len(ipc_frames) != len(TARGET_CASES) * 2:
                raise TimeoutError("addon did not deliver every request and response envelope")

            frames = [(json.loads(auth), json.loads(envelope)) for auth, envelope in ipc_frames]
            if any(auth.get("token") != token for auth, _ in frames):
                raise RuntimeError("IPC auth token was not preserved in every auth frame")
            envelopes = [envelope for _, envelope in frames]
            encoded_envelopes = json.dumps(envelopes)
            if any(canary in encoded_envelopes for canary in CANARIES.values()):
                raise RuntimeError("a credential canary crossed the sidecar IPC boundary")
            for case in TARGET_CASES:
                case_envelopes = [
                    envelope
                    for envelope in envelopes
                    if f"preserved prompt {case}" in json.dumps(envelope)
                ]
                if len(case_envelopes) != 2:
                    raise RuntimeError(f"{case} request/response envelopes were not paired")
                request_envelope = next(
                    envelope for envelope in case_envelopes if "outcome" not in envelope
                )
                response_envelope = next(
                    envelope
                    for envelope in case_envelopes
                    if envelope.get("outcome", {}).get("kind") == "response"
                )
                if request_envelope["capture_id"] != response_envelope["capture_id"]:
                    raise RuntimeError(f"{case} request and response capture IDs differ")
                response_result = response_envelope["outcome"]["result"]
                if response_result["status"] != 200:
                    raise RuntimeError(f"{case} response status was not captured")
                captured_body = response_result["body"]
                if case == "sse":
                    if (
                        captured_body["state"] != "text"
                        or 'data: {"delta":"done"}' not in captured_body["content"]
                    ):
                        raise RuntimeError("sanitized SSE response was not preserved")
                elif captured_body["content"] != {"ok": True, "case": case}:
                    raise RuntimeError(f"sanitized {case} response was not preserved")

                forwarded = UpstreamHandler.received[case]
                if forwarded["authorization"] != CANARIES["authorization"]:
                    raise RuntimeError(f"authorization changed for {case}")
                if forwarded["x_api_key"] != CANARIES["header_api_key"]:
                    raise RuntimeError(f"API key changed for {case}")
                if CANARIES["query"] not in forwarded["path"]:
                    raise RuntimeError(f"query changed for {case}")
                if CANARIES["body"] not in forwarded["body"]:
                    raise RuntimeError(f"body changed for {case}")

                response = forwarded_responses[case]
                if response["status"] != 200 or response["cookie"] != CANARIES["response_cookie"]:
                    raise RuntimeError(f"{case} response metadata changed during forwarding")
                if case == "gzip":
                    forwarded_body = gzip.decompress(response["body"]).decode()
                    expected_encoding = "gzip"
                elif case == "brotli":
                    forwarded_body = brotli.decompress(response["body"]).decode()
                    expected_encoding = "br"
                else:
                    forwarded_body = response["body"].decode()
                    expected_encoding = None
                if response["content_encoding"] != expected_encoding:
                    raise RuntimeError(f"{case} content encoding changed during forwarding")
                if CANARIES["response_body"] not in forwarded_body:
                    raise RuntimeError(f"{case} response body changed during forwarding")

            peer_certificate, tunnel_response = request_non_target_tunnel(
                proxy_port, tunnel.server_port
            )
            if peer_certificate != tunnel_certificate:
                raise RuntimeError("non-target TLS certificate was intercepted")
            if b"non-target tunnel preserved" not in tunnel_response:
                raise RuntimeError("non-target TLS response changed during tunneling")
            if not TunnelHandler.received_event.wait(5):
                raise TimeoutError("non-target TLS server did not receive the tunneled request")
            ipc_listener.settimeout(0.5)
            try:
                unexpected, _ = ipc_listener.accept()
            except TimeoutError:
                pass
            else:
                unexpected.close()
                raise RuntimeError("non-target TLS traffic crossed the capture IPC boundary")

            print(
                json.dumps(
                    {
                        "started": True,
                        "startup_ms": startup_ms,
                        "forwarding_preserved": True,
                        "credential_canaries_in_envelope": 0,
                        "prompt_preserved": True,
                        "response_preserved": True,
                        "compressed_response_preserved": True,
                        "stream_credentials_removed": True,
                        "non_target_tunnel": True,
                    }
                )
            )
        finally:
            stop_process_tree(process)
            upstream.shutdown()
            upstream.server_close()
            tunnel.shutdown()
            tunnel.server_close()
            ipc_listener.close()


if __name__ == "__main__":
    main()
