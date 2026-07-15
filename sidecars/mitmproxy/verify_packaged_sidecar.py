"""Exercise the packaged proxy, addon scrubber, and IPC transport end to end."""

from __future__ import annotations

import argparse
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any


CANARIES = {
    "authorization": "Bearer header-canary",
    "header_api_key": "header-api-key-canary",
    "query": "query-canary",
    "body": "body-canary",
    "response_cookie": "response-cookie-canary",
    "response_body": "response-body-canary",
}


class UpstreamHandler(BaseHTTPRequestHandler):
    received: dict[str, Any] = {}
    received_event = threading.Event()

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        type(self).received = {
            "path": self.path,
            "authorization": self.headers.get("authorization"),
            "x_api_key": self.headers.get("x-api-key"),
            "body": self.rfile.read(length).decode("utf-8"),
        }
        type(self).received_event.set()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("set-cookie", CANARIES["response_cookie"])
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {"ok": True, "access_token": CANARIES["response_body"]}
            ).encode()
        )

    def log_message(self, format: str, *args: object) -> None:
        del format, args


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    arguments = parser.parse_args()

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    ipc_listener = socket.socket()
    ipc_listener.bind(("127.0.0.1", 0))
    ipc_listener.listen(2)
    ipc_frames: list[tuple[bytes, bytes]] = []

    def receive_ipc() -> None:
        for _ in range(2):
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
            "CIC_CAPTURE_HOSTS": "127.0.0.1",
            "CIC_CAPTURE_IPC_ADDR": f"127.0.0.1:{ipc_listener.getsockname()[1]}",
            "CIC_CAPTURE_IPC_TOKEN": token,
        }
    )

    with tempfile.TemporaryDirectory(prefix="codeischeap-sidecar-") as confdir:
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
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            startup_ms = wait_for_port(proxy_port, process)
            body = json.dumps(
                {
                    "api_key": CANARIES["body"],
                    "messages": [{"role": "user", "content": "preserved prompt"}],
                }
            )
            target = (
                f"http://127.0.0.1:{upstream.server_port}/v1/chat/completions"
                f"?access_token={CANARIES['query']}"
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
            forwarded_response_body = response.read().decode()
            forwarded_response_cookie = response.getheader("set-cookie")
            client.close()
            if response.status != 200:
                raise RuntimeError(f"unexpected proxy response status: {response.status}")
            if not UpstreamHandler.received_event.wait(5):
                raise TimeoutError("upstream did not receive the forwarded request")
            ipc_thread.join(timeout=5)
            if ipc_thread.is_alive() or len(ipc_frames) != 2:
                raise TimeoutError("addon did not deliver request and response IPC envelopes")

            frames = [(json.loads(auth), json.loads(envelope)) for auth, envelope in ipc_frames]
            if any(auth.get("token") != token for auth, _ in frames):
                raise RuntimeError("IPC auth token was not preserved in every auth frame")
            envelopes = [envelope for _, envelope in frames]
            encoded_envelopes = json.dumps(envelopes)
            if any(canary in encoded_envelopes for canary in CANARIES.values()):
                raise RuntimeError("a credential canary crossed the sidecar IPC boundary")
            if "preserved prompt" not in encoded_envelopes:
                raise RuntimeError("the prompt was lost during capture")
            request_envelope = next(
                envelope for envelope in envelopes if "outcome" not in envelope
            )
            response_envelope = next(
                envelope
                for envelope in envelopes
                if envelope.get("outcome", {}).get("kind") == "response"
            )
            if request_envelope["capture_id"] != response_envelope["capture_id"]:
                raise RuntimeError("request and response capture IDs differ")
            response_result = response_envelope["outcome"]["result"]
            if response_result["status"] != 200 or response_result["body"]["content"] != {
                "ok": True
            }:
                raise RuntimeError("the sanitized response outcome was not preserved")

            forwarded = UpstreamHandler.received
            if forwarded["authorization"] != CANARIES["authorization"]:
                raise RuntimeError("authorization was changed on the forwarded request")
            if forwarded["x_api_key"] != CANARIES["header_api_key"]:
                raise RuntimeError("API key was changed on the forwarded request")
            if CANARIES["query"] not in forwarded["path"]:
                raise RuntimeError("query was changed on the forwarded request")
            if CANARIES["body"] not in forwarded["body"]:
                raise RuntimeError("body was changed on the forwarded request")
            if forwarded_response_cookie != CANARIES["response_cookie"]:
                raise RuntimeError("set-cookie was changed on the forwarded response")
            if CANARIES["response_body"] not in forwarded_response_body:
                raise RuntimeError("body was changed on the forwarded response")

            print(
                json.dumps(
                    {
                        "started": True,
                        "startup_ms": startup_ms,
                        "forwarding_preserved": True,
                        "credential_canaries_in_envelope": 0,
                        "prompt_preserved": True,
                        "response_preserved": True,
                    }
                )
            )
        finally:
            stop_process_tree(process)
            upstream.shutdown()
            upstream.server_close()
            ipc_listener.close()


if __name__ == "__main__":
    main()
