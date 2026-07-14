"""Security boundary for the CodeIsCheap mitmproxy capture sidecar."""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import threading
import time
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit


IPC_PROTOCOL = "codeischeap.capture-ipc"
IPC_PROTOCOL_VERSION = "0.1"
CAPTURE_ENVELOPE_VERSION = "0.1"
DEFAULT_TARGET_HOSTS = frozenset(
    {
        "api.anthropic.com",
        "api.mistral.ai",
        "api.openai.com",
        "generativelanguage.googleapis.com",
    }
)
SENSITIVE_NAMES = frozenset(
    {
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "password",
        "proxyauthorization",
        "secret",
        "setcookie",
        "token",
        "accesstoken",
        "anthropicapikey",
        "xapikey",
    }
)


def _normalized_name(name: str) -> str:
    return "".join(character for character in name.lower() if character.isalnum())


def _is_sensitive(name: str) -> bool:
    return _normalized_name(name) in SENSITIVE_NAMES


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _header_items(headers: Any) -> Iterable[tuple[str, str]]:
    try:
        items = headers.items(multi=True)
    except TypeError:
        items = headers.items()
    return ((_text(name), _text(value)) for name, value in items)


def _header_value(headers: Any, name: str) -> str:
    value = headers.get(name, "")
    return _text(value)


def _redaction(location: str, name: str) -> dict[str, str]:
    return {"location": location, "name": name}


def _sanitize_headers(headers: Any) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    captured = []
    redactions = []
    for name, value in _header_items(headers):
        if _is_sensitive(name):
            redactions.append(_redaction("header", name))
        else:
            captured.append({"name": name.lower(), "value": value})
    return captured, redactions


def _sanitize_query(query: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    captured = []
    redactions = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if _is_sensitive(name):
            redactions.append(_redaction("query", name))
        else:
            captured.append({"name": name, "value": value})
    return captured, redactions


def _sanitize_json(value: Any, redactions: list[dict[str, str]]) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, child in value.items():
            key_text = _text(key)
            if _is_sensitive(key_text):
                redactions.append(_redaction("body", key_text))
            else:
                sanitized[key_text] = _sanitize_json(child, redactions)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_json(item, redactions) for item in value]
    return value


def _capture_body(raw_content: bytes | None, content_type: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not raw_content:
        return {"state": "empty", "content": None}, []
    if "application/json" not in content_type.lower() and "+json" not in content_type.lower():
        return {"state": "omitted_unsupported_content_type", "content": None}, []
    try:
        decoded = raw_content.decode("utf-8")
    except UnicodeDecodeError:
        return {"state": "invalid_utf8", "content": None}, []
    try:
        value = json.loads(decoded)
    except json.JSONDecodeError:
        return {"state": "invalid_json", "content": None}, []

    redactions: list[dict[str, str]] = []
    return {"state": "json", "content": _sanitize_json(value, redactions)}, redactions


def target_hosts() -> frozenset[str]:
    configured = os.getenv("CIC_CAPTURE_HOSTS")
    if not configured:
        return DEFAULT_TARGET_HOSTS
    return frozenset(host.strip().lower().rstrip(".") for host in configured.split(",") if host.strip())


def should_capture(host: str) -> bool:
    return host.lower().rstrip(".") in target_hosts()


def build_envelope(flow: Any) -> dict[str, Any]:
    request = flow.request
    split = urlsplit(_text(getattr(request, "pretty_url", request.url)))
    headers, header_redactions = _sanitize_headers(request.headers)
    query, query_redactions = _sanitize_query(split.query)
    body, body_redactions = _capture_body(
        getattr(request, "raw_content", None),
        _header_value(request.headers, "content-type"),
    )
    timestamp = getattr(request, "timestamp_start", None) or time.time()

    return {
        "version": CAPTURE_ENVELOPE_VERSION,
        "capture_id": _text(flow.id),
        "observed_at_unix_ms": int(timestamp * 1000),
        "source": "mitmproxy",
        "request": {
            "method": _text(request.method),
            "scheme": _text(request.scheme),
            "host": _text(request.host).lower(),
            "port": int(request.port),
            "path": split.path or "/",
            "query": query,
            "headers": headers,
            "body": body,
        },
        "redactions": header_redactions + query_redactions + body_redactions,
    }


class IpcConfig:
    def __init__(self, host: str, port: int, token: str, timeout_seconds: float = 0.5) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls) -> IpcConfig | None:
        address = os.getenv("CIC_CAPTURE_IPC_ADDR")
        token = os.getenv("CIC_CAPTURE_IPC_TOKEN")
        if not address or not token:
            return None
        host, separator, port_text = address.rpartition(":")
        if not separator or not host or not port_text:
            raise ValueError("CIC_CAPTURE_IPC_ADDR must be an IP address and port")
        host = host.removeprefix("[").removesuffix("]")
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("capture IPC address must be loopback")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("capture IPC port is invalid")
        return cls(host=host, port=port, token=token)


def send_envelope(config: IpcConfig, envelope: dict[str, Any]) -> None:
    auth = {
        "protocol": IPC_PROTOCOL,
        "version": IPC_PROTOCOL_VERSION,
        "token": config.token,
    }
    frames = (
        json.dumps(auth, ensure_ascii=True, separators=(",", ":"))
        + "\n"
        + json.dumps(envelope, ensure_ascii=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    with socket.create_connection((config.host, config.port), timeout=config.timeout_seconds) as connection:
        connection.sendall(frames)


class IpcEmitter:
    def __init__(self, config: IpcConfig, capacity: int = 64) -> None:
        self._config = config
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=capacity)
        self._worker = threading.Thread(target=self._run, name="codeischeap-ipc", daemon=True)
        self._worker.start()

    def submit(self, envelope: dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(envelope)
            return True
        except queue.Full:
            return False

    def close(self) -> None:
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            return
        self._worker.join(timeout=1)

    def _run(self) -> None:
        while True:
            envelope = self._queue.get()
            if envelope is None:
                return
            try:
                send_envelope(self._config, envelope)
            except (OSError, ValueError):
                _warn("CodeIsCheap capture IPC delivery failed; the request was not recorded")


def _warn(message: str) -> None:
    try:
        from mitmproxy import ctx

        ctx.log.warn(message)
    except (ImportError, RuntimeError):
        pass


class CaptureAddon:
    def __init__(self) -> None:
        self._emitter: IpcEmitter | None = None
        self._configuration_failed = False

    def request(self, flow: Any) -> None:
        if not should_capture(_text(flow.request.host)):
            return
        if self._configuration_failed:
            return
        if self._emitter is None:
            try:
                config = IpcConfig.from_env()
            except ValueError:
                self._configuration_failed = True
                _warn("CodeIsCheap capture IPC configuration is invalid")
                return
            if config is None:
                self._configuration_failed = True
                _warn("CodeIsCheap capture IPC configuration is missing")
                return
            self._emitter = IpcEmitter(config)

        try:
            envelope = build_envelope(flow)
        except (AttributeError, TypeError, ValueError):
            _warn("CodeIsCheap could not sanitize this target request; the request was not recorded")
            return
        if not self._emitter.submit(envelope):
            _warn("CodeIsCheap capture queue is full; the request was not recorded")

    def done(self) -> None:
        if self._emitter is not None:
            self._emitter.close()


addons = [CaptureAddon()]
