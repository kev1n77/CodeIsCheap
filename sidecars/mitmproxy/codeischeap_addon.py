"""Security boundary for the CodeIsCheap mitmproxy capture sidecar."""

from __future__ import annotations

import ipaddress
import json
import os
from fnmatch import fnmatchcase
from pathlib import Path
import queue
import socket
import threading
import time
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlsplit


IPC_PROTOCOL = "codeischeap.capture-ipc"
IPC_PROTOCOL_VERSION = "0.2"
IPC_ORIGIN = "mitmproxy"
CAPTURE_ENVELOPE_VERSION = "0.1"
CAPTURE_POLICY_VERSION = "0.1"
CAPTURE_POLICY_FILENAME = "capture-policy.v0.1.json"
DEFAULT_ATTRIBUTION_POLICY = {
    "client_label_header": "x-codeischeap-client",
    "max_label_bytes": 64,
    "user_agents": [
        {"application": "Cursor", "contains": ["cursor/", "cursor "]},
        {"application": "VS Code", "contains": ["vscode/", "visual studio code"]},
        {"application": "Claude Code", "contains": ["claude-code", "claude code"]},
        {"application": "Codex CLI", "contains": ["codex-cli", "openai-codex", "codex/"]},
        {"application": "JetBrains", "contains": ["jetbrains", "intellij", "pycharm", "webstorm"]},
        {"application": "Microsoft Edge", "contains": ["edg/"]},
        {"application": "Google Chrome", "contains": ["chrome/"]},
        {"application": "Mozilla Firefox", "contains": ["firefox/"]},
        {"application": "Apple Safari", "contains": ["safari/"]},
        {"application": "curl", "contains": ["curl/"]},
        {"application": "Python", "contains": ["python-requests/", "aiohttp/"]},
        {"application": "Node.js", "contains": ["node-fetch", "undici"]},
    ],
    "gateway_fallback": "Gateway client",
    "proxy_fallback": "Proxy client",
}
ATTRIBUTION_METADATA_KEY = "codeischeap.attribution"


def _valid_application_label(value: Any, max_bytes: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 0 < len(value.encode("ascii", errors="ignore")) <= max_bytes
        and value.isascii()
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _policy_path() -> Path:
    configured = os.getenv("CIC_CAPTURE_POLICY_PATH")
    if configured:
        return Path(configured)

    source = Path(__file__).resolve()
    candidates = [source.with_name(CAPTURE_POLICY_FILENAME)]
    if len(source.parents) > 2:
        candidates.append(source.parents[2] / "policies" / CAPTURE_POLICY_FILENAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError("CodeIsCheap capture policy file is missing")


def load_policy() -> dict[str, Any]:
    policy = json.loads(_policy_path().read_text(encoding="utf-8"))
    if policy.get("version") != CAPTURE_POLICY_VERSION:
        raise ValueError("CodeIsCheap capture policy version is unsupported")
    targets = policy.get("targets")
    sensitive_names = policy.get("sensitive_names")
    if not isinstance(targets, list) or not targets:
        raise ValueError("CodeIsCheap capture policy has no targets")
    if not isinstance(sensitive_names, list) or not sensitive_names:
        raise ValueError("CodeIsCheap capture policy has no sensitive names")
    attribution = policy.setdefault("attribution", DEFAULT_ATTRIBUTION_POLICY)
    if not isinstance(attribution, dict):
        raise ValueError("CodeIsCheap attribution policy is invalid")
    if (
        attribution.get("client_label_header") != "x-codeischeap-client"
        or not isinstance(attribution.get("max_label_bytes"), int)
        or not 1 <= attribution["max_label_bytes"] <= 128
        or not _valid_application_label(
            attribution.get("gateway_fallback"), attribution["max_label_bytes"]
        )
        or not _valid_application_label(
            attribution.get("proxy_fallback"), attribution["max_label_bytes"]
        )
    ):
        raise ValueError("CodeIsCheap attribution policy is invalid")
    user_agents = attribution.get("user_agents")
    if not isinstance(user_agents, list):
        raise ValueError("CodeIsCheap attribution policy is invalid")
    for rule in user_agents:
        if (
            not isinstance(rule, dict)
            or not _valid_application_label(
                rule.get("application"), attribution["max_label_bytes"]
            )
            or not isinstance(rule.get("contains"), list)
            or not rule["contains"]
            or any(
                not isinstance(pattern, str)
                or not pattern
                or len(pattern) > 128
                or pattern != pattern.lower()
                for pattern in rule["contains"]
            )
        ):
            raise ValueError("CodeIsCheap attribution policy is invalid")
    target_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("CodeIsCheap capture policy target is invalid")
        target_id = target.get("id")
        if not isinstance(target_id, str) or not target_id or target_id in target_ids:
            raise ValueError("CodeIsCheap capture policy target id is invalid")
        target_ids.add(target_id)
        for field in ("hosts", "methods", "paths"):
            values = target.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value for value in values)
            ):
                raise ValueError("CodeIsCheap capture policy target is invalid")
        if any(host != host.lower().rstrip(".") for host in target["hosts"]):
            raise ValueError("CodeIsCheap capture policy host is invalid")
        if any(method != method.upper() for method in target["methods"]):
            raise ValueError("CodeIsCheap capture policy method is invalid")
        if any(not path.startswith("/") for path in target["paths"]):
            raise ValueError("CodeIsCheap capture policy path is invalid")
    normalized_names = [
        "".join(character for character in name.lower() if character.isalnum())
        for name in sensitive_names
        if isinstance(name, str)
    ]
    if (
        len(normalized_names) != len(sensitive_names)
        or any(not name for name in normalized_names)
        or len(set(normalized_names)) != len(normalized_names)
    ):
        raise ValueError("CodeIsCheap sensitive name policy is invalid")
    return policy


CAPTURE_POLICY = load_policy()
ATTRIBUTION_POLICY = CAPTURE_POLICY["attribution"]
SENSITIVE_NAMES = frozenset(
    "".join(character for character in name.lower() if character.isalnum())
    for name in CAPTURE_POLICY["sensitive_names"]
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


def _sanitize_headers(
    headers: Any, location: str = "header"
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    captured = []
    redactions = []
    for name, value in _header_items(headers):
        if name.lower() == ATTRIBUTION_POLICY["client_label_header"]:
            continue
        if _is_sensitive(name):
            redactions.append(_redaction(location, name))
        else:
            captured.append({"name": name.lower(), "value": value})
    return captured, redactions


def _derive_attribution(headers: Any) -> dict[str, Any]:
    max_bytes = ATTRIBUTION_POLICY["max_label_bytes"]
    client_label = _header_value(headers, ATTRIBUTION_POLICY["client_label_header"]).strip()
    if _valid_application_label(client_label, max_bytes):
        return {
            "application": client_label,
            "source": "client_label",
            "confidence": "high",
        }
    user_agent = _header_value(headers, "user-agent").lower()
    for rule in ATTRIBUTION_POLICY["user_agents"]:
        if any(pattern in user_agent for pattern in rule["contains"]):
            return {
                "application": rule["application"],
                "source": "user_agent",
                "confidence": "medium",
            }
    return {
        "application": ATTRIBUTION_POLICY["proxy_fallback"],
        "source": "capture_mode",
        "confidence": "low",
    }


def _flow_attribution(flow: Any, headers: Any) -> dict[str, Any]:
    metadata = getattr(flow, "metadata", None)
    if isinstance(metadata, dict) and ATTRIBUTION_METADATA_KEY in metadata:
        return metadata[ATTRIBUTION_METADATA_KEY]
    attribution = _derive_attribution(headers)
    if isinstance(metadata, dict):
        metadata[ATTRIBUTION_METADATA_KEY] = attribution
    return attribution


def _remove_client_label(headers: Any) -> None:
    name = ATTRIBUTION_POLICY["client_label_header"]
    try:
        headers.pop(name, None)
    except (AttributeError, TypeError):
        entries = getattr(headers, "entries", None)
        if isinstance(entries, list):
            headers.entries = [
                (key, value) for key, value in entries if key.lower() != name
            ]


def _sanitize_query(query: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    captured = []
    redactions = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if _is_sensitive(name):
            redactions.append(_redaction("query", name))
        else:
            captured.append({"name": name, "value": value})
    return captured, redactions


def _sanitize_json(
    value: Any, redactions: list[dict[str, str]], location: str
) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, child in value.items():
            key_text = _text(key)
            if _is_sensitive(key_text):
                redactions.append(_redaction(location, key_text))
            else:
                sanitized[key_text] = _sanitize_json(child, redactions, location)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_json(item, redactions, location) for item in value]
    return value


def _sanitize_json_text(
    text: str, redactions: list[dict[str, str]], location: str
) -> str:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text
    sanitized = _sanitize_json(value, redactions, location)
    return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))


def _sanitize_sse(
    text: str, redactions: list[dict[str, str]], location: str
) -> str:
    sanitized_lines = []
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        ending = line[len(content) :]
        if not content.startswith("data:"):
            sanitized_lines.append(line)
            continue
        prefix = "data: " if content.startswith("data: ") else "data:"
        payload = content[len(prefix) :]
        if payload and payload != "[DONE]":
            payload = _sanitize_json_text(payload, redactions, location)
        sanitized_lines.append(f"{prefix}{payload}{ending}")
    return "".join(sanitized_lines)


def _sanitize_json_lines(
    text: str, redactions: list[dict[str, str]], location: str
) -> str:
    sanitized_lines = []
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        ending = line[len(content) :]
        sanitized_lines.append(
            _sanitize_json_text(content, redactions, location) + ending
            if content
            else line
        )
    return "".join(sanitized_lines)


def _sanitize_json_sequence(
    text: str, redactions: list[dict[str, str]], location: str
) -> str:
    records = text.split("\x1e")
    return "\x1e".join(
        _sanitize_json_text(record, redactions, location) if record else record
        for record in records
    )


def _capture_body(
    raw_content: bytes | None,
    content_type: str,
    *,
    allow_text: bool = False,
    redaction_location: str = "body",
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not raw_content:
        return {"state": "empty", "content": None}, []
    media_type = content_type.lower().partition(";")[0].strip()
    is_json = media_type == "application/json" or media_type.endswith("+json")
    is_text = media_type.startswith("text/") or media_type in {
        "application/x-ndjson",
        "application/json-seq",
        "application/ndjson",
    }
    if not is_json and not (allow_text and is_text):
        return {"state": "omitted_unsupported_content_type", "content": None}, []
    try:
        decoded = raw_content.decode("utf-8")
    except UnicodeDecodeError:
        return {"state": "invalid_utf8", "content": None}, []
    redactions: list[dict[str, str]] = []
    if allow_text and is_text and not is_json:
        if media_type == "text/event-stream":
            decoded = _sanitize_sse(decoded, redactions, redaction_location)
        elif media_type in {"application/x-ndjson", "application/ndjson"}:
            decoded = _sanitize_json_lines(decoded, redactions, redaction_location)
        elif media_type == "application/json-seq":
            decoded = _sanitize_json_sequence(decoded, redactions, redaction_location)
        return {"state": "text", "content": decoded}, redactions

    try:
        value = json.loads(decoded)
    except json.JSONDecodeError:
        return {"state": "invalid_json", "content": None}, []
    return {
        "state": "json",
        "content": _sanitize_json(value, redactions, redaction_location),
    }, redactions


def target_hosts() -> frozenset[str]:
    configured = os.getenv("CIC_CAPTURE_HOSTS")
    if configured:
        return frozenset(
            host.strip().lower().rstrip(".")
            for host in configured.split(",")
            if host.strip()
        )
    return frozenset(
        host
        for target in CAPTURE_POLICY["targets"]
        for host in target["hosts"]
    )


def should_capture(host: str, path: str, method: str) -> bool:
    normalized_host = host.lower().rstrip(".")
    if normalized_host not in target_hosts():
        return False

    configured_hosts = bool(os.getenv("CIC_CAPTURE_HOSTS"))
    for target in CAPTURE_POLICY["targets"]:
        host_matches = configured_hosts or normalized_host in target["hosts"]
        if (
            host_matches
            and method.upper() in target["methods"]
            and any(fnmatchcase(path, pattern) for pattern in target["paths"])
        ):
            return True
    return False


def build_envelope(flow: Any) -> dict[str, Any]:
    request = flow.request
    split = urlsplit(_text(getattr(request, "pretty_url", request.url)))
    headers, header_redactions = _sanitize_headers(request.headers)
    query, query_redactions = _sanitize_query(split.query)
    body, body_redactions = _capture_body(
        getattr(request, "raw_content", None),
        _header_value(request.headers, "content-type"),
    )
    attribution = _flow_attribution(flow, request.headers)
    _remove_client_label(request.headers)
    timestamp = getattr(request, "timestamp_start", None) or time.time()

    envelope = {
        "version": CAPTURE_ENVELOPE_VERSION,
        "capture_id": _text(flow.id),
        "observed_at_unix_ms": int(timestamp * 1000),
        "source": "mitmproxy",
        "attribution": attribution,
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
    response = getattr(flow, "response", None)
    if response is not None:
        response_headers, response_header_redactions = _sanitize_headers(
            response.headers, "response_header"
        )
        response_body, response_body_redactions = _capture_body(
            getattr(response, "content", None)
            or getattr(response, "raw_content", None),
            _header_value(response.headers, "content-type"),
            allow_text=True,
            redaction_location="response_body",
        )
        ended_at = getattr(response, "timestamp_end", None) or time.time()
        duration_ms = max(0, round((ended_at - timestamp) * 1000))
        envelope["outcome"] = {
            "kind": "response",
            "result": {
                "status": int(response.status_code),
                "headers": response_headers,
                "body": response_body,
                "duration_ms": duration_ms,
                "completeness": "complete",
            },
        }
        envelope["redactions"].extend(
            response_header_redactions + response_body_redactions
        )
    return envelope


def build_failure_envelope(flow: Any) -> dict[str, Any]:
    envelope = build_envelope(flow)
    started_at = getattr(flow.request, "timestamp_start", None) or time.time()
    ended_at = getattr(getattr(flow, "error", None), "timestamp", None) or time.time()
    envelope["outcome"] = {
        "kind": "upstream_failure",
        "result": {"duration_ms": max(0, round((ended_at - started_at) * 1000))},
    }
    return envelope


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
        "origin": IPC_ORIGIN,
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

    def _submit(
        self,
        flow: Any,
        builder: Callable[[Any], dict[str, Any]],
        failure_message: str,
    ) -> None:
        request = flow.request
        split = urlsplit(_text(getattr(request, "pretty_url", request.url)))
        if not should_capture(
            _text(request.host), split.path or "/", _text(request.method)
        ):
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
            envelope = builder(flow)
        except (AttributeError, TypeError, ValueError):
            _warn(failure_message)
            return
        if not self._emitter.submit(envelope):
            _warn("CodeIsCheap capture queue is full; the request was not recorded")

    def request(self, flow: Any) -> None:
        self._submit(
            flow,
            build_envelope,
            "CodeIsCheap could not sanitize this target request; the request was not recorded",
        )

    def response(self, flow: Any) -> None:
        self._submit(
            flow,
            build_envelope,
            "CodeIsCheap could not sanitize this target response; the response was not recorded",
        )

    def error(self, flow: Any) -> None:
        self._submit(
            flow,
            build_failure_envelope,
            "CodeIsCheap could not record this upstream failure",
        )

    def done(self) -> None:
        if self._emitter is not None:
            self._emitter.close()


addons = [CaptureAddon()]
