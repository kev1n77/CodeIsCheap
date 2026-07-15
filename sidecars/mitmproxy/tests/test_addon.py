from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


SIDECAR_DIR = Path(__file__).resolve().parents[1]
FIXTURE = SIDECAR_DIR.parents[1] / "crates" / "capture-ipc" / "tests" / "fixtures" / "mitmproxy-request.json"
sys.path.insert(0, str(SIDECAR_DIR))

from codeischeap_addon import (
    IpcConfig,
    build_envelope,
    build_failure_envelope,
    load_policy,
    send_envelope,
    should_capture,
)


class FakeHeaders:
    def __init__(self, entries: list[tuple[str, str]]) -> None:
        self.entries = entries

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        return list(self.entries)

    def get(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.entries:
            if key.lower() == lowered:
                return value
        return default


class FakeRequest:
    method = "POST"
    scheme = "https"
    host = "api.openai.com"
    port = 443
    timestamp_start = 1_721_000_000.25
    pretty_url = (
        "https://api.openai.com/v1/chat/completions?stream=true&access_token=query-canary"
    )
    url = pretty_url
    headers = FakeHeaders(
        [
            ("authorization", "Bearer header-canary"),
            ("x-api-key", "header-api-key-canary"),
            ("content-type", "application/json"),
            ("x-request-id", "request_1"),
        ]
    )
    raw_content = json.dumps(
        {
            "api_key": "body-canary",
            "messages": [{"role": "user", "content": "keep this prompt"}],
            "metadata": {"client_secret": "nested-canary", "trace": "keep"},
        }
    ).encode()


class FakeFlow:
    id = "flow_1"
    request = FakeRequest()


class FakeResponse:
    status_code = 429
    timestamp_end = FakeRequest.timestamp_start + 0.875
    headers = FakeHeaders(
        [
            ("content-type", "application/json"),
            ("set-cookie", "response-cookie-canary"),
            ("x-request-id", "response_1"),
        ]
    )
    content = json.dumps(
        {"error": "rate limited", "access_token": "response-body-canary"}
    ).encode()
    raw_content = content


class FakeError:
    timestamp = FakeRequest.timestamp_start + 0.125


class AddonTests(unittest.TestCase):
    def test_output_matches_the_shared_rust_fixture(self) -> None:
        expected = json.loads(FIXTURE.read_text(encoding="utf-8"))

        self.assertEqual(build_envelope(FakeFlow()), expected)

    def test_credentials_are_removed_before_serialization(self) -> None:
        envelope = build_envelope(FakeFlow())
        encoded = json.dumps(envelope)

        for canary in (
            "header-canary",
            "header-api-key-canary",
            "query-canary",
            "body-canary",
            "nested-canary",
        ):
            self.assertNotIn(canary, encoded)
        self.assertIn("keep this prompt", encoded)
        self.assertIn('"trace": "keep"', encoded)
        self.assertEqual(envelope["request"]["body"]["state"], "json")
        self.assertEqual(len(envelope["redactions"]), 5)

    def test_unknown_body_types_are_not_sent_across_ipc(self) -> None:
        flow = FakeFlow()
        flow.request = FakeRequest()
        flow.request.headers = FakeHeaders([("content-type", "application/octet-stream")])
        flow.request.raw_content = b"opaque-canary"

        envelope = build_envelope(flow)

        self.assertEqual(
            envelope["request"]["body"],
            {"state": "omitted_unsupported_content_type", "content": None},
        )
        self.assertNotIn("opaque-canary", json.dumps(envelope))

    def test_response_outcome_preserves_json_and_removes_response_credentials(self) -> None:
        flow = FakeFlow()
        flow.response = FakeResponse()

        envelope = build_envelope(flow)
        encoded = json.dumps(envelope)

        self.assertEqual(envelope["outcome"]["kind"], "response")
        result = envelope["outcome"]["result"]
        self.assertEqual(result["status"], 429)
        self.assertEqual(result["duration_ms"], 875)
        self.assertEqual(result["body"]["content"], {"error": "rate limited"})
        self.assertEqual(
            result["headers"],
            [
                {"name": "content-type", "value": "application/json"},
                {"name": "x-request-id", "value": "response_1"},
            ],
        )
        self.assertNotIn("response-cookie-canary", encoded)
        self.assertNotIn("response-body-canary", encoded)
        self.assertIn(
            {"location": "response_header", "name": "set-cookie"},
            envelope["redactions"],
        )
        self.assertIn(
            {"location": "response_body", "name": "access_token"},
            envelope["redactions"],
        )

    def test_sse_response_is_preserved_as_utf8_text(self) -> None:
        flow = FakeFlow()
        flow.response = FakeResponse()
        flow.response.headers = FakeHeaders([("content-type", "text/event-stream")])
        flow.response.content = (
            b'event: message\ndata: {"delta":"done","access_token":"sse-canary"}\n\n'
            b"data: [DONE]\n\n"
        )

        envelope = build_envelope(flow)
        body = envelope["outcome"]["result"]["body"]

        self.assertEqual(body["state"], "text")
        self.assertIn("event: message", body["content"])
        self.assertIn('data: {"delta":"done"}', body["content"])
        self.assertIn("data: [DONE]", body["content"])
        self.assertNotIn("sse-canary", json.dumps(envelope))
        self.assertIn(
            {"location": "response_body", "name": "access_token"},
            envelope["redactions"],
        )

    def test_ndjson_and_json_sequence_response_credentials_are_removed(self) -> None:
        cases = [
            (
                "application/x-ndjson",
                b'{"delta":"one","token":"ndjson-canary"}\n{"delta":"two"}\n',
                "ndjson-canary",
            ),
            (
                "application/json-seq",
                b'\x1e{"delta":"one","secret":"json-seq-canary"}\x1e{"delta":"two"}',
                "json-seq-canary",
            ),
        ]
        for content_type, content, canary in cases:
            with self.subTest(content_type=content_type):
                flow = FakeFlow()
                flow.response = FakeResponse()
                flow.response.headers = FakeHeaders([("content-type", content_type)])
                flow.response.content = content

                envelope = build_envelope(flow)

                self.assertNotIn(canary, json.dumps(envelope))
                self.assertIn("delta", envelope["outcome"]["result"]["body"]["content"])

    def test_upstream_failure_retains_the_request_and_duration(self) -> None:
        flow = FakeFlow()
        flow.error = FakeError()

        envelope = build_failure_envelope(flow)

        self.assertEqual(envelope["capture_id"], "flow_1")
        self.assertEqual(
            envelope["outcome"],
            {"kind": "upstream_failure", "result": {"duration_ms": 125}},
        )

    def test_only_explicit_target_hosts_are_captured(self) -> None:
        self.assertTrue(
            should_capture("api.openai.com", "/v1/chat/completions", "POST")
        )
        self.assertFalse(
            should_capture("example.com", "/v1/chat/completions", "POST")
        )
        self.assertFalse(
            should_capture(
                "api.openai.com.example.com", "/v1/chat/completions", "POST"
            )
        )

    def test_unlisted_paths_and_methods_are_not_captured(self) -> None:
        self.assertFalse(should_capture("api.openai.com", "/v1/files", "POST"))
        self.assertFalse(
            should_capture("api.openai.com", "/v1/chat/completions", "GET")
        )
        self.assertTrue(
            should_capture(
                "generativelanguage.googleapis.com",
                "/v1beta/models/gemini-pro:streamGenerateContent",
                "POST",
            )
        )

    def test_explicit_host_override_still_enforces_paths(self) -> None:
        with patch.dict(os.environ, {"CIC_CAPTURE_HOSTS": "127.0.0.1"}):
            self.assertTrue(
                should_capture("127.0.0.1", "/v1/chat/completions", "POST")
            )
            self.assertFalse(should_capture("127.0.0.1", "/admin", "POST"))

    def test_shared_policy_is_versioned_and_covers_extended_credentials(self) -> None:
        policy = load_policy()
        self.assertEqual(policy["version"], "0.1")

        flow = FakeFlow()
        flow.request = FakeRequest()
        flow.request.headers = FakeHeaders(
            [
                ("content-type", "application/json"),
                ("x-goog-api-key", "google-canary"),
            ]
        )
        flow.request.raw_content = json.dumps(
            {
                "messages": [{"role": "user", "content": "keep"}],
                "session_token": "session-canary",
            }
        ).encode()

        encoded = json.dumps(build_envelope(flow))
        self.assertNotIn("google-canary", encoded)
        self.assertNotIn("session-canary", encoded)
        self.assertIn("keep", encoded)

    def test_invalid_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-policy.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "0.1",
                        "targets": [
                            {
                                "id": "test",
                                "hosts": ["api.openai.com"],
                                "methods": ["POST"],
                                "paths": ["/v1/responses"],
                            }
                        ],
                        "sensitive_names": ["api-key", "api_key"],
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"CIC_CAPTURE_POLICY_PATH": str(path)}):
                with self.assertRaisesRegex(ValueError, "sensitive name"):
                    load_policy()

    def test_ipc_rejects_non_loopback_configuration(self) -> None:
        with patch.dict(
            os.environ,
            {
                "CIC_CAPTURE_IPC_ADDR": "192.0.2.10:3211",
                "CIC_CAPTURE_IPC_TOKEN": "synthetic-token",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "loopback"):
                IpcConfig.from_env()

    def test_ipc_sends_auth_and_envelope_as_separate_frames(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        received: list[bytes] = []

        def accept() -> None:
            connection, _ = listener.accept()
            with connection:
                stream = connection.makefile("rb")
                received.extend([stream.readline(), stream.readline()])

        worker = threading.Thread(target=accept)
        worker.start()
        config = IpcConfig("127.0.0.1", listener.getsockname()[1], "synthetic-token")
        envelope = build_envelope(FakeFlow())
        send_envelope(config, envelope)
        worker.join(timeout=2)
        listener.close()

        self.assertFalse(worker.is_alive())
        auth = json.loads(received[0])
        captured = json.loads(received[1])
        self.assertEqual(auth["token"], "synthetic-token")
        self.assertNotIn("token", captured)
        self.assertEqual(captured, envelope)


if __name__ == "__main__":
    unittest.main()
