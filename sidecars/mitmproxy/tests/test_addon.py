from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import patch


SIDECAR_DIR = Path(__file__).resolve().parents[1]
FIXTURE = SIDECAR_DIR.parents[1] / "crates" / "capture-ipc" / "tests" / "fixtures" / "mitmproxy-request.json"
sys.path.insert(0, str(SIDECAR_DIR))

from codeischeap_addon import IpcConfig, build_envelope, send_envelope, should_capture


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

    def test_only_explicit_target_hosts_are_captured(self) -> None:
        self.assertTrue(should_capture("api.openai.com"))
        self.assertFalse(should_capture("example.com"))
        self.assertFalse(should_capture("api.openai.com.example.com"))

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
