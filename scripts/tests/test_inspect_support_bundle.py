from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from inspect_support_bundle import (
    MAX_SUPPORT_BUNDLE_BYTES,
    SupportBundleError,
    format_summary,
    load_support_bundle,
    summarize_support_bundle,
    validate_support_bundle,
)


def support_bundle() -> dict[str, object]:
    return {
        "formatVersion": "0.1",
        "policyVersion": "0.1",
        "generatedAtUnixMs": 1_784_000_000_000,
        "product": {
            "name": "CodeIsCheap",
            "version": "0.1.0",
            "desktopApiVersion": "0.1",
            "platform": "windows",
            "architecture": "x86_64",
        },
        "privacy": {
            "requestContentIncluded": False,
            "requestIdentifiersIncluded": False,
            "rawCaptureIncluded": False,
            "logsIncluded": True,
            "logDetailsIncluded": False,
        },
        "diagnostics": {
            "source": "encrypted_local",
            "capture": {
                "active": True,
                "canControl": True,
                "mode": "gateway",
                "endpoint": "127.0.0.1:8787",
                "profile": "Local gateway",
                "proxyAvailable": True,
                "requestCount": 4,
                "storage": "SQLCipher 4 / WAL",
            },
            "certificateAuthority": {
                "state": "ready",
                "trust": "trusted",
                "privateMaterial": "restricted",
                "canManageTrust": True,
                "fingerprintSha256": "a" * 64,
            },
            "health": {
                "encryptedStore": True,
                "captureRuntime": True,
                "endpointConnected": True,
                "proxyBundle": True,
            },
            "compatibility": {
                "code": "gateway_ready",
                "status": "ready",
                "confidence": "high",
                "title": "Gateway capture ready",
                "summary": "Route the target client to the local Gateway endpoint.",
                "recommendedMode": "gateway",
                "action": "none",
                "steps": [
                    {
                        "id": "gateway_runtime",
                        "status": "pass",
                        "label": "Local Gateway",
                        "detail": "Ready",
                    }
                ],
            },
            "runtimeIssue": None,
            "diagnosticEvents": [
                {
                    "occurredAtUnixMs": 1_784_000_000_001,
                    "code": "sidecar_process_exited",
                }
            ],
        },
        "redactionCount": 0,
    }


class SupportBundleInspectionTests(unittest.TestCase):
    def test_cli_validates_and_emits_a_content_free_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "support.json"
            path.write_text(json.dumps(support_bundle()), encoding="utf-8")
            validate = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "inspect_support_bundle.py"),
                    "validate",
                    str(path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            summary = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "inspect_support_bundle.py"),
                    "summarize",
                    str(path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertIn("support bundle is valid", validate.stdout)
            self.assertIn("gateway_ready", summary.stdout)
            self.assertNotIn("127.0.0.1", summary.stdout)
            self.assertNotIn("fingerprint", summary.stdout.lower())

    def test_validates_and_summarizes_only_triage_fields(self) -> None:
        bundle = support_bundle()
        validate_support_bundle(bundle)
        summary = summarize_support_bundle(bundle)
        rendered = format_summary(summary)

        self.assertEqual(summary["compatibility"]["code"], "gateway_ready")
        self.assertIn("sidecar_process_exited", rendered)
        self.assertNotIn("127.0.0.1", rendered)
        self.assertNotIn("fingerprint", rendered.lower())
        self.assertNotIn("runtimeIssue", summary)

    def test_rejects_request_content_and_credentials(self) -> None:
        with self.assertRaisesRegex(SupportBundleError, "request content field"):
            bundle = support_bundle()
            bundle["diagnostics"]["prompt"] = "private prompt"
            validate_support_bundle(bundle)

        with self.assertRaisesRegex(SupportBundleError, "credential pattern"):
            bundle = support_bundle()
            bundle["diagnostics"]["runtimeIssue"] = (
                "upstream rejected Bearer abcdefghijklmnopqrstuvwxyz123456"
            )
            validate_support_bundle(bundle)

    def test_rejects_privacy_mismatch_recovery_control_and_unknown_format(self) -> None:
        cases = []

        privacy = support_bundle()
        privacy["privacy"]["requestContentIncluded"] = True
        cases.append(privacy)

        recovery = support_bundle()
        recovery["diagnostics"]["source"] = "recovery_backup"
        cases.append(recovery)

        version = support_bundle()
        version["formatVersion"] = "0.2"
        cases.append(version)

        logs = support_bundle()
        logs["privacy"]["logsIncluded"] = False
        cases.append(logs)

        for bundle in cases:
            with self.subTest(bundle=bundle), self.assertRaises(SupportBundleError):
                validate_support_bundle(bundle)

    def test_file_loader_rejects_duplicates_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "support.json"
            valid.write_text(json.dumps(support_bundle()), encoding="utf-8")
            self.assertEqual(load_support_bundle(valid)["formatVersion"], "0.1")

            duplicate = root / "duplicate.json"
            duplicate.write_text('{"formatVersion":"0.1","formatVersion":"0.1"}', encoding="utf-8")
            with self.assertRaisesRegex(SupportBundleError, "duplicate JSON key"):
                load_support_bundle(duplicate)

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MAX_SUPPORT_BUNDLE_BYTES + 1))
            with self.assertRaisesRegex(SupportBundleError, "bundle size"):
                load_support_bundle(oversized)

            deeply_nested = root / "deep.json"
            deeply_nested.write_text("[" * 1_100 + "0" + "]" * 1_100, encoding="utf-8")
            with self.assertRaises(SupportBundleError):
                load_support_bundle(deeply_nested)

    def test_rejects_documents_with_excessive_json_nodes(self) -> None:
        bundle = support_bundle()
        bundle["unexpected"] = [None] * 10_001
        with self.assertRaisesRegex(SupportBundleError, "too many JSON values"):
            validate_support_bundle(bundle)

    def test_recovery_bundle_is_accepted_when_controls_are_disabled(self) -> None:
        bundle = copy.deepcopy(support_bundle())
        bundle["diagnostics"]["source"] = "recovery_backup"
        bundle["diagnostics"]["capture"]["active"] = False
        bundle["diagnostics"]["capture"]["canControl"] = False
        bundle["diagnostics"]["compatibility"]["code"] = "recovery_read_only"
        bundle["diagnostics"]["compatibility"]["status"] = "attention"
        validate_support_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
