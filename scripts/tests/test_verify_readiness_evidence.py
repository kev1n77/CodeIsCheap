from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(SCRIPTS))

from verify_readiness_evidence import (
    ReadinessEvidenceError,
    build_manual_template,
    validate_beta_report,
    validate_manual_evidence,
    write_manual_template,
)


class ReadinessEvidenceTests(unittest.TestCase):
    def repository(self, root: Path) -> Path:
        repository = root / "repository"
        (repository / "release").mkdir(parents=True)
        (repository / "release/beta-metrics-policy.v0.1.json").write_text(
            json.dumps(
                {
                    "schemaVersion": "0.1",
                    "releaseVersion": "1.2.3",
                    "allowedPlatforms": ["macos", "windows"],
                    "minimums": {
                        "contributors": 3,
                        "firstCaptureSamples": 3,
                        "supportedCaptures": 6,
                        "completedSessions": 6,
                    },
                    "thresholds": {
                        "firstCaptureP50MaxMs": 500,
                        "endpointParseRateMinBasisPointsExclusive": 9500,
                        "crashFreeRateMinBasisPointsExclusive": 9950,
                    },
                }
            ),
            encoding="utf-8",
        )
        return repository

    def manual_packet(self, repository: Path) -> Path:
        packet = build_manual_template("windows_admin_matrix", "1.2.3")
        packet.update(
            {
                "completedAt": "2026-07-20T00:00:00Z",
                "executor": "qa-executor",
                "reviewer": "release-owner",
                "summary": "Windows acceptance matrix completed.",
            }
        )
        evidence_directory = repository / "evidence"
        evidence_directory.mkdir()
        for scenario in packet["scenarios"]:
            attachment = evidence_directory / f'{scenario["id"]}.txt'
            attachment.write_text("reviewed result", encoding="utf-8")
            scenario.update(
                {
                    "architecture": "x86_64",
                    "environment": "Windows 11 24H2 clean VM",
                    "status": "passed",
                    "evidence": [f"evidence/{attachment.name}"],
                    "notes": "Expected recovery behavior observed.",
                }
            )
        path = repository / "windows.json"
        path.write_text(json.dumps(packet), encoding="utf-8")
        return path

    def beta_report(self, repository: Path) -> Path:
        report = {
            "schemaVersion": "0.1",
            "releaseVersion": "1.2.3",
            "generatedAtUnixMs": 1,
            "privacy": {
                "sourceContentIncluded": False,
                "sampleIdsIncluded": False,
                "automaticUpload": False,
            },
            "cohort": {
                "contributorCount": 3,
                "platformCounts": {"macos": 1, "windows": 2},
                "sourceSha256": [f"{value:064x}" for value in range(1, 4)],
            },
            "metrics": {
                "firstCaptureSampleCount": 3,
                "firstCaptureP50Ms": 200,
                "supportedCaptureCount": 100,
                "parsedCaptureCount": 99,
                "parseRateBasisPoints": 9900,
                "completedSessionCount": 1000,
                "uncleanSessionCount": 0,
                "crashFreeRateBasisPoints": 10000,
            },
            "gates": {
                "firstCaptureP50": {
                    "status": "passed",
                    "actual": 200,
                    "requirement": "under 500 ms",
                },
                "endpointParseRate": {
                    "status": "passed",
                    "actual": 9900,
                    "requirement": "over 9500 basis points",
                },
                "crashFreeSessions": {
                    "status": "passed",
                    "actual": 10000,
                    "requirement": "over 9950 basis points",
                },
            },
            "ready": True,
        }
        path = repository / "beta-report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def test_validates_completed_manual_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            packet = self.manual_packet(repository)
            document = validate_manual_evidence(
                packet,
                repository,
                gate_id="windows_admin_matrix",
                release_version="1.2.3",
                reviewer="release-owner",
                gate_completed_at="2026-07-21T00:00:00Z",
            )
            self.assertEqual(len(document["scenarios"]), 5)

    def test_template_is_new_file_only_and_pending_template_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            path = repository / "template.json"
            write_manual_template(path, "windows_admin_matrix", "1.2.3")
            with self.assertRaises(ReadinessEvidenceError):
                write_manual_template(path, "windows_admin_matrix", "1.2.3")
            with self.assertRaises(ReadinessEvidenceError):
                validate_manual_evidence(path, repository)

    def test_rejects_duplicate_scenarios_same_reviewer_and_unsafe_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            original = self.manual_packet(repository)
            packet = json.loads(original.read_text(encoding="utf-8"))
            cases = []

            duplicate = copy.deepcopy(packet)
            duplicate["scenarios"][1]["id"] = duplicate["scenarios"][0]["id"]
            cases.append(duplicate)

            self_review = copy.deepcopy(packet)
            self_review["executor"] = self_review["reviewer"]
            cases.append(self_review)

            unsafe = copy.deepcopy(packet)
            unsafe["scenarios"][0]["evidence"] = ["../outside.txt"]
            cases.append(unsafe)

            missing = copy.deepcopy(packet)
            missing["scenarios"][0]["evidence"] = ["evidence/missing.txt"]
            cases.append(missing)

            for index, document in enumerate(cases):
                with self.subTest(index=index):
                    path = repository / f"invalid-{index}.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ReadinessEvidenceError):
                        validate_manual_evidence(path, repository)

    def test_rejects_symlink_attachment_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            packet_path = self.manual_packet(repository)
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            link = repository / "evidence/link.txt"
            try:
                link.symlink_to(repository / "evidence/gateway_standard_user.txt")
            except OSError:
                self.skipTest("symlink creation is not available")
            packet["scenarios"][0]["evidence"] = ["evidence/link.txt"]
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            with self.assertRaisesRegex(ReadinessEvidenceError, "symlink"):
                validate_manual_evidence(packet_path, repository)

    def test_validates_beta_report_and_rejects_forged_or_insufficient_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            path = self.beta_report(repository)
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(
                validate_beta_report(path, repository, release_version="1.2.3")["ready"]
            )

            cases = []
            unsafe_privacy = copy.deepcopy(report)
            unsafe_privacy["privacy"]["sourceContentIncluded"] = True
            cases.append(unsafe_privacy)

            forged_rate = copy.deepcopy(report)
            forged_rate["metrics"]["parseRateBasisPoints"] = 9999
            cases.append(forged_rate)

            insufficient = copy.deepcopy(report)
            insufficient["cohort"] = {
                "contributorCount": 1,
                "platformCounts": {"windows": 1},
                "sourceSha256": [f"{1:064x}"],
            }
            insufficient["metrics"]["firstCaptureSampleCount"] = 1
            cases.append(insufficient)

            for index, document in enumerate(cases):
                with self.subTest(index=index):
                    invalid = repository / f"invalid-beta-{index}.json"
                    invalid.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ReadinessEvidenceError):
                        validate_beta_report(invalid, repository)


if __name__ == "__main__":
    unittest.main()
