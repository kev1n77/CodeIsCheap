from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from verify_release_readiness import (
    REQUIRED_GATE_IDS,
    ReadinessError,
    verify_release_readiness,
)
from verify_readiness_evidence import BETA_GATE_IDS, MANUAL_GATE_IDS, build_manual_template


class ReleaseReadinessTests(unittest.TestCase):
    def repository(self, root: Path, version: str = "1.2.3") -> Path:
        repository = root / "repository"
        (repository / "apps/desktop/src-tauri").mkdir(parents=True)
        (repository / "apps/desktop/src-tauri/tauri.conf.json").write_text(
            json.dumps({"version": version}), encoding="utf-8"
        )
        (repository / "apps/desktop/package.json").write_text(
            json.dumps({"version": version}), encoding="utf-8"
        )
        (repository / "apps/desktop/src-tauri/Cargo.toml").write_text(
            f'[package]\nname = "desktop"\nversion = "{version}"\n',
            encoding="utf-8",
        )
        (repository / "docs").mkdir()
        (repository / "docs/evidence.html").write_text(
            "<!doctype html><title>Evidence</title>", encoding="utf-8"
        )
        notes = repository / "release/notes" / f"v{version}.md"
        notes.parent.mkdir(parents=True)
        notes.write_text(f"# CodeIsCheap {version}\n", encoding="utf-8")
        (repository / "release/beta-metrics-policy.v0.1.json").write_text(
            json.dumps(
                {
                    "schemaVersion": "0.1",
                    "releaseVersion": version,
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

    def structured_evidence(self, repository: Path, version: str) -> dict[str, str]:
        evidence_directory = repository / "evidence"
        evidence_directory.mkdir(exist_ok=True)
        paths: dict[str, str] = {}
        for gate_id in sorted(MANUAL_GATE_IDS):
            packet = build_manual_template(gate_id, version)
            packet.update(
                {
                    "completedAt": "2026-07-20T00:00:00Z",
                    "executor": "qa-executor",
                    "reviewer": "release-owner",
                    "summary": f"{gate_id} acceptance completed.",
                }
            )
            for scenario in packet["scenarios"]:
                attachment = evidence_directory / f'{gate_id}-{scenario["id"]}.txt'
                attachment.write_text("reviewed result", encoding="utf-8")
                scenario.update(
                    {
                        "architecture": "cross-platform",
                        "environment": "isolated acceptance environment",
                        "status": "passed",
                        "evidence": [f"evidence/{attachment.name}"],
                        "notes": "Expected behavior observed.",
                    }
                )
            path = evidence_directory / f"{gate_id}.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            paths[gate_id] = f"evidence/{path.name}"

        beta_report = {
            "schemaVersion": "0.1",
            "releaseVersion": version,
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
        beta_path = evidence_directory / "beta-report.json"
        beta_path.write_text(json.dumps(beta_report), encoding="utf-8")
        for gate_id in BETA_GATE_IDS:
            paths[gate_id] = "evidence/beta-report.json"
        return paths

    def document(self, repository: Path, version: str = "1.2.3") -> dict[str, object]:
        structured = self.structured_evidence(repository, version)
        return {
            "schemaVersion": "0.1",
            "releaseVersion": version,
            "updatedAt": "2026-07-21T00:00:00Z",
            "notesFile": f"release/notes/v{version}.md",
            "gates": [
                {
                    "id": gate_id,
                    "status": "passed",
                    "reviewer": "release-owner",
                    "completedAt": "2026-07-21T00:00:00Z",
                    "evidence": [structured.get(gate_id, "docs/evidence.html")],
                }
                for gate_id in sorted(REQUIRED_GATE_IDS)
            ],
        }

    def write(self, repository: Path, document: dict[str, object]) -> None:
        (repository / "release/readiness.v0.1.json").write_text(
            json.dumps(document), encoding="utf-8"
        )

    def test_all_passed_gates_produce_a_ready_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            self.write(repository, self.document(repository))
            report = verify_release_readiness(repository, "v1.2.3")
            self.assertTrue(report["ready"])
            self.assertEqual(report["passed"], len(REQUIRED_GATE_IDS))
            self.assertEqual(report["pending"], [])

    def test_pending_gates_validate_but_block_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            document = self.document(repository)
            document["gates"][0] = {
                "id": document["gates"][0]["id"],
                "status": "pending",
                "reviewer": None,
                "completedAt": None,
                "evidence": [],
            }
            self.write(repository, document)
            report = verify_release_readiness(repository, allow_pending=True)
            self.assertFalse(report["ready"])
            with self.assertRaisesRegex(ReadinessError, "pending gates"):
                verify_release_readiness(repository, "v1.2.3")

    def test_rejects_wrong_versions_duplicate_gates_and_unsafe_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            cases = []

            wrong_version = self.document(repository, "9.9.9")
            cases.append(wrong_version)

            duplicate = self.document(repository)
            duplicate["gates"][1]["id"] = duplicate["gates"][0]["id"]
            cases.append(duplicate)

            unsafe = self.document(repository)
            unsafe["gates"][0]["evidence"] = ["../outside.html"]
            cases.append(unsafe)

            insecure_url = self.document(repository)
            insecure_url["gates"][0]["evidence"] = ["http://example.test/evidence"]
            cases.append(insecure_url)

            self_review = self.document(repository)
            security_gate = next(
                gate
                for gate in self_review["gates"]
                if gate["id"] == "independent_security_review"
            )
            security_gate["reviewer"] = "Codex"
            cases.append(self_review)

            for document in cases:
                with self.subTest(document=document):
                    self.write(repository, document)
                    with self.assertRaises(ReadinessError):
                        verify_release_readiness(repository, "v1.2.3", allow_pending=True)

    def test_pending_gates_cannot_claim_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            document = self.document(repository)
            document["gates"][0]["status"] = "pending"
            self.write(repository, document)
            with self.assertRaisesRegex(ReadinessError, "cannot claim"):
                verify_release_readiness(repository, allow_pending=True)

    def test_external_gates_reject_arbitrary_local_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            document = self.document(repository)
            for gate in document["gates"]:
                if gate["id"] in MANUAL_GATE_IDS | BETA_GATE_IDS:
                    gate["evidence"] = ["docs/evidence.html"]
            self.write(repository, document)
            with self.assertRaisesRegex(ReadinessError, "evidence is invalid"):
                verify_release_readiness(repository, allow_pending=True)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            (repository / "release/readiness.v0.1.json").write_text(
                '{"schemaVersion":"0.1","schemaVersion":"0.1"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReadinessError, "duplicate JSON key"):
                verify_release_readiness(repository, allow_pending=True)


if __name__ == "__main__":
    unittest.main()
