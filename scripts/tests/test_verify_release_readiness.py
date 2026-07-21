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
        return repository

    def document(self, version: str = "1.2.3") -> dict[str, object]:
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
                    "evidence": ["docs/evidence.html"],
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
            self.write(repository, self.document())
            report = verify_release_readiness(repository, "v1.2.3")
            self.assertTrue(report["ready"])
            self.assertEqual(report["passed"], len(REQUIRED_GATE_IDS))
            self.assertEqual(report["pending"], [])

    def test_pending_gates_validate_but_block_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            document = self.document()
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

            wrong_version = self.document("9.9.9")
            cases.append(wrong_version)

            duplicate = self.document()
            duplicate["gates"][1]["id"] = duplicate["gates"][0]["id"]
            cases.append(duplicate)

            unsafe = self.document()
            unsafe["gates"][0]["evidence"] = ["../outside.html"]
            cases.append(unsafe)

            insecure_url = self.document()
            insecure_url["gates"][0]["evidence"] = ["http://example.test/evidence"]
            cases.append(insecure_url)

            self_review = self.document()
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
            document = self.document()
            document["gates"][0]["status"] = "pending"
            self.write(repository, document)
            with self.assertRaisesRegex(ReadinessError, "cannot claim"):
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
