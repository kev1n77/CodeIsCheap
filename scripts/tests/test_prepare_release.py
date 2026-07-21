from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from prepare_release import (
    ReleaseError,
    prepare_release,
    sha256_file,
    validate_tag,
    verify_release,
)
from verify_release_readiness import REQUIRED_GATE_IDS
from verify_readiness_evidence import BETA_GATE_IDS, MANUAL_GATE_IDS, build_manual_template


class ReleasePreparationTests(unittest.TestCase):
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
        evidence = repository / "docs" / "release-evidence.html"
        evidence.parent.mkdir(parents=True)
        evidence.write_text("<!doctype html><title>Evidence</title>", encoding="utf-8")
        notes = repository / "release" / "notes" / f"v{version}.md"
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
        structured: dict[str, str] = {}
        if "-" not in version:
            evidence_directory = repository / "evidence"
            evidence_directory.mkdir()
            for gate_id in MANUAL_GATE_IDS:
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
                packet_path = evidence_directory / f"{gate_id}.json"
                packet_path.write_text(json.dumps(packet), encoding="utf-8")
                structured[gate_id] = f"evidence/{packet_path.name}"
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
                structured[gate_id] = "evidence/beta-report.json"
        readiness = {
            "schemaVersion": "0.1",
            "releaseVersion": version,
            "updatedAt": "2026-07-21T00:00:00Z",
            "notesFile": f"release/notes/v{version}.md",
            "gates": [
                {
                    "id": gate_id,
                    "status": (
                        "pending"
                        if "-" in version and gate_id in MANUAL_GATE_IDS | BETA_GATE_IDS
                        else "passed"
                    ),
                    "reviewer": (
                        None
                        if "-" in version and gate_id in MANUAL_GATE_IDS | BETA_GATE_IDS
                        else "release-owner"
                    ),
                    "completedAt": (
                        None
                        if "-" in version and gate_id in MANUAL_GATE_IDS | BETA_GATE_IDS
                        else "2026-07-21T00:00:00Z"
                    ),
                    "evidence": (
                        []
                        if "-" in version and gate_id in MANUAL_GATE_IDS | BETA_GATE_IDS
                        else [structured.get(gate_id, "docs/release-evidence.html")]
                    ),
                }
                for gate_id in sorted(REQUIRED_GATE_IDS)
            ],
        }
        (repository / "release" / "readiness.v0.1.json").write_text(
            json.dumps(readiness), encoding="utf-8"
        )
        return repository

    def release_input(self, root: Path) -> Path:
        release_input = root / "input"
        windows = release_input / "release-windows-x86_64"
        macos = release_input / "release-darwin-x86_64"
        windows.mkdir(parents=True, exist_ok=True)
        macos.mkdir(parents=True, exist_ok=True)
        (windows / "CodeIsCheap_1.2.3_x64-setup.exe").write_bytes(b"windows-installer")
        (windows / "CodeIsCheap_1.2.3_x64-setup.nsis.zip").write_bytes(
            b"windows-updater"
        )
        (windows / "CodeIsCheap_1.2.3_x64-setup.nsis.zip.sig").write_text(
            "w" * 64, encoding="utf-8"
        )
        (windows / "CodeIsCheap_1.2.3_x64_en-US.msi").write_bytes(b"windows-msi")
        (macos / "CodeIsCheap_aarch.app.tar.gz").write_bytes(b"macos-updater")
        (macos / "CodeIsCheap_aarch.app.tar.gz.sig").write_text(
            "m" * 64, encoding="utf-8"
        )
        (macos / "CodeIsCheap_1.2.3_x64.dmg").write_bytes(b"macos-dmg")
        return release_input

    def test_prepares_latest_json_and_integrity_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            manifest = prepare_release(
                self.repository(root),
                self.release_input(root),
                output,
                "v1.2.3",
                "example/CodeIsCheap",
                "2026-07-21T00:00:00Z",
                "Signed release",
            )

            self.assertEqual(manifest["version"], "1.2.3")
            self.assertEqual(
                manifest["readiness"]["file"], "release-readiness.v0.1.json"
            )
            latest = json.loads((output / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                set(latest["platforms"]), {"windows-x86_64", "darwin-x86_64"}
            )
            self.assertTrue(
                latest["platforms"]["windows-x86_64"]["url"].endswith(
                    "CodeIsCheap_1.2.3_x64-setup.nsis.zip"
                )
            )
            self.assertEqual(verify_release(output)["tag"], "v1.2.3")

            readiness_path = output / "release-readiness.v0.1.json"
            readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
            readiness["gates"][0] = {
                "id": readiness["gates"][0]["id"],
                "status": "pending",
                "reviewer": None,
                "completedAt": None,
                "evidence": [],
            }
            readiness_path.write_text(json.dumps(readiness), encoding="utf-8")
            manifest_path = output / "release-manifest.v0.1.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["readiness"]["bytes"] = readiness_path.stat().st_size
            manifest["readiness"]["sha256"] = sha256_file(readiness_path)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "incomplete gate"):
                verify_release(output)

    def test_rejects_version_mismatch_missing_signatures_and_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.repository(root)
            release_input = self.release_input(root)
            with self.assertRaises(ReleaseError):
                validate_tag(repository, "v1.2.4")
            (release_input / "release-darwin-x86_64/CodeIsCheap_aarch.app.tar.gz.sig").unlink()
            with self.assertRaises(ReleaseError):
                prepare_release(
                    repository,
                    release_input,
                    root / "missing-signature",
                    "v1.2.3",
                    "example/CodeIsCheap",
                    "2026-07-21T00:00:00Z",
                    "Release",
                )

            release_input = self.release_input(root)
            output = root / "output"
            prepare_release(
                repository,
                release_input,
                output,
                "v1.2.3",
                "example/CodeIsCheap",
                "2026-07-21T00:00:00Z",
                "Release",
            )
            updater = output / "CodeIsCheap_1.2.3_x64-setup.nsis.zip"
            updater.write_bytes(b"tampered")
            with self.assertRaises(ReleaseError):
                verify_release(output)

    def test_prerelease_can_build_signed_candidate_with_pending_manual_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.repository(root, "1.2.3-rc.1")
            readiness_path = repository / "release/readiness.v0.1.json"
            readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
            readiness["gates"][0] = {
                "id": readiness["gates"][0]["id"],
                "status": "pending",
                "reviewer": None,
                "completedAt": None,
                "evidence": [],
            }
            readiness_path.write_text(json.dumps(readiness), encoding="utf-8")

            manifest = prepare_release(
                repository,
                self.release_input(root),
                root / "candidate",
                "v1.2.3-rc.1",
                "example/CodeIsCheap",
                "2026-07-21T00:00:00Z",
                "Release candidate",
            )
            self.assertEqual(manifest["version"], "1.2.3-rc.1")
            self.assertEqual(verify_release(root / "candidate")["tag"], "v1.2.3-rc.1")

            output = root / "candidate"
            output_readiness_path = output / "release-readiness.v0.1.json"
            output_readiness = json.loads(
                output_readiness_path.read_text(encoding="utf-8")
            )
            output_readiness["gates"][0]["status"] = "waived"
            output_readiness_path.write_text(
                json.dumps(output_readiness), encoding="utf-8"
            )
            manifest_path = output / "release-manifest.v0.1.json"
            output_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            output_manifest["readiness"]["bytes"] = output_readiness_path.stat().st_size
            output_manifest["readiness"]["sha256"] = sha256_file(
                output_readiness_path
            )
            manifest_path.write_text(json.dumps(output_manifest), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "unsupported gate status"):
                verify_release(output)


if __name__ == "__main__":
    unittest.main()
