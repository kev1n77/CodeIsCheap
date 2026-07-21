from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from aggregate_beta_metrics import (
    MAX_EVIDENCE_BYTES,
    BetaMetricsError,
    aggregate_evidence,
    load_evidence,
    load_policy,
)
from release_version import repository_version


def policy() -> dict[str, object]:
    return {
        "schemaVersion": "0.1",
        "releaseVersion": "0.1.0",
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


def evidence(index: int, *, sample_id: str | None = None) -> dict[str, object]:
    return {
        "formatVersion": "0.1",
        "generatedAtUnixMs": 1_784_000_000_000 + index,
        "sampleId": sample_id or f"{index:032x}",
        "product": {
            "name": "CodeIsCheap",
            "version": "0.1.0",
            "platform": "windows" if index % 2 else "macos",
            "architecture": "x86_64",
        },
        "privacy": {
            "requestContentIncluded": False,
            "requestIdentifiersIncluded": False,
            "rawCaptureIncluded": False,
            "logsIncluded": False,
            "requestTimestampsIncluded": False,
            "pseudonymousSampleIdIncluded": True,
            "automaticUpload": False,
        },
        "metrics": {
            "firstCaptureElapsedMs": index * 100,
            "supportedCaptureCount": 2,
            "parsedCaptureCount": 2,
            "parseRateBasisPoints": 10_000,
            "completedSessionCount": 2,
            "uncleanSessionCount": 0,
            "crashFreeRateBasisPoints": 10_000,
        },
    }


class BetaMetricsAggregationTests(unittest.TestCase):
    def write_policy(self, root: Path) -> tuple[Path, dict[str, object]]:
        path = root / "policy.json"
        document = policy()
        path.write_text(json.dumps(document), encoding="utf-8")
        return path, load_policy(path)

    def write_evidence(self, root: Path, index: int, document: dict[str, object] | None = None) -> Path:
        path = root / f"sample-{index}.json"
        path.write_text(json.dumps(document or evidence(index)), encoding="utf-8")
        return path

    def test_checked_in_policy_matches_the_desktop_release(self) -> None:
        checked_in = load_policy(REPOSITORY_ROOT / "release/beta-metrics-policy.v0.1.json")
        self.assertEqual(checked_in["releaseVersion"], repository_version(REPOSITORY_ROOT))
        self.assertEqual(checked_in["minimums"]["contributors"], 30)

    def test_aggregates_a_sufficient_content_free_cohort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, loaded_policy = self.write_policy(root)
            paths = [self.write_evidence(root, index) for index in range(1, 4)]

            report = aggregate_evidence(
                paths,
                loaded_policy,
                generated_at_unix_ms=1_800_000_000_000,
            )

            self.assertTrue(report["ready"])
            self.assertEqual(report["metrics"]["firstCaptureP50Ms"], 200)
            self.assertEqual(report["metrics"]["parseRateBasisPoints"], 10_000)
            self.assertEqual(report["cohort"]["contributorCount"], 3)
            self.assertEqual(report["cohort"]["platformCounts"], {"macos": 1, "windows": 2})
            self.assertFalse(report["privacy"]["sampleIdsIncluded"])
            rendered = json.dumps(report)
            self.assertNotIn(f"{1:032x}", rendered)

    def test_rejects_duplicate_contributors_and_forged_rates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, loaded_policy = self.write_policy(root)
            duplicate_id = "a" * 32
            paths = [
                self.write_evidence(root, 1, evidence(1, sample_id=duplicate_id)),
                self.write_evidence(root, 2, evidence(2, sample_id=duplicate_id)),
            ]
            with self.assertRaisesRegex(BetaMetricsError, "duplicate Beta contributor"):
                aggregate_evidence(paths, loaded_policy)

            forged = evidence(3)
            forged["metrics"]["parseRateBasisPoints"] = 9_999
            forged_path = self.write_evidence(root, 3, forged)
            with self.assertRaisesRegex(BetaMetricsError, "parse rate"):
                load_evidence(forged_path, loaded_policy)

    def test_rejects_unsafe_privacy_wrong_versions_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, loaded_policy = self.write_policy(root)
            cases = []

            unsafe = evidence(1)
            unsafe["privacy"]["requestContentIncluded"] = True
            cases.append(unsafe)

            numeric_privacy = evidence(4)
            numeric_privacy["privacy"]["requestContentIncluded"] = 0
            cases.append(numeric_privacy)

            wrong_version = evidence(2)
            wrong_version["product"]["version"] = "0.2.0"
            cases.append(wrong_version)

            content = evidence(3)
            content["prompt"] = "private"
            cases.append(content)

            boolean_rate = evidence(5)
            boolean_rate["metrics"]["parsedCaptureCount"] = 0
            boolean_rate["metrics"]["parseRateBasisPoints"] = False
            cases.append(boolean_rate)

            for index, document in enumerate(cases, 10):
                with self.subTest(document=document):
                    path = self.write_evidence(root, index, document)
                    with self.assertRaises(BetaMetricsError):
                        load_evidence(path, loaded_policy)

    def test_reports_insufficient_evidence_without_claiming_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, loaded_policy = self.write_policy(root)
            report = aggregate_evidence(
                [self.write_evidence(root, 1)],
                loaded_policy,
                generated_at_unix_ms=1,
            )

            self.assertFalse(report["ready"])
            self.assertEqual(
                {gate["status"] for gate in report["gates"].values()},
                {"insufficient"},
            )

    def test_loaders_reject_duplicate_keys_oversized_files_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, loaded_policy = self.write_policy(root)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"formatVersion":"0.1","formatVersion":"0.1"}', encoding="utf-8")
            with self.assertRaisesRegex(BetaMetricsError, "duplicate JSON key"):
                load_evidence(duplicate, loaded_policy)

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MAX_EVIDENCE_BYTES + 1))
            with self.assertRaisesRegex(BetaMetricsError, "size"):
                load_evidence(oversized, loaded_policy)

            source = self.write_evidence(root, 1)
            symlink = root / "symlink.json"
            try:
                symlink.symlink_to(source)
            except OSError:
                return
            with self.assertRaisesRegex(BetaMetricsError, "symlink"):
                load_evidence(symlink, loaded_policy)

    def test_cli_writes_only_new_reports_and_can_require_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path, _ = self.write_policy(root)
            evidence_directory = root / "evidence"
            evidence_directory.mkdir()
            for index in range(1, 4):
                self.write_evidence(evidence_directory, index)
            output = root / "report.json"
            command = [
                sys.executable,
                str(SCRIPTS / "aggregate_beta_metrics.py"),
                "--policy",
                str(policy_path),
                "--input-directory",
                str(evidence_directory),
                "--generated-at-unix-ms",
                "1800000000000",
                "--require-ready",
                "--output",
                str(output),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["ready"])
            repeated = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 1)

            insufficient = root / "insufficient"
            insufficient.mkdir()
            self.write_evidence(insufficient, 9)
            not_ready = subprocess.run(
                command[0:4]
                + ["--input-directory", str(insufficient), "--require-ready"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(not_ready.returncode, 2)


if __name__ == "__main__":
    unittest.main()
