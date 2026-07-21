from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


FORMAT_VERSION = "0.1"
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_POLICY_BYTES = 32 * 1024
MAX_EVIDENCE_FILES = 1_000
MAX_COUNTER = 1_000_000_000_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_FIRST_CAPTURE_MS = 30 * 24 * 60 * 60 * 1_000
DEFAULT_POLICY_PATH = Path("release/beta-metrics-policy.v0.1.json")

ROOT_KEYS = {"formatVersion", "generatedAtUnixMs", "sampleId", "product", "privacy", "metrics"}
PRODUCT_KEYS = {"name", "version", "platform", "architecture"}
PRIVACY = {
    "requestContentIncluded": False,
    "requestIdentifiersIncluded": False,
    "rawCaptureIncluded": False,
    "logsIncluded": False,
    "requestTimestampsIncluded": False,
    "pseudonymousSampleIdIncluded": True,
    "automaticUpload": False,
}
METRIC_KEYS = {
    "firstCaptureElapsedMs",
    "supportedCaptureCount",
    "parsedCaptureCount",
    "parseRateBasisPoints",
    "completedSessionCount",
    "uncleanSessionCount",
    "crashFreeRateBasisPoints",
}
POLICY_KEYS = {"schemaVersion", "releaseVersion", "allowedPlatforms", "minimums", "thresholds"}
MINIMUM_KEYS = {"contributors", "firstCaptureSamples", "supportedCaptures", "completedSessions"}
THRESHOLD_KEYS = {
    "firstCaptureP50MaxMs",
    "endpointParseRateMinBasisPointsExclusive",
    "crashFreeRateMinBasisPointsExclusive",
}
SAMPLE_ID = re.compile(r"[0-9a-f]{32}\Z")
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)


class BetaMetricsError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BetaMetricsError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        missing = ", ".join(sorted(expected - set(value))) or "none"
        unknown = ", ".join(sorted(set(value) - expected)) or "none"
        raise BetaMetricsError(
            f"{context} fields are invalid (missing: {missing}; unknown: {unknown})"
        )


def _integer(value: Any, context: str, *, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise BetaMetricsError(f"{context} must be an integer from {minimum} to {maximum}")
    return value


def _text(value: Any, context: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BetaMetricsError(f"{context} must be non-empty text of at most {maximum} characters")
    return value


def _read_json(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BetaMetricsError(f"{label} could not be inspected: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BetaMetricsError(f"{label} must be a regular file, not a symlink")
    if metadata.st_size == 0 or metadata.st_size > maximum:
        raise BetaMetricsError(f"{label} size must be between 1 and {maximum} bytes")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise BetaMetricsError(f"{label} must remain a regular file while read")
            encoded = source.read(maximum + 1)
        if not encoded or len(encoded) > maximum:
            raise BetaMetricsError(f"{label} changed to an invalid size while read")
        document = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except OSError as error:
        raise BetaMetricsError(f"{label} could not be read: {error}") from error
    except UnicodeDecodeError as error:
        raise BetaMetricsError(f"{label} must be UTF-8 JSON") from error
    except RecursionError as error:
        raise BetaMetricsError(f"{label} JSON nesting is too deep") from error
    except json.JSONDecodeError as error:
        raise BetaMetricsError(f"{label} is invalid JSON: {error.msg}") from error
    if not isinstance(document, dict):
        raise BetaMetricsError(f"{label} root must be an object")
    return document, encoded


def load_policy(path: Path) -> dict[str, Any]:
    policy, _ = _read_json(path, MAX_POLICY_BYTES, "Beta metrics policy")
    _exact_keys(policy, POLICY_KEYS, "policy")
    if policy["schemaVersion"] != FORMAT_VERSION:
        raise BetaMetricsError("policy schema version is unsupported")
    version = _text(policy["releaseVersion"], "policy.releaseVersion")
    if not VERSION.fullmatch(version):
        raise BetaMetricsError("policy.releaseVersion must be a plain semantic version")
    platforms = policy["allowedPlatforms"]
    if (
        not isinstance(platforms, list)
        or not 1 <= len(platforms) <= 8
        or any(not isinstance(item, str) or not item or len(item) > 32 for item in platforms)
        or len(set(platforms)) != len(platforms)
    ):
        raise BetaMetricsError("policy.allowedPlatforms must contain unique platform names")
    minimums = policy["minimums"]
    thresholds = policy["thresholds"]
    if not isinstance(minimums, dict) or not isinstance(thresholds, dict):
        raise BetaMetricsError("policy minimums and thresholds must be objects")
    _exact_keys(minimums, MINIMUM_KEYS, "policy.minimums")
    _exact_keys(thresholds, THRESHOLD_KEYS, "policy.thresholds")
    for key in MINIMUM_KEYS:
        _integer(minimums[key], f"policy.minimums.{key}", minimum=1, maximum=MAX_COUNTER)
    if minimums["contributors"] > MAX_EVIDENCE_FILES:
        raise BetaMetricsError(
            f"policy.minimums.contributors cannot exceed {MAX_EVIDENCE_FILES}"
        )
    if minimums["firstCaptureSamples"] > minimums["contributors"]:
        raise BetaMetricsError(
            "policy.minimums.firstCaptureSamples cannot exceed contributors"
        )
    _integer(
        thresholds["firstCaptureP50MaxMs"],
        "policy.thresholds.firstCaptureP50MaxMs",
        minimum=1,
        maximum=MAX_FIRST_CAPTURE_MS,
    )
    for key in (
        "endpointParseRateMinBasisPointsExclusive",
        "crashFreeRateMinBasisPointsExclusive",
    ):
        _integer(thresholds[key], f"policy.thresholds.{key}", maximum=9_999)
    return policy


def _rate_basis_points(numerator: int, denominator: int) -> int | None:
    return None if denominator == 0 else min(10_000, numerator * 10_000 // denominator)


def load_evidence(path: Path, policy: dict[str, Any]) -> dict[str, Any]:
    document, encoded = _read_json(path, MAX_EVIDENCE_BYTES, f"evidence {path.name}")
    _exact_keys(document, ROOT_KEYS, "evidence")
    if document["formatVersion"] != FORMAT_VERSION:
        raise BetaMetricsError(f"evidence {path.name} format version is unsupported")
    _integer(document["generatedAtUnixMs"], "evidence.generatedAtUnixMs", minimum=1)
    sample_id = document["sampleId"]
    if not isinstance(sample_id, str) or not SAMPLE_ID.fullmatch(sample_id):
        raise BetaMetricsError("evidence.sampleId must be 128-bit lowercase hexadecimal")

    product = document["product"]
    if not isinstance(product, dict):
        raise BetaMetricsError("evidence.product must be an object")
    _exact_keys(product, PRODUCT_KEYS, "evidence.product")
    if product["name"] != "CodeIsCheap" or product["version"] != policy["releaseVersion"]:
        raise BetaMetricsError("evidence product name or version does not match the policy")
    if product["platform"] not in policy["allowedPlatforms"]:
        raise BetaMetricsError("evidence platform is outside the release policy")
    _text(product["architecture"], "evidence.product.architecture")

    privacy = document["privacy"]
    if not isinstance(privacy, dict):
        raise BetaMetricsError("evidence.privacy must be an object")
    _exact_keys(privacy, set(PRIVACY), "evidence.privacy")
    if any(type(value) is not bool for value in privacy.values()) or privacy != PRIVACY:
        raise BetaMetricsError("evidence privacy declaration is unsafe")

    metrics = document["metrics"]
    if not isinstance(metrics, dict):
        raise BetaMetricsError("evidence.metrics must be an object")
    _exact_keys(metrics, METRIC_KEYS, "evidence.metrics")
    first_capture = metrics["firstCaptureElapsedMs"]
    if first_capture is not None:
        first_capture = _integer(
            first_capture,
            "evidence.metrics.firstCaptureElapsedMs",
            maximum=MAX_FIRST_CAPTURE_MS,
        )
    supported = _integer(
        metrics["supportedCaptureCount"],
        "evidence.metrics.supportedCaptureCount",
        maximum=MAX_COUNTER,
    )
    parsed = _integer(
        metrics["parsedCaptureCount"],
        "evidence.metrics.parsedCaptureCount",
        maximum=MAX_COUNTER,
    )
    completed = _integer(
        metrics["completedSessionCount"],
        "evidence.metrics.completedSessionCount",
        maximum=MAX_COUNTER,
    )
    unclean = _integer(
        metrics["uncleanSessionCount"],
        "evidence.metrics.uncleanSessionCount",
        maximum=MAX_COUNTER,
    )
    if parsed > supported or unclean > completed:
        raise BetaMetricsError("evidence aggregate counts violate subset invariants")
    expected_parse = _rate_basis_points(parsed, supported)
    expected_crash_free = _rate_basis_points(completed - unclean, completed)
    parse_rate = metrics["parseRateBasisPoints"]
    crash_free_rate = metrics["crashFreeRateBasisPoints"]
    if parse_rate is not None:
        parse_rate = _integer(
            parse_rate, "evidence.metrics.parseRateBasisPoints", maximum=10_000
        )
    if crash_free_rate is not None:
        crash_free_rate = _integer(
            crash_free_rate,
            "evidence.metrics.crashFreeRateBasisPoints",
            maximum=10_000,
        )
    if parse_rate != expected_parse:
        raise BetaMetricsError("evidence parse rate does not match its counts")
    if crash_free_rate != expected_crash_free:
        raise BetaMetricsError("evidence crash-free rate does not match its counts")
    return {
        "sampleId": sample_id,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "platform": product["platform"],
        "firstCaptureElapsedMs": first_capture,
        "supportedCaptureCount": supported,
        "parsedCaptureCount": parsed,
        "completedSessionCount": completed,
        "uncleanSessionCount": unclean,
    }


def _gate(actual: int | None, enough: bool, passed: bool, requirement: str) -> dict[str, Any]:
    status = "insufficient" if not enough else "passed" if passed else "failed"
    return {"status": status, "actual": actual, "requirement": requirement}


def aggregate_evidence(
    paths: list[Path],
    policy: dict[str, Any],
    *,
    generated_at_unix_ms: int | None = None,
) -> dict[str, Any]:
    if not 1 <= len(paths) <= MAX_EVIDENCE_FILES:
        raise BetaMetricsError(f"evidence count must be from 1 to {MAX_EVIDENCE_FILES}")
    samples = [load_evidence(path, policy) for path in paths]
    sample_ids = [sample["sampleId"] for sample in samples]
    if len(set(sample_ids)) != len(sample_ids):
        raise BetaMetricsError("duplicate Beta contributor sampleId")
    digests = [sample["sha256"] for sample in samples]
    if len(set(digests)) != len(digests):
        raise BetaMetricsError("duplicate Beta evidence file content")

    first_captures = sorted(
        sample["firstCaptureElapsedMs"]
        for sample in samples
        if sample["firstCaptureElapsedMs"] is not None
    )
    first_capture_p50 = first_captures[len(first_captures) // 2] if first_captures else None
    supported = _integer(
        sum(sample["supportedCaptureCount"] for sample in samples),
        "report.metrics.supportedCaptureCount",
        maximum=MAX_COUNTER,
    )
    parsed = _integer(
        sum(sample["parsedCaptureCount"] for sample in samples),
        "report.metrics.parsedCaptureCount",
        maximum=MAX_COUNTER,
    )
    completed = _integer(
        sum(sample["completedSessionCount"] for sample in samples),
        "report.metrics.completedSessionCount",
        maximum=MAX_COUNTER,
    )
    unclean = _integer(
        sum(sample["uncleanSessionCount"] for sample in samples),
        "report.metrics.uncleanSessionCount",
        maximum=MAX_COUNTER,
    )
    parse_rate = _rate_basis_points(parsed, supported)
    crash_free_rate = _rate_basis_points(completed - unclean, completed)
    minimums = policy["minimums"]
    thresholds = policy["thresholds"]
    contributor_minimum_met = len(samples) >= minimums["contributors"]

    gates = {
        "firstCaptureP50": _gate(
            first_capture_p50,
            contributor_minimum_met and len(first_captures) >= minimums["firstCaptureSamples"],
            first_capture_p50 is not None
            and first_capture_p50 < thresholds["firstCaptureP50MaxMs"],
            f'< {thresholds["firstCaptureP50MaxMs"]} ms with at least '
            f'{minimums["firstCaptureSamples"]} samples and {minimums["contributors"]} contributors',
        ),
        "endpointParseRate": _gate(
            parse_rate,
            contributor_minimum_met and supported >= minimums["supportedCaptures"],
            parse_rate is not None
            and parse_rate > thresholds["endpointParseRateMinBasisPointsExclusive"],
            f'> {thresholds["endpointParseRateMinBasisPointsExclusive"]} basis points with at least '
            f'{minimums["supportedCaptures"]} captures and {minimums["contributors"]} contributors',
        ),
        "crashFreeSessions": _gate(
            crash_free_rate,
            contributor_minimum_met and completed >= minimums["completedSessions"],
            crash_free_rate is not None
            and crash_free_rate > thresholds["crashFreeRateMinBasisPointsExclusive"],
            f'> {thresholds["crashFreeRateMinBasisPointsExclusive"]} basis points with at least '
            f'{minimums["completedSessions"]} sessions and {minimums["contributors"]} contributors',
        ),
    }
    if generated_at_unix_ms is None:
        generated_at_unix_ms = int(datetime.now(timezone.utc).timestamp() * 1_000)
    _integer(generated_at_unix_ms, "report.generatedAtUnixMs", minimum=1)
    return {
        "schemaVersion": FORMAT_VERSION,
        "releaseVersion": policy["releaseVersion"],
        "generatedAtUnixMs": generated_at_unix_ms,
        "privacy": {
            "sourceContentIncluded": False,
            "sampleIdsIncluded": False,
            "automaticUpload": False,
        },
        "cohort": {
            "contributorCount": len(samples),
            "platformCounts": dict(sorted(Counter(sample["platform"] for sample in samples).items())),
            "sourceSha256": sorted(digests),
        },
        "metrics": {
            "firstCaptureSampleCount": len(first_captures),
            "firstCaptureP50Ms": first_capture_p50,
            "supportedCaptureCount": supported,
            "parsedCaptureCount": parsed,
            "parseRateBasisPoints": parse_rate,
            "completedSessionCount": completed,
            "uncleanSessionCount": unclean,
            "crashFreeRateBasisPoints": crash_free_rate,
        },
        "gates": gates,
        "ready": all(gate["status"] == "passed" for gate in gates.values()),
    }


def _input_paths(arguments: argparse.Namespace) -> list[Path]:
    paths = list(arguments.evidence)
    if arguments.input_directory is not None:
        directory = arguments.input_directory
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise BetaMetricsError(f"input directory is unavailable: {error}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BetaMetricsError("input directory must be a real directory, not a symlink")
        paths.extend(sorted(directory.glob("*.json")))
    if len(set(path.resolve() for path in paths)) != len(paths):
        raise BetaMetricsError("the same evidence path was supplied more than once")
    return paths


def _write_report(path: Path, report: dict[str, Any]) -> None:
    if path.suffix.lower() != ".json":
        raise BetaMetricsError("report output must use a .json filename")
    encoded = f"{json.dumps(report, indent=2, sort_keys=True)}\n"
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise BetaMetricsError(f"report must be written to a new file: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate reviewed, content-free CodeIsCheap Beta evidence.")
    parser.add_argument("evidence", nargs="*", type=Path)
    parser.add_argument("--input-directory", type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--generated-at-unix-ms", type=int)
    parser.add_argument("--require-ready", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        policy = load_policy(arguments.policy)
        report = aggregate_evidence(
            _input_paths(arguments),
            policy,
            generated_at_unix_ms=arguments.generated_at_unix_ms,
        )
        if arguments.output is not None:
            _write_report(arguments.output, report)
            print(f"Beta evidence report written to {arguments.output}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        if arguments.require_ready and not report["ready"]:
            print("Beta evidence does not meet the release policy", file=sys.stderr)
            return 2
        return 0
    except BetaMetricsError as error:
        print(f"Beta evidence rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
