#!/usr/bin/env python3
"""Generate and validate structured evidence for external GA readiness gates."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any
from urllib.parse import urlsplit

from aggregate_beta_metrics import load_policy


EVIDENCE_SCHEMA_VERSION = "0.1"
MAX_PACKET_BYTES = 256 * 1024
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_TEXT_CHARS = 2_000
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")

MANUAL_GATE_SCENARIOS: dict[str, dict[str, str]] = {
    "windows_admin_matrix": {
        "gateway_standard_user": "windows",
        "proxy_standard_user": "windows",
        "ca_trust_round_trip": "windows",
        "proxy_force_kill_recovery": "windows",
        "startup_recovery": "windows",
    },
    "macos_admin_matrix": {
        "apple_silicon_proxy_recovery": "macos",
        "intel_proxy_recovery": "macos",
        "ca_trust_round_trip": "macos",
        "authorization_denial_recovery": "macos",
        "helper_force_kill_recovery": "macos",
    },
    "screen_reader_acceptance": {
        "nvda_workbench_navigation": "windows",
        "nvda_settings_and_export": "windows",
        "voiceover_workbench_navigation": "macos",
        "voiceover_settings_and_export": "macos",
    },
    "independent_security_review": {
        "threat_model_review": "cross-platform",
        "capture_boundary_review": "cross-platform",
        "storage_and_export_review": "cross-platform",
        "release_and_update_review": "cross-platform",
        "finding_disposition": "cross-platform",
    },
    "signed_update_rollback": {
        "windows_signed_update": "windows",
        "windows_migration_failure_recovery": "windows",
        "macos_signed_update": "macos",
        "macos_migration_failure_recovery": "macos",
    },
    "incident_response_drill": {
        "windows_network_recovery": "windows",
        "macos_network_recovery": "macos",
        "tampered_update_rejection": "cross-platform",
        "migration_failure_response": "cross-platform",
        "communication_and_follow_up": "cross-platform",
    },
}
MANUAL_GATE_IDS = frozenset(MANUAL_GATE_SCENARIOS)
BETA_GATE_IDS = frozenset(
    {"first_capture_p50", "endpoint_parse_rate", "beta_crash_free_sessions"}
)
ROOT_KEYS = {
    "schemaVersion",
    "releaseVersion",
    "gateId",
    "completedAt",
    "executor",
    "reviewer",
    "summary",
    "scenarios",
}
SCENARIO_KEYS = {
    "id",
    "platform",
    "architecture",
    "environment",
    "status",
    "evidence",
    "notes",
}
BETA_ROOT_KEYS = {
    "schemaVersion",
    "releaseVersion",
    "generatedAtUnixMs",
    "privacy",
    "cohort",
    "metrics",
    "gates",
    "ready",
}
BETA_PRIVACY = {
    "sourceContentIncluded": False,
    "sampleIdsIncluded": False,
    "automaticUpload": False,
}
BETA_COHORT_KEYS = {"contributorCount", "platformCounts", "sourceSha256"}
BETA_METRIC_KEYS = {
    "firstCaptureSampleCount",
    "firstCaptureP50Ms",
    "supportedCaptureCount",
    "parsedCaptureCount",
    "parseRateBasisPoints",
    "completedSessionCount",
    "uncleanSessionCount",
    "crashFreeRateBasisPoints",
}
BETA_REPORT_GATES = {
    "firstCaptureP50": "firstCaptureP50Ms",
    "endpointParseRate": "parseRateBasisPoints",
    "crashFreeSessions": "crashFreeRateBasisPoints",
}
BETA_GATE_KEYS = {"status", "actual", "requirement"}


class ReadinessEvidenceError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadinessEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        unknown = ", ".join(sorted(actual - expected)) or "none"
        raise ReadinessEvidenceError(
            f"{context} fields are invalid (missing: {missing}; unknown: {unknown})"
        )


def _text(value: Any, context: str, *, maximum: int = MAX_TEXT_CHARS) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 and character not in "\n\r\t" for character in value)
    ):
        raise ReadinessEvidenceError(
            f"{context} must be non-empty text of at most {maximum} characters"
        )
    return value.strip()


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ReadinessEvidenceError(f"{context} must be an integer of at least {minimum}")
    return value


def _timestamp(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ReadinessEvidenceError(f"{context} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReadinessEvidenceError(f"{context} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ReadinessEvidenceError(f"{context} must include a timezone")
    return parsed


def _regular_file(path: Path, maximum: int, context: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReadinessEvidenceError(f"{context} is unavailable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReadinessEvidenceError(f"{context} must be a regular file, not a symlink")
    if metadata.st_size == 0 or metadata.st_size > maximum:
        raise ReadinessEvidenceError(f"{context} has an invalid size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ReadinessEvidenceError(f"{context} must remain a regular file while read")
            encoded = source.read(maximum + 1)
    except OSError as error:
        raise ReadinessEvidenceError(f"{context} could not be read: {error}") from error
    if not encoded or len(encoded) > maximum:
        raise ReadinessEvidenceError(f"{context} changed to an invalid size while read")
    return encoded


def _read_json(path: Path, context: str) -> dict[str, Any]:
    encoded = _regular_file(path, MAX_PACKET_BYTES, context)
    try:
        document = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except UnicodeDecodeError as error:
        raise ReadinessEvidenceError(f"{context} must be UTF-8 JSON") from error
    except RecursionError as error:
        raise ReadinessEvidenceError(f"{context} JSON nesting is too deep") from error
    except json.JSONDecodeError as error:
        raise ReadinessEvidenceError(f"{context} is invalid JSON: {error.msg}") from error
    if not isinstance(document, dict):
        raise ReadinessEvidenceError(f"{context} root must be an object")
    return document


def _reference(
    repository: Path,
    value: Any,
    context: str,
    *,
    packet_path: Path | None = None,
) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ReadinessEvidenceError(f"{context} contains an invalid evidence reference")
    parsed = urlsplit(value)
    if parsed.scheme:
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ReadinessEvidenceError(f"{context} evidence URL must use safe HTTPS")
        return value
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts or "\\" in value:
        raise ReadinessEvidenceError(f"{context} local evidence path is unsafe: {value}")
    path = repository.joinpath(*candidate.parts)
    try:
        resolved_repository = repository.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReadinessEvidenceError(f"{context} local evidence is unavailable: {value}") from error
    if not resolved.is_relative_to(resolved_repository):
        raise ReadinessEvidenceError(f"{context} local evidence escapes the repository")
    if packet_path is not None and resolved == packet_path.resolve(strict=True):
        raise ReadinessEvidenceError(f"{context} cannot cite its own evidence packet")
    _regular_file(path, MAX_ATTACHMENT_BYTES, f"{context} evidence {value}")
    return value


def build_manual_template(gate_id: str, release_version: str) -> dict[str, Any]:
    scenarios = MANUAL_GATE_SCENARIOS.get(gate_id)
    if scenarios is None:
        raise ReadinessEvidenceError(f"manual readiness gate is unsupported: {gate_id}")
    if not VERSION.fullmatch(release_version):
        raise ReadinessEvidenceError("release version must be a plain semantic version")
    return {
        "schemaVersion": EVIDENCE_SCHEMA_VERSION,
        "releaseVersion": release_version,
        "gateId": gate_id,
        "completedAt": "",
        "executor": "",
        "reviewer": "",
        "summary": "",
        "scenarios": [
            {
                "id": scenario_id,
                "platform": platform,
                "architecture": "n/a" if platform == "cross-platform" else "",
                "environment": "",
                "status": "pending",
                "evidence": [],
                "notes": "",
            }
            for scenario_id, platform in scenarios.items()
        ],
    }


def write_manual_template(path: Path, gate_id: str, release_version: str) -> None:
    if path.suffix.lower() != ".json":
        raise ReadinessEvidenceError("manual evidence template must use a .json filename")
    encoded = f"{json.dumps(build_manual_template(gate_id, release_version), indent=2)}\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise ReadinessEvidenceError(f"manual evidence template must be a new file: {error}") from error


def validate_manual_evidence(
    path: Path,
    repository: Path,
    *,
    gate_id: str | None = None,
    release_version: str | None = None,
    reviewer: str | None = None,
    gate_completed_at: str | None = None,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    document = _read_json(path, f"manual evidence {path.name}")
    _exact_keys(document, ROOT_KEYS, "manual evidence")
    if document["schemaVersion"] != EVIDENCE_SCHEMA_VERSION:
        raise ReadinessEvidenceError("manual evidence schema version is unsupported")
    actual_version = _text(document["releaseVersion"], "manual evidence.releaseVersion")
    if not VERSION.fullmatch(actual_version):
        raise ReadinessEvidenceError("manual evidence releaseVersion must be semantic version")
    if release_version is not None and actual_version != release_version:
        raise ReadinessEvidenceError("manual evidence release version does not match readiness")
    actual_gate = document["gateId"]
    scenarios_required = MANUAL_GATE_SCENARIOS.get(actual_gate)
    if scenarios_required is None:
        raise ReadinessEvidenceError("manual evidence gateId is unsupported")
    if gate_id is not None and actual_gate != gate_id:
        raise ReadinessEvidenceError("manual evidence gate does not match readiness")
    completed_at = _timestamp(document["completedAt"], "manual evidence.completedAt")
    if gate_completed_at is not None and completed_at > _timestamp(
        gate_completed_at, "readiness gate completedAt"
    ):
        raise ReadinessEvidenceError("manual evidence was completed after its readiness approval")
    executor = _text(document["executor"], "manual evidence.executor", maximum=128)
    actual_reviewer = _text(document["reviewer"], "manual evidence.reviewer", maximum=128)
    if executor.casefold() == actual_reviewer.casefold():
        raise ReadinessEvidenceError("manual evidence executor and reviewer must be different people")
    if reviewer is not None and actual_reviewer != reviewer.strip():
        raise ReadinessEvidenceError("manual evidence reviewer does not match readiness")
    _text(document["summary"], "manual evidence.summary")

    scenarios = document["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(scenarios_required):
        raise ReadinessEvidenceError("manual evidence scenarios must match the required matrix")
    seen: set[str] = set()
    references: set[str] = set()
    for index, scenario in enumerate(scenarios):
        context = f"manual evidence.scenarios[{index}]"
        if not isinstance(scenario, dict):
            raise ReadinessEvidenceError(f"{context} must be an object")
        _exact_keys(scenario, SCENARIO_KEYS, context)
        scenario_id = scenario["id"]
        if not isinstance(scenario_id, str) or scenario_id not in scenarios_required:
            raise ReadinessEvidenceError(f"{context}.id is unsupported")
        if scenario_id in seen:
            raise ReadinessEvidenceError(f"duplicate manual evidence scenario: {scenario_id}")
        seen.add(scenario_id)
        if scenario["platform"] != scenarios_required[scenario_id]:
            raise ReadinessEvidenceError(f"{context}.platform does not match the required matrix")
        _text(scenario["architecture"], f"{context}.architecture", maximum=64)
        _text(scenario["environment"], f"{context}.environment", maximum=512)
        if scenario["status"] != "passed":
            raise ReadinessEvidenceError(f"{context}.status must be passed")
        evidence = scenario["evidence"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 8:
            raise ReadinessEvidenceError(f"{context}.evidence must contain 1 to 8 items")
        for item in evidence:
            reference = _reference(repository, item, context, packet_path=path)
            if reference in references:
                raise ReadinessEvidenceError("manual evidence references must be unique across scenarios")
            references.add(reference)
        _text(scenario["notes"], f"{context}.notes")
    if seen != set(scenarios_required):
        raise ReadinessEvidenceError("manual evidence is missing required scenarios")
    return document


def _rate(numerator: int, denominator: int) -> int | None:
    return None if denominator == 0 else min(10_000, numerator * 10_000 // denominator)


def validate_beta_report(
    path: Path,
    repository: Path,
    *,
    release_version: str | None = None,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    report = _read_json(path, f"Beta readiness report {path.name}")
    _exact_keys(report, BETA_ROOT_KEYS, "Beta readiness report")
    if report["schemaVersion"] != EVIDENCE_SCHEMA_VERSION:
        raise ReadinessEvidenceError("Beta readiness report schema version is unsupported")
    actual_version = _text(report["releaseVersion"], "Beta report.releaseVersion")
    if not VERSION.fullmatch(actual_version):
        raise ReadinessEvidenceError("Beta report releaseVersion must be semantic version")
    if release_version is not None and actual_version != release_version:
        raise ReadinessEvidenceError("Beta report release version does not match readiness")
    _integer(report["generatedAtUnixMs"], "Beta report.generatedAtUnixMs", minimum=1)
    if report["privacy"] != BETA_PRIVACY:
        raise ReadinessEvidenceError("Beta readiness report privacy declaration is unsafe")
    if report["ready"] is not True:
        raise ReadinessEvidenceError("Beta readiness report must pass every Beta gate")

    cohort = report["cohort"]
    metrics = report["metrics"]
    gates = report["gates"]
    if not isinstance(cohort, dict) or not isinstance(metrics, dict) or not isinstance(gates, dict):
        raise ReadinessEvidenceError("Beta report cohort, metrics, and gates must be objects")
    _exact_keys(cohort, BETA_COHORT_KEYS, "Beta report.cohort")
    _exact_keys(metrics, BETA_METRIC_KEYS, "Beta report.metrics")
    _exact_keys(gates, set(BETA_REPORT_GATES), "Beta report.gates")

    contributors = _integer(cohort["contributorCount"], "Beta report contributorCount", minimum=1)
    platform_counts = cohort["platformCounts"]
    digests = cohort["sourceSha256"]
    if (
        not isinstance(platform_counts, dict)
        or not platform_counts
        or any(not isinstance(key, str) or not key for key in platform_counts)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in platform_counts.values()
        )
        or sum(platform_counts.values()) != contributors
    ):
        raise ReadinessEvidenceError("Beta report platformCounts do not match contributorCount")
    if (
        not isinstance(digests, list)
        or len(digests) != contributors
        or len(set(digests)) != len(digests)
        or any(not isinstance(digest, str) or not SHA256.fullmatch(digest) for digest in digests)
    ):
        raise ReadinessEvidenceError("Beta report sourceSha256 must identify every contributor")

    first_samples = _integer(metrics["firstCaptureSampleCount"], "Beta firstCaptureSampleCount")
    first_p50 = metrics["firstCaptureP50Ms"]
    if first_p50 is not None:
        first_p50 = _integer(first_p50, "Beta firstCaptureP50Ms")
    supported = _integer(metrics["supportedCaptureCount"], "Beta supportedCaptureCount")
    parsed = _integer(metrics["parsedCaptureCount"], "Beta parsedCaptureCount")
    completed = _integer(metrics["completedSessionCount"], "Beta completedSessionCount")
    unclean = _integer(metrics["uncleanSessionCount"], "Beta uncleanSessionCount")
    if first_samples > contributors or parsed > supported or unclean > completed:
        raise ReadinessEvidenceError("Beta readiness report aggregate counts are inconsistent")
    parse_rate = metrics["parseRateBasisPoints"]
    crash_rate = metrics["crashFreeRateBasisPoints"]
    if parse_rate != _rate(parsed, supported) or crash_rate != _rate(completed - unclean, completed):
        raise ReadinessEvidenceError("Beta readiness report rates do not match their counts")

    policy_path = repository / "release" / "beta-metrics-policy.v0.1.json"
    try:
        policy = load_policy(policy_path)
    except Exception as error:
        raise ReadinessEvidenceError(f"Beta metrics policy is invalid: {error}") from error
    if policy["releaseVersion"] != actual_version:
        raise ReadinessEvidenceError("Beta report release version does not match its policy")
    if not set(platform_counts).issubset(set(policy["allowedPlatforms"])):
        raise ReadinessEvidenceError("Beta report contains a platform outside its policy")
    minimums = policy["minimums"]
    thresholds = policy["thresholds"]
    if (
        contributors < minimums["contributors"]
        or first_samples < minimums["firstCaptureSamples"]
        or supported < minimums["supportedCaptures"]
        or completed < minimums["completedSessions"]
        or first_p50 is None
        or first_p50 >= thresholds["firstCaptureP50MaxMs"]
        or parse_rate is None
        or parse_rate <= thresholds["endpointParseRateMinBasisPointsExclusive"]
        or crash_rate is None
        or crash_rate <= thresholds["crashFreeRateMinBasisPointsExclusive"]
    ):
        raise ReadinessEvidenceError("Beta readiness report does not meet the release policy")

    for gate_name, metric_name in BETA_REPORT_GATES.items():
        gate = gates[gate_name]
        if not isinstance(gate, dict):
            raise ReadinessEvidenceError(f"Beta report gate {gate_name} must be an object")
        _exact_keys(gate, BETA_GATE_KEYS, f"Beta report.gates.{gate_name}")
        if gate["status"] != "passed" or gate["actual"] != metrics[metric_name]:
            raise ReadinessEvidenceError(f"Beta report gate {gate_name} is inconsistent")
        _text(gate["requirement"], f"Beta report.gates.{gate_name}.requirement", maximum=512)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    initialize = subparsers.add_parser("init-manual", help="write a new manual gate template")
    initialize.add_argument("--gate", choices=sorted(MANUAL_GATE_IDS), required=True)
    initialize.add_argument("--release-version", required=True)
    initialize.add_argument("--output", type=Path, required=True)
    verify_manual = subparsers.add_parser("verify-manual", help="validate a completed manual packet")
    verify_manual.add_argument("--repository-root", type=Path, default=Path.cwd())
    verify_manual.add_argument("--evidence", type=Path, required=True)
    verify_beta = subparsers.add_parser("verify-beta", help="validate a ready Beta report")
    verify_beta.add_argument("--repository-root", type=Path, default=Path.cwd())
    verify_beta.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init-manual":
            write_manual_template(arguments.output, arguments.gate, arguments.release_version)
            print(f"Manual evidence template written to {arguments.output}")
        elif arguments.command == "verify-manual":
            document = validate_manual_evidence(
                arguments.evidence, arguments.repository_root
            )
            print(
                json.dumps(
                    {
                        "gateId": document["gateId"],
                        "releaseVersion": document["releaseVersion"],
                        "scenarioCount": len(document["scenarios"]),
                        "valid": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            report = validate_beta_report(arguments.evidence, arguments.repository_root)
            print(
                json.dumps(
                    {
                        "releaseVersion": report["releaseVersion"],
                        "contributorCount": report["cohort"]["contributorCount"],
                        "valid": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
    except ReadinessEvidenceError as error:
        print(f"readiness evidence rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
