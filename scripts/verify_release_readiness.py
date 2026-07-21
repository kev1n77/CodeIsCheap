from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any
from urllib.parse import urlsplit

from release_version import ReleaseVersionError, repository_version, validate_tag
from verify_readiness_evidence import (
    BETA_GATE_IDS,
    MANUAL_GATE_IDS,
    ReadinessEvidenceError,
    validate_beta_report,
    validate_manual_evidence,
)


READINESS_SCHEMA_VERSION = "0.1"
READINESS_PATH = Path("release/readiness.v0.1.json")
MAX_READINESS_BYTES = 128 * 1024
REQUIRED_GATE_IDS = {
    "beta_crash_free_sessions",
    "compatibility_matrix",
    "endpoint_parse_rate",
    "first_capture_p50",
    "incident_response_drill",
    "incident_response_plan",
    "independent_security_review",
    "macos_admin_matrix",
    "screen_reader_acceptance",
    "signed_update_rollback",
    "support_process",
    "windows_admin_matrix",
}
ROOT_KEYS = {
    "schemaVersion",
    "releaseVersion",
    "updatedAt",
    "notesFile",
    "gates",
}
GATE_KEYS = {"id", "status", "reviewer", "completedAt", "evidence"}


class ReadinessError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadinessError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ReadinessError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReadinessError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ReadinessError(f"{field} must include a timezone")
    return parsed


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        raise ReadinessError(
            f"{context} fields are invalid (missing: {missing}; unknown: {extra})"
        )


def _regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReadinessError(f"{label} is unavailable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReadinessError(f"{label} must be a regular file, not a symlink")
    if metadata.st_size == 0 or metadata.st_size > maximum:
        raise ReadinessError(f"{label} has an invalid size")
    try:
        with path.open("rb") as source:
            encoded = source.read(maximum + 1)
    except OSError as error:
        raise ReadinessError(f"{label} could not be read: {error}") from error
    if not encoded or len(encoded) > maximum:
        raise ReadinessError(f"{label} changed to an invalid size while read")
    return encoded


def _local_evidence(repository: Path, value: str) -> None:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts or "\\" in value:
        raise ReadinessError(f"local evidence path is unsafe: {value}")
    path = repository.joinpath(*candidate.parts)
    resolved_repository = repository.resolve(strict=True)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReadinessError(f"local evidence is unavailable: {value}") from error
    if not resolved.is_relative_to(resolved_repository):
        raise ReadinessError(f"local evidence escapes the repository: {value}")
    _regular_file(path, 2 * 1024 * 1024, f"evidence {value}")


def _evidence(repository: Path, value: Any, gate_id: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ReadinessError(f"gate {gate_id} contains invalid evidence")
    parsed = urlsplit(value)
    if parsed.scheme:
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ReadinessError(f"gate {gate_id} evidence URL must use safe HTTPS")
    else:
        _local_evidence(repository, value)
    return value


def _structured_evidence_path(repository: Path, value: str, gate_id: str) -> Path:
    if urlsplit(value).scheme:
        raise ReadinessError(
            f"gate {gate_id} requires its first evidence item to be a local JSON file"
        )
    return repository.joinpath(*PurePosixPath(value).parts)


def _read_document(repository: Path) -> dict[str, Any]:
    path = repository / READINESS_PATH
    encoded = _regular_file(path, MAX_READINESS_BYTES, "release readiness file")
    try:
        document = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except UnicodeDecodeError as error:
        raise ReadinessError("release readiness file must be UTF-8 JSON") from error
    except RecursionError as error:
        raise ReadinessError("release readiness JSON nesting is too deep") from error
    except json.JSONDecodeError as error:
        raise ReadinessError(f"release readiness JSON is invalid: {error.msg}") from error
    if not isinstance(document, dict):
        raise ReadinessError("release readiness root must be an object")
    return document


def verify_release_readiness(
    repository: Path,
    tag: str | None = None,
    *,
    allow_pending: bool = False,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    try:
        expected_version = (
            validate_tag(repository, tag) if tag else repository_version(repository)
        )
    except ReleaseVersionError as error:
        raise ReadinessError(str(error)) from error
    document = _read_document(repository)
    _exact_keys(document, ROOT_KEYS, "readiness")
    if document.get("schemaVersion") != READINESS_SCHEMA_VERSION:
        raise ReadinessError("release readiness schema is unsupported")
    if document.get("releaseVersion") != expected_version:
        raise ReadinessError(
            "release readiness version does not match the desktop application"
        )
    updated_at = _timestamp(document.get("updatedAt"), "readiness.updatedAt")

    expected_notes = f"release/notes/v{expected_version}.md"
    if document.get("notesFile") != expected_notes:
        raise ReadinessError(f"readiness.notesFile must equal {expected_notes}")
    _local_evidence(repository, expected_notes)

    gates = document.get("gates")
    if not isinstance(gates, list):
        raise ReadinessError("readiness.gates must be an array")
    seen: set[str] = set()
    pending: list[str] = []
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            raise ReadinessError(f"readiness.gates[{index}] must be an object")
        _exact_keys(gate, GATE_KEYS, f"readiness.gates[{index}]")
        gate_id = gate.get("id")
        if not isinstance(gate_id, str) or gate_id not in REQUIRED_GATE_IDS:
            raise ReadinessError(f"readiness.gates[{index}].id is unsupported")
        if gate_id in seen:
            raise ReadinessError(f"duplicate readiness gate: {gate_id}")
        seen.add(gate_id)
        status = gate.get("status")
        evidence = gate.get("evidence")
        if not isinstance(evidence, list) or len(evidence) > 8:
            raise ReadinessError(f"gate {gate_id} evidence must be an array of at most 8 items")
        if status == "pending":
            if gate.get("reviewer") is not None or gate.get("completedAt") is not None or evidence:
                raise ReadinessError(f"pending gate {gate_id} cannot claim approval or evidence")
            pending.append(gate_id)
        elif status == "passed":
            reviewer = gate.get("reviewer")
            if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 128:
                raise ReadinessError(f"passed gate {gate_id} requires a reviewer")
            if gate_id == "independent_security_review" and reviewer.strip().lower() in {
                "codex",
                "tbd",
            }:
                raise ReadinessError(
                    "independent security review requires an external named reviewer"
                )
            completed_at = _timestamp(
                gate.get("completedAt"), f"gate {gate_id}.completedAt"
            )
            if completed_at > updated_at:
                raise ReadinessError(
                    f"gate {gate_id} completion is later than readiness.updatedAt"
                )
            if not evidence:
                raise ReadinessError(f"passed gate {gate_id} requires evidence")
            validated_evidence = [
                _evidence(repository, item, gate_id) for item in evidence
            ]
            if len(set(validated_evidence)) != len(validated_evidence):
                raise ReadinessError(f"gate {gate_id} contains duplicate evidence")
            try:
                if gate_id in MANUAL_GATE_IDS:
                    validate_manual_evidence(
                        _structured_evidence_path(
                            repository, validated_evidence[0], gate_id
                        ),
                        repository,
                        gate_id=gate_id,
                        release_version=expected_version,
                        reviewer=reviewer,
                        gate_completed_at=gate["completedAt"],
                    )
                elif gate_id in BETA_GATE_IDS:
                    validate_beta_report(
                        _structured_evidence_path(
                            repository, validated_evidence[0], gate_id
                        ),
                        repository,
                        release_version=expected_version,
                    )
            except ReadinessEvidenceError as error:
                raise ReadinessError(f"gate {gate_id} evidence is invalid: {error}") from error
        else:
            raise ReadinessError(f"gate {gate_id} status must be pending or passed")
    if seen != REQUIRED_GATE_IDS:
        missing = ", ".join(sorted(REQUIRED_GATE_IDS - seen))
        raise ReadinessError(f"required readiness gates are missing: {missing}")
    if pending and not allow_pending:
        raise ReadinessError("release is blocked by pending gates: " + ", ".join(sorted(pending)))
    return {
        "schemaVersion": READINESS_SCHEMA_VERSION,
        "releaseVersion": expected_version,
        "tag": tag or f"v{expected_version}",
        "passed": len(REQUIRED_GATE_IDS) - len(pending),
        "pending": sorted(pending),
        "ready": not pending,
        "notesFile": expected_notes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the versioned CodeIsCheap GA release evidence gates."
    )
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--tag")
    parser.add_argument("--allow-pending", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        report = verify_release_readiness(
            arguments.repository_root,
            arguments.tag,
            allow_pending=arguments.allow_pending,
        )
    except ReadinessError as error:
        print(f"release readiness rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
