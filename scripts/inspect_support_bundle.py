from __future__ import annotations

import argparse
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


SUPPORT_BUNDLE_FORMAT_VERSION = "0.1"
SUPPORT_BUNDLE_POLICY_VERSION = "0.1"
MAX_SUPPORT_BUNDLE_BYTES = 512 * 1024
MAX_DIAGNOSTIC_EVENTS = 100
MAX_TEXT_LENGTH = 4096
MAX_DOCUMENT_NODES = 10_000
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CREDENTIAL_CORPUS_PATH = (
    REPOSITORY_ROOT / "policies" / "credential-corpus.v0.1.json"
)

TOP_LEVEL_KEYS = {
    "formatVersion",
    "policyVersion",
    "generatedAtUnixMs",
    "product",
    "privacy",
    "diagnostics",
    "redactionCount",
}
PRODUCT_KEYS = {
    "name",
    "version",
    "desktopApiVersion",
    "platform",
    "architecture",
}
PRIVACY_KEYS = {
    "requestContentIncluded",
    "requestIdentifiersIncluded",
    "rawCaptureIncluded",
    "logsIncluded",
    "logDetailsIncluded",
}
DIAGNOSTIC_KEYS = {
    "source",
    "capture",
    "certificateAuthority",
    "health",
    "compatibility",
    "runtimeIssue",
    "diagnosticEvents",
}
CAPTURE_KEYS = {
    "active",
    "canControl",
    "mode",
    "endpoint",
    "profile",
    "proxyAvailable",
    "requestCount",
    "storage",
}
CERTIFICATE_KEYS = {
    "state",
    "trust",
    "privateMaterial",
    "canManageTrust",
    "fingerprintSha256",
}
HEALTH_KEYS = {
    "encryptedStore",
    "captureRuntime",
    "endpointConnected",
    "proxyBundle",
}
COMPATIBILITY_KEYS = {
    "code",
    "status",
    "confidence",
    "title",
    "summary",
    "recommendedMode",
    "action",
    "steps",
}
COMPATIBILITY_STEP_KEYS = {"id", "status", "label", "detail"}
DIAGNOSTIC_EVENT_KEYS = {"occurredAtUnixMs", "code"}
FORBIDDEN_CONTENT_KEYS = {
    "captureid",
    "instructions",
    "messages",
    "prompt",
    "prompts",
    "raw",
    "rawcapture",
    "request",
    "requestbody",
    "requestid",
    "requests",
    "responsebody",
    "tools",
}
COMPATIBILITY_CODES = {
    "gateway_ready",
    "gateway_unavailable",
    "proxy_bundle_unavailable",
    "proxy_unavailable",
    "certificate_missing",
    "certificate_invalid",
    "certificate_trust_required",
    "capture_paused",
    "recovery_read_only",
    "proxy_capture_unobserved",
    "proxy_capture_observed",
}


class SupportBundleError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupportBundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_support_bundle(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SupportBundleError(f"bundle could not be inspected: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SupportBundleError("bundle must be a regular file, not a symlink")
    if metadata.st_size == 0 or metadata.st_size > MAX_SUPPORT_BUNDLE_BYTES:
        raise SupportBundleError(
            f"bundle size must be between 1 and {MAX_SUPPORT_BUNDLE_BYTES} bytes"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as bundle_file:
            opened_metadata = os.fstat(bundle_file.fileno())
            if not stat.S_ISREG(opened_metadata.st_mode):
                raise SupportBundleError("bundle must remain a regular file while read")
            encoded = bundle_file.read(MAX_SUPPORT_BUNDLE_BYTES + 1)
        if not encoded or len(encoded) > MAX_SUPPORT_BUNDLE_BYTES:
            raise SupportBundleError(
                f"bundle size must be between 1 and {MAX_SUPPORT_BUNDLE_BYTES} bytes"
            )
        document = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except OSError as error:
        raise SupportBundleError(f"bundle could not be read: {error}") from error
    except RecursionError as error:
        raise SupportBundleError("bundle JSON nesting is too deep") from error
    except UnicodeDecodeError as error:
        raise SupportBundleError("bundle must be UTF-8 JSON") from error
    except json.JSONDecodeError as error:
        raise SupportBundleError(f"bundle is not valid JSON: {error.msg}") from error
    if not isinstance(document, dict):
        raise SupportBundleError("bundle root must be a JSON object")
    validate_support_bundle(document)
    return document


def validate_support_bundle(document: dict[str, Any]) -> None:
    _reject_forbidden_content_fields(document)
    _require_exact_keys(document, TOP_LEVEL_KEYS, "bundle")
    _require_equal(document, "formatVersion", SUPPORT_BUNDLE_FORMAT_VERSION, "bundle")
    _require_equal(document, "policyVersion", SUPPORT_BUNDLE_POLICY_VERSION, "bundle")
    _require_positive_integer(document, "generatedAtUnixMs", "bundle")
    _require_non_negative_integer(document, "redactionCount", "bundle")

    product = _require_object(document, "product", "bundle")
    _require_exact_keys(product, PRODUCT_KEYS, "product")
    _require_equal(product, "name", "CodeIsCheap", "product")
    for key in ("version", "desktopApiVersion", "platform", "architecture"):
        _require_text(product, key, "product", maximum=128)

    privacy = _require_object(document, "privacy", "bundle")
    _require_exact_keys(privacy, PRIVACY_KEYS, "privacy")
    for key in PRIVACY_KEYS:
        _require_boolean(privacy, key, "privacy")
    for key in (
        "requestContentIncluded",
        "requestIdentifiersIncluded",
        "rawCaptureIncluded",
        "logDetailsIncluded",
    ):
        _require_equal(privacy, key, False, "privacy")

    diagnostics = _require_object(document, "diagnostics", "bundle")
    _require_exact_keys(diagnostics, DIAGNOSTIC_KEYS, "diagnostics")
    source = _require_choice(
        diagnostics,
        "source",
        {"synthetic_fixture", "encrypted_local", "recovery_backup"},
        "diagnostics",
    )
    runtime_issue = diagnostics.get("runtimeIssue")
    if runtime_issue is not None:
        _require_text(diagnostics, "runtimeIssue", "diagnostics")

    capture = _require_object(diagnostics, "capture", "diagnostics")
    _require_exact_keys(capture, CAPTURE_KEYS, "diagnostics.capture")
    for key in ("active", "canControl", "proxyAvailable"):
        _require_boolean(capture, key, "diagnostics.capture")
    _require_choice(capture, "mode", {"gateway", "proxy"}, "diagnostics.capture")
    for key in ("endpoint", "profile", "storage"):
        _require_text(capture, key, "diagnostics.capture")
    _require_non_negative_integer(capture, "requestCount", "diagnostics.capture")

    certificate = _require_object(
        diagnostics, "certificateAuthority", "diagnostics"
    )
    _require_exact_keys(
        certificate, CERTIFICATE_KEYS, "diagnostics.certificateAuthority"
    )
    _require_choice(
        certificate,
        "state",
        {"missing", "ready", "invalid"},
        "diagnostics.certificateAuthority",
    )
    _require_choice(
        certificate,
        "trust",
        {"unchecked", "trusted", "not_trusted", "unsupported"},
        "diagnostics.certificateAuthority",
    )
    _require_choice(
        certificate,
        "privateMaterial",
        {"missing", "restricted", "unchecked", "insecure"},
        "diagnostics.certificateAuthority",
    )
    _require_boolean(
        certificate, "canManageTrust", "diagnostics.certificateAuthority"
    )
    fingerprint = certificate.get("fingerprintSha256")
    if fingerprint is not None:
        fingerprint = _require_text(
            certificate,
            "fingerprintSha256",
            "diagnostics.certificateAuthority",
            maximum=95,
        )
        if not re.fullmatch(r"[0-9A-Fa-f:]{64,95}", fingerprint):
            raise SupportBundleError("certificate fingerprint is invalid")

    health = _require_object(diagnostics, "health", "diagnostics")
    _require_exact_keys(health, HEALTH_KEYS, "diagnostics.health")
    for key in HEALTH_KEYS:
        _require_boolean(health, key, "diagnostics.health")

    compatibility = _require_object(diagnostics, "compatibility", "diagnostics")
    _require_exact_keys(
        compatibility, COMPATIBILITY_KEYS, "diagnostics.compatibility"
    )
    _require_choice(
        compatibility,
        "code",
        COMPATIBILITY_CODES,
        "diagnostics.compatibility",
    )
    _require_choice(
        compatibility,
        "status",
        {"ready", "attention", "blocked"},
        "diagnostics.compatibility",
    )
    _require_choice(
        compatibility,
        "confidence",
        {"high", "low"},
        "diagnostics.compatibility",
    )
    _require_choice(
        compatibility,
        "recommendedMode",
        {"gateway", "proxy"},
        "diagnostics.compatibility",
    )
    _require_choice(
        compatibility,
        "action",
        {"none", "resume_capture", "trust_certificate", "use_gateway"},
        "diagnostics.compatibility",
    )
    for key in ("title", "summary"):
        _require_text(compatibility, key, "diagnostics.compatibility")
    steps = _require_list(compatibility, "steps", "diagnostics.compatibility")
    if len(steps) > 16:
        raise SupportBundleError("compatibility steps exceed the supported limit")
    for index, step in enumerate(steps):
        context = f"diagnostics.compatibility.steps[{index}]"
        if not isinstance(step, dict):
            raise SupportBundleError(f"{context} must be an object")
        _require_exact_keys(step, COMPATIBILITY_STEP_KEYS, context)
        for key in ("id", "label", "detail"):
            _require_text(step, key, context)
        _require_choice(
            step, "status", {"pass", "attention", "blocked", "pending"}, context
        )

    events = _require_list(diagnostics, "diagnosticEvents", "diagnostics")
    if len(events) > MAX_DIAGNOSTIC_EVENTS:
        raise SupportBundleError("diagnostic event count exceeds the supported limit")
    for index, event in enumerate(events):
        context = f"diagnostics.diagnosticEvents[{index}]"
        if not isinstance(event, dict):
            raise SupportBundleError(f"{context} must be an object")
        _require_exact_keys(event, DIAGNOSTIC_EVENT_KEYS, context)
        _require_positive_integer(event, "occurredAtUnixMs", context)
        code = _require_text(event, "code", context, maximum=64)
        if not re.fullmatch(r"[a-z0-9_]+", code):
            raise SupportBundleError(f"{context}.code is invalid")
    if privacy["logsIncluded"] != bool(events):
        raise SupportBundleError(
            "privacy.logsIncluded must match the diagnostic event collection"
        )

    if source == "recovery_backup" and (
        capture["active"] or capture["canControl"]
    ):
        raise SupportBundleError("recovery bundles must report read-only capture state")

    _scan_credentials(document)


def summarize_support_bundle(document: dict[str, Any]) -> dict[str, Any]:
    validate_support_bundle(document)
    diagnostics = document["diagnostics"]
    compatibility = diagnostics["compatibility"]
    capture = diagnostics["capture"]
    return {
        "formatVersion": document["formatVersion"],
        "generatedAtUnixMs": document["generatedAtUnixMs"],
        "product": document["product"],
        "source": diagnostics["source"],
        "compatibility": {
            "code": compatibility["code"],
            "status": compatibility["status"],
            "confidence": compatibility["confidence"],
            "action": compatibility["action"],
        },
        "capture": {
            "mode": capture["mode"],
            "active": capture["active"],
            "canControl": capture["canControl"],
            "proxyAvailable": capture["proxyAvailable"],
            "requestCount": capture["requestCount"],
        },
        "health": diagnostics["health"],
        "diagnosticEvents": diagnostics["diagnosticEvents"],
        "redactionCount": document["redactionCount"],
    }


def format_summary(summary: dict[str, Any]) -> str:
    product = summary["product"]
    compatibility = summary["compatibility"]
    capture = summary["capture"]
    health = summary["health"]
    event_codes = [event["code"] for event in summary["diagnosticEvents"]]
    lines = [
        f"CodeIsCheap {product['version']} on {product['platform']}/{product['architecture']}",
        f"Source: {summary['source']}",
        (
            "Compatibility: "
            f"{compatibility['status']} / {compatibility['code']} "
            f"({compatibility['confidence']} confidence, action={compatibility['action']})"
        ),
        (
            f"Capture: mode={capture['mode']}, active={str(capture['active']).lower()}, "
            f"controllable={str(capture['canControl']).lower()}, "
            f"proxyBundle={str(capture['proxyAvailable']).lower()}, "
            f"storedRequests={capture['requestCount']}"
        ),
        "Health: "
        + ", ".join(
            f"{key}={str(value).lower()}" for key, value in sorted(health.items())
        ),
        "Diagnostic events: " + (", ".join(event_codes) if event_codes else "none"),
        f"Redactions applied before intake: {summary['redactionCount']}",
    ]
    return "\n".join(lines)


def _require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unknown {', '.join(extra)}")
        raise SupportBundleError(f"{context} fields are invalid: {'; '.join(details)}")


def _require_object(value: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    result = value.get(key)
    if not isinstance(result, dict):
        raise SupportBundleError(f"{context}.{key} must be an object")
    return result


def _require_list(value: dict[str, Any], key: str, context: str) -> list[Any]:
    result = value.get(key)
    if not isinstance(result, list):
        raise SupportBundleError(f"{context}.{key} must be an array")
    return result


def _require_text(
    value: dict[str, Any],
    key: str,
    context: str,
    *,
    maximum: int = MAX_TEXT_LENGTH,
) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result or len(result) > maximum:
        raise SupportBundleError(
            f"{context}.{key} must be a non-empty string of at most {maximum} characters"
        )
    return result


def _require_boolean(value: dict[str, Any], key: str, context: str) -> bool:
    result = value.get(key)
    if not isinstance(result, bool):
        raise SupportBundleError(f"{context}.{key} must be a boolean")
    return result


def _require_positive_integer(value: dict[str, Any], key: str, context: str) -> int:
    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
        raise SupportBundleError(f"{context}.{key} must be a positive integer")
    return result


def _require_non_negative_integer(
    value: dict[str, Any], key: str, context: str
) -> int:
    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise SupportBundleError(f"{context}.{key} must be a non-negative integer")
    return result


def _require_choice(
    value: dict[str, Any],
    key: str,
    choices: set[str],
    context: str,
) -> str:
    result = value.get(key)
    if not isinstance(result, str) or result not in choices:
        raise SupportBundleError(f"{context}.{key} is unsupported")
    return result


def _require_equal(
    value: dict[str, Any], key: str, expected: Any, context: str
) -> None:
    if value.get(key) != expected:
        raise SupportBundleError(f"{context}.{key} must equal {expected!r}")


def _normalize_field_name(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _reject_forbidden_content_fields(value: Any, pointer: str = "") -> None:
    for child_pointer, child, key in _walk_document(value, pointer):
        if key is not None:
            if _normalize_field_name(key) in FORBIDDEN_CONTENT_KEYS:
                raise SupportBundleError(
                    f"request content field is forbidden in support bundles: {child_pointer}"
                )


@lru_cache(maxsize=1)
def _credential_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    corpus = json.loads(CREDENTIAL_CORPUS_PATH.read_text(encoding="utf-8"))
    if corpus.get("version") != SUPPORT_BUNDLE_POLICY_VERSION:
        raise SupportBundleError("credential corpus version is unsupported")
    return tuple(
        (entry["category"], re.compile(entry["expression"]))
        for entry in corpus["text_patterns"]
    )


def _scan_credentials(value: Any, pointer: str = "") -> None:
    for child_pointer, child, _ in _walk_document(value, pointer):
        if isinstance(child, str):
            for category, pattern in _credential_patterns():
                if not pattern.search(child):
                    continue
                raise SupportBundleError(
                    f"credential pattern {category} detected at {child_pointer or '/'}"
                )


def _walk_document(
    value: Any, pointer: str = ""
) -> list[tuple[str, Any, str | None]]:
    result: list[tuple[str, Any, str | None]] = []
    stack: list[tuple[str, Any, str | None]] = [(pointer, value, None)]
    while stack:
        child_pointer, child, key = stack.pop()
        result.append((child_pointer, child, key))
        if len(result) > MAX_DOCUMENT_NODES:
            raise SupportBundleError("bundle contains too many JSON values")
        if isinstance(child, dict):
            for child_key, nested in reversed(tuple(child.items())):
                stack.append((f"{child_pointer}/{child_key}", nested, child_key))
        elif isinstance(child, list):
            for index in range(len(child) - 1, -1, -1):
                stack.append((f"{child_pointer}/{index}", child[index], None))
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and summarize a CodeIsCheap support bundle without exposing request content."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="reject unsafe or incompatible bundles")
    validate.add_argument("bundle", type=Path)
    summarize = subparsers.add_parser(
        "summarize", help="emit a content-free triage summary"
    )
    summarize.add_argument("bundle", type=Path)
    summarize.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        document = load_support_bundle(arguments.bundle)
        if arguments.command == "validate":
            print("support bundle is valid")
        else:
            summary = summarize_support_bundle(document)
            if arguments.json:
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print(format_summary(summary))
    except (OSError, SupportBundleError) as error:
        print(f"support bundle rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
