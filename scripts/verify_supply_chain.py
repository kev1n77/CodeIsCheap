#!/usr/bin/env python3
"""Deterministic repository supply-chain policy checks."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any


ACTION_PATTERN = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
EXACT_NODE_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
EXACT_PYTHON_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;]+(?:\s*;\s*.+)?$"
)
EXACT_RUST_TOOLCHAIN = re.compile(r"^\d+\.\d+\.\d+$")
SENSITIVE_OWNER_PATHS = (
    "/.github/",
    "/apps/desktop/src-tauri/",
    "/crates/capture-ipc/",
    "/crates/capture-policy/",
    "/crates/proxy-recovery/",
    "/crates/sidecar-runtime/",
    "/crates/storage/",
    "/policies/",
    "/sidecars/",
)
DEPENDABOT_ECOSYSTEMS = {"cargo", "npm", "pip", "github-actions"}


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _check_actions(root: Path, violations: list[str]) -> None:
    workflows = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    if not workflows:
        violations.append(".github/workflows: at least one workflow is required")
        return
    for workflow in workflows:
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = ACTION_PATTERN.match(line)
            if match is None:
                continue
            action, revision = match.groups()
            if action.startswith("./"):
                continue
            if FULL_SHA.fullmatch(revision) is None:
                violations.append(
                    f"{_relative(root, workflow)}:{line_number}: action {action} must use a full commit SHA"
                )


def _check_node(root: Path, violations: list[str]) -> None:
    manifests = [root / "package.json", root / "apps" / "desktop" / "package.json"]
    for manifest in manifests:
        if not manifest.is_file():
            violations.append(f"{_relative(root, manifest)}: manifest is missing")
            continue
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, version in data.get(section, {}).items():
                if EXACT_NODE_VERSION.fullmatch(version) is None:
                    violations.append(
                        f"{_relative(root, manifest)}: {section}.{name} must use an exact version"
                    )

    lock_path = root / "package-lock.json"
    if not lock_path.is_file():
        violations.append("package-lock.json: npm lockfile is missing")
        return
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("lockfileVersion", 0) < 3:
        violations.append("package-lock.json: lockfileVersion must be at least 3")
    for name, package in lock.get("packages", {}).items():
        if package.get("link") is True:
            continue
        resolved = package.get("resolved")
        if resolved is None:
            continue
        if not resolved.startswith("https://"):
            violations.append(f"package-lock.json: {name or '<root>'} uses a non-HTTPS artifact")
        if not package.get("integrity"):
            violations.append(f"package-lock.json: {name or '<root>'} is missing integrity")


def _check_python(root: Path, violations: list[str]) -> None:
    directory = root / "sidecars" / "mitmproxy"
    requirements = sorted(directory.glob("requirements*.txt"))
    if not requirements:
        violations.append("sidecars/mitmproxy: pinned requirements are missing")
        return
    for path in requirements:
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r "):
                included = path.parent / line[3:].strip()
                if not included.is_file():
                    violations.append(
                        f"{_relative(root, path)}:{line_number}: included requirements file is missing"
                    )
                continue
            if EXACT_PYTHON_REQUIREMENT.fullmatch(line) is None:
                violations.append(
                    f"{_relative(root, path)}:{line_number}: requirement must use == with an exact version"
                )


def _walk_rust_dependencies(
    root: Path,
    manifest: Path,
    value: Any,
    location: str,
    violations: list[str],
) -> None:
    if isinstance(value, dict):
        if "git" in value:
            revision = value.get("rev")
            if not isinstance(revision, str) or FULL_SHA.fullmatch(revision) is None:
                violations.append(
                    f"{_relative(root, manifest)}:{location}: git dependency must pin a full rev SHA"
                )
            if "branch" in value or "tag" in value:
                violations.append(
                    f"{_relative(root, manifest)}:{location}: git dependency cannot use branch or tag"
                )
        for key, child in value.items():
            next_location = f"{location}.{key}" if location else key
            _walk_rust_dependencies(root, manifest, child, next_location, violations)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_rust_dependencies(root, manifest, child, f"{location}[{index}]", violations)


def _check_rust(root: Path, violations: list[str]) -> None:
    manifests = sorted(
        path
        for path in root.rglob("Cargo.toml")
        if "target" not in path.parts and "node_modules" not in path.parts
    )
    if not manifests:
        violations.append("Cargo.toml: Rust manifests are missing")
    for manifest in manifests:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        _walk_rust_dependencies(root, manifest, data, "", violations)

    for lock in (root / "Cargo.lock", root / "apps" / "desktop" / "src-tauri" / "Cargo.lock"):
        if not lock.is_file():
            violations.append(f"{_relative(root, lock)}: Cargo lockfile is missing")
            continue
        for line_number, line in enumerate(lock.read_text(encoding="utf-8").splitlines(), 1):
            if 'source = "git+' not in line:
                continue
            fragment = line.rsplit("#", 1)[-1].rstrip('"')
            if FULL_SHA.fullmatch(fragment) is None:
                violations.append(
                    f"{_relative(root, lock)}:{line_number}: git source must resolve to a full commit SHA"
                )

    toolchain_path = root / "rust-toolchain.toml"
    if not toolchain_path.is_file():
        violations.append("rust-toolchain.toml: pinned toolchain is missing")
    else:
        channel = tomllib.loads(toolchain_path.read_text(encoding="utf-8")).get("toolchain", {}).get(
            "channel"
        )
        if not isinstance(channel, str) or EXACT_RUST_TOOLCHAIN.fullmatch(channel) is None:
            violations.append("rust-toolchain.toml: channel must be an exact stable version")


def _check_repository_policy(root: Path, violations: list[str]) -> None:
    owners_path = root / ".github" / "CODEOWNERS"
    if not owners_path.is_file():
        violations.append(".github/CODEOWNERS: file is missing")
    else:
        owners = owners_path.read_text(encoding="utf-8")
        for path in SENSITIVE_OWNER_PATHS:
            if path not in owners:
                violations.append(f".github/CODEOWNERS: missing explicit owner for {path}")

    dependabot_path = root / ".github" / "dependabot.yml"
    if not dependabot_path.is_file():
        violations.append(".github/dependabot.yml: file is missing")
    else:
        content = dependabot_path.read_text(encoding="utf-8")
        present = set(re.findall(r"package-ecosystem:\s*([A-Za-z0-9_-]+)", content))
        missing = sorted(DEPENDABOT_ECOSYSTEMS - present)
        if missing:
            violations.append(
                ".github/dependabot.yml: missing ecosystems " + ", ".join(missing)
            )


def collect_violations(root: Path) -> list[str]:
    root = root.resolve()
    violations: list[str] = []
    _check_actions(root, violations)
    _check_node(root, violations)
    _check_python(root, violations)
    _check_rust(root, violations)
    _check_repository_policy(root, violations)
    return violations


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations = collect_violations(root)
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}", file=sys.stderr)
        return 1
    print("Supply chain policy verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
