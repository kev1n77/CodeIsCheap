"""Prepare and verify a signed CodeIsCheap desktop release directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib
from typing import Any
from urllib.parse import quote, unquote


PLATFORM_DIRECTORY_PREFIX = "release-"
SUPPORTED_PLATFORMS = {
    "windows-x86_64": (".nsis.zip", ".msi.zip"),
    "darwin-x86_64": (".app.tar.gz", ".app.tar"),
    "darwin-aarch64": (".app.tar.gz", ".app.tar"),
}
TAG_PATTERN = re.compile(
    r"v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\Z"
)


class ReleaseError(ValueError):
    """Raised when release inputs are incomplete or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_version(repository: Path) -> str:
    tauri = json.loads(
        (repository / "apps/desktop/src-tauri/tauri.conf.json").read_text(
            encoding="utf-8"
        )
    )["version"]
    package = json.loads(
        (repository / "apps/desktop/package.json").read_text(encoding="utf-8")
    )["version"]
    with (repository / "apps/desktop/src-tauri/Cargo.toml").open("rb") as source:
        cargo = tomllib.load(source)["package"]["version"]
    versions = {str(tauri), str(package), str(cargo)}
    if len(versions) != 1:
        raise ReleaseError(
            "desktop versions disagree across tauri.conf.json, package.json, and Cargo.toml"
        )
    return versions.pop()


def validate_tag(repository: Path, tag: str) -> str:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseError("release tag must be a canonical v<semver> tag")
    version = match.group("version")
    expected = repository_version(repository)
    if version != expected:
        raise ReleaseError(f"release tag {tag} does not match desktop version {expected}")
    return version


def _safe_file(path: Path, root: Path) -> Path:
    resolved = path.resolve(strict=True)
    root = root.resolve(strict=True)
    if resolved.parent != root or path.is_symlink() or not path.is_file():
        raise ReleaseError(f"release artifact must be a regular direct child: {path}")
    return resolved


def _platform_directories(release_input: Path) -> dict[str, Path]:
    platforms: dict[str, Path] = {}
    for directory in sorted(release_input.iterdir()):
        if not directory.is_dir() or not directory.name.startswith(PLATFORM_DIRECTORY_PREFIX):
            continue
        platform = directory.name.removeprefix(PLATFORM_DIRECTORY_PREFIX)
        if platform not in SUPPORTED_PLATFORMS:
            raise ReleaseError(f"unsupported release platform directory: {directory.name}")
        if platform in platforms:
            raise ReleaseError(f"duplicate release platform: {platform}")
        platforms[platform] = directory
    if "windows-x86_64" not in platforms:
        raise ReleaseError("Windows x86_64 release artifacts are required")
    if not ({"darwin-x86_64", "darwin-aarch64"} & platforms.keys()):
        raise ReleaseError("at least one macOS release artifact is required")
    return platforms


def _updater_pair(platform: str, directory: Path) -> tuple[Path, Path]:
    suffixes = SUPPORTED_PLATFORMS[platform]
    pairs: list[tuple[Path, Path]] = []
    for candidate in sorted(directory.iterdir()):
        if not candidate.is_file() or candidate.name.endswith(".sig"):
            continue
        if not any(candidate.name.endswith(suffix) for suffix in suffixes):
            continue
        signature = candidate.with_name(f"{candidate.name}.sig")
        if signature.is_file():
            pairs.append(
                (_safe_file(candidate, directory), _safe_file(signature, directory))
            )
    if len(pairs) != 1:
        raise ReleaseError(
            f"{platform} must contain exactly one updater artifact with an adjacent .sig file"
        )
    signature = pairs[0][1].read_text(encoding="utf-8").strip()
    if len(signature) < 32 or "\x00" in signature:
        raise ReleaseError(f"{platform} updater signature is invalid")
    return pairs[0]


def _copy_artifacts(platforms: dict[str, Path], output: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for platform, directory in platforms.items():
        for source in sorted(directory.iterdir()):
            if not source.is_file():
                continue
            source = _safe_file(source, directory)
            if source.name in names:
                raise ReleaseError(f"duplicate release artifact filename: {source.name}")
            names.add(source.name)
            destination = output / source.name
            shutil.copy2(source, destination)
            if destination.stat().st_size == 0:
                raise ReleaseError(f"release artifact is empty: {destination.name}")
            records.append(
                {
                    "platform": platform,
                    "file": destination.name,
                    "bytes": destination.stat().st_size,
                    "sha256": sha256_file(destination),
                }
            )
    return records


def prepare_release(
    repository_root: Path,
    release_input: Path,
    output: Path,
    tag: str,
    github_repository: str,
    pub_date: str,
    notes: str,
) -> dict[str, Any]:
    version = validate_tag(repository_root, tag)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", github_repository):
        raise ReleaseError("GitHub repository must use owner/name syntax")
    if not pub_date or "T" not in pub_date:
        raise ReleaseError("release publication date must be an ISO-8601 timestamp")
    platforms = _platform_directories(release_input)
    updater_pairs = {
        platform: _updater_pair(platform, directory)
        for platform, directory in platforms.items()
    }

    if output.exists():
        if output.is_symlink() or not output.is_dir():
            raise ReleaseError("release output must be a normal directory")
        if any(output.iterdir()):
            raise ReleaseError("release output directory must be empty")
    else:
        output.mkdir(parents=True)

    artifacts = _copy_artifacts(platforms, output)
    base_url = f"https://github.com/{github_repository}/releases/download/{tag}"
    latest_platforms: dict[str, dict[str, str]] = {}
    for platform, (artifact, signature) in updater_pairs.items():
        latest_platforms[platform] = {
            "signature": signature.read_text(encoding="utf-8").strip(),
            "url": f"{base_url}/{quote(artifact.name)}",
        }
    latest = {
        "version": version,
        "notes": notes.strip(),
        "pub_date": pub_date,
        "platforms": latest_platforms,
    }
    latest_path = output / "latest.json"
    latest_path.write_text(json.dumps(latest, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schemaVersion": "0.1",
        "tag": tag,
        "version": version,
        "repository": github_repository,
        "artifacts": artifacts,
        "updaters": {
            platform: {
                "artifact": artifact.name,
                "signatureFile": signature.name,
            }
            for platform, (artifact, signature) in updater_pairs.items()
        },
        "latestJson": {
            "file": latest_path.name,
            "bytes": latest_path.stat().st_size,
            "sha256": sha256_file(latest_path),
        },
    }
    manifest_path = output / "release-manifest.v0.1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    verify_release(output)
    return manifest


def verify_release(output: Path) -> dict[str, Any]:
    manifest_path = output / "release-manifest.v0.1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != "0.1":
        raise ReleaseError("release manifest schema is unsupported")
    expected_names = {"release-manifest.v0.1.json", "latest.json"}
    for record in manifest.get("artifacts", []):
        if not isinstance(record, dict) or not isinstance(record.get("file"), str):
            raise ReleaseError("release manifest artifact record is invalid")
        path = _safe_file(output / record["file"], output)
        expected_names.add(path.name)
        if path.stat().st_size != record.get("bytes") or sha256_file(path) != record.get(
            "sha256"
        ):
            raise ReleaseError(f"release artifact integrity failed: {path.name}")
    latest_record = manifest.get("latestJson", {})
    latest_path = _safe_file(output / "latest.json", output)
    if latest_path.stat().st_size != latest_record.get("bytes") or sha256_file(
        latest_path
    ) != latest_record.get("sha256"):
        raise ReleaseError("latest.json integrity failed")
    latest = json.loads(latest_path.read_text(encoding="utf-8"))
    if latest.get("version") != manifest.get("version"):
        raise ReleaseError("latest.json version does not match the release manifest")
    expected_updaters = manifest.get("updaters", {})
    if set(latest.get("platforms", {})) != set(expected_updaters):
        raise ReleaseError("latest.json platform set does not match the release manifest")
    for platform, update in latest.get("platforms", {}).items():
        if platform not in SUPPORTED_PLATFORMS or not isinstance(update, dict):
            raise ReleaseError("latest.json contains an unsupported platform")
        filename = unquote(str(update.get("url", "")).rsplit("/", 1)[-1])
        updater = expected_updaters.get(platform, {})
        if (
            filename != updater.get("artifact")
            or filename not in expected_names
            or len(str(update.get("signature", ""))) < 32
        ):
            raise ReleaseError(f"latest.json updater entry is invalid: {platform}")
        signature_file = f"{filename}.sig"
        if (
            updater.get("signatureFile") != signature_file
            or signature_file not in expected_names
            or _safe_file(output / signature_file, output)
            .read_text(encoding="utf-8")
            .strip()
            != update.get("signature")
        ):
            raise ReleaseError(f"latest.json updater signature is invalid: {platform}")
    actual_names = {path.name for path in output.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise ReleaseError("release directory contains untracked or missing files")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    check = subcommands.add_parser("check-version")
    check.add_argument("--repository-root", type=Path, default=Path.cwd())
    check.add_argument("--tag", required=True)
    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--repository-root", type=Path, default=Path.cwd())
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--github-repository", required=True)
    prepare.add_argument("--pub-date", required=True)
    prepare.add_argument("--notes-file", type=Path, required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    if arguments.command == "check-version":
        print(validate_tag(arguments.repository_root, arguments.tag))
    elif arguments.command == "prepare":
        manifest = prepare_release(
            arguments.repository_root,
            arguments.input,
            arguments.output,
            arguments.tag,
            arguments.github_repository,
            arguments.pub_date,
            arguments.notes_file.read_text(encoding="utf-8"),
        )
        print(json.dumps(manifest, indent=2))
    else:
        print(json.dumps(verify_release(arguments.output), indent=2))


if __name__ == "__main__":
    main()
