from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib


TAG_PATTERN = re.compile(
    r"v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\Z"
)


class ReleaseVersionError(ValueError):
    pass


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
        raise ReleaseVersionError(
            "desktop versions disagree across tauri.conf.json, package.json, and Cargo.toml"
        )
    return versions.pop()


def validate_tag(repository: Path, tag: str) -> str:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseVersionError("release tag must be a canonical v<semver> tag")
    version = match.group("version")
    expected = repository_version(repository)
    if version != expected:
        raise ReleaseVersionError(
            f"release tag {tag} does not match desktop version {expected}"
        )
    return version
