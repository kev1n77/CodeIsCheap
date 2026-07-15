"""Atomically install a verified sidecar bundle into a Tauri resource directory."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any
import uuid

from verify_sidecar_bundle import MANIFEST_FILENAME, bundle_path, validate_bundle


def install_bundle(
    bundle: Path, destination: Path, require_signature: bool = False
) -> dict[str, Any]:
    manifest = validate_bundle(bundle, require_signature)
    destination = destination.resolve()
    parent = destination.parent
    if not destination.name:
        raise ValueError("sidecar destination must have a directory name")
    parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("sidecar destination must be a real directory")

    files = [
        manifest["artifact"]["file"],
        manifest["capture_contract"]["policy_file"],
        manifest["sbom"]["file"],
        MANIFEST_FILENAME,
    ]
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=parent)
    )
    backup: Path | None = None
    try:
        for name in files:
            source = bundle_path(bundle, name)
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"sidecar source file is invalid: {name}")
            shutil.copy2(source, staging / name)
        keep_file = destination / ".gitkeep"
        if keep_file.is_file() and not keep_file.is_symlink():
            shutil.copy2(keep_file, staging / keep_file.name)
        if os.name != "nt":
            (staging / manifest["artifact"]["file"]).chmod(0o755)
        validate_bundle(staging, require_signature)

        if destination.exists():
            backup = parent / f".{destination.name}.backup-{uuid.uuid4().hex}"
            destination.replace(backup)
        try:
            staging.replace(destination)
        except BaseException:
            if backup is not None and backup.exists() and not destination.exists():
                backup.replace(destination)
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    arguments = parser.parse_args()
    try:
        manifest = install_bundle(
            arguments.bundle, arguments.destination, arguments.require_signature
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        json.dumps(
            {
                "installed": True,
                "destination": str(arguments.destination.resolve()),
                "artifact": manifest["artifact"]["file"],
                "signature": manifest["signature"]["status"],
            }
        )
    )


if __name__ == "__main__":
    main()
