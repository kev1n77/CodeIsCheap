"""Build and describe the pinned CodeIsCheap mitmproxy sidecar artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
NAME = "codeischeap-mitmproxy"
MAX_ACCEPTABLE_BYTES = 150 * 1024 * 1024


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    arguments = parser.parse_args()
    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    if not arguments.skip_build:
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            NAME,
            "--distpath",
            str(DIST),
            "--workpath",
            str(BUILD / "work"),
            "--specpath",
            str(BUILD),
            "--add-data",
            f"{ROOT / 'codeischeap_addon.py'}{';' if sys.platform == 'win32' else ':'}.",
            "--collect-all",
            "mitmproxy",
            "--collect-all",
            "mitmproxy_rs",
            str(ROOT / "entrypoint.py"),
        ]
        subprocess.run(command, check=True)

    executable = DIST / (f"{NAME}.exe" if sys.platform == "win32" else NAME)
    version = subprocess.run(
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    probe = subprocess.run(
        [sys.executable, str(ROOT / "verify_packaged_sidecar.py"), str(executable)],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    probe_result = json.loads(probe.stdout)
    artifact = executable.read_bytes()
    manifest = {
        "name": NAME,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "packaging": "pyinstaller-onefile",
        "bytes": len(artifact),
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "version_output": version,
        "integration_probe": probe_result,
        "signed": False,
        "acceptable_for_spike": len(artifact) <= MAX_ACCEPTABLE_BYTES,
        "max_acceptable_bytes": MAX_ACCEPTABLE_BYTES,
    }
    (DIST / "sidecar-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
