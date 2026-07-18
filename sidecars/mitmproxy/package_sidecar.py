"""Build a versioned, auditable CodeIsCheap mitmproxy sidecar bundle."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
DIST = ROOT / "dist"
BUILD = ROOT / "build"
NAME = "codeischeap-mitmproxy"
MANIFEST_VERSION = "0.1"
MAX_ACCEPTABLE_BYTES = 150 * 1024 * 1024
POLICY_PATH = REPOSITORY / "policies" / "capture-policy.v0.1.json"
POLICY_FILENAME = POLICY_PATH.name
SBOM_FILENAME = "sidecar-sbom.cdx.json"
MANIFEST_FILENAME = "sidecar-manifest.json"
ALLOWED_ENVIRONMENT = [
    "CIC_CAPTURE_HOSTS",
    "CIC_CAPTURE_IPC_ADDR",
    "CIC_CAPTURE_IPC_TOKEN",
    "CIC_CAPTURE_POLICY_PATH",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def target_triple(system: str | None = None, machine: str | None = None) -> str:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(machine)
    if architecture is None:
        raise ValueError(f"unsupported sidecar architecture: {machine}")
    suffix = {
        "windows": "pc-windows-msvc",
        "darwin": "apple-darwin",
        "linux": "unknown-linux-gnu",
    }.get(system)
    if suffix is None:
        raise ValueError(f"unsupported sidecar operating system: {system}")
    return f"{architecture}-{suffix}"


def executable_name(triple: str) -> str:
    extension = ".exe" if triple.endswith("windows-msvc") else ""
    return f"{NAME}-{triple}{extension}"


def _project_version() -> str:
    config = json.loads(
        (REPOSITORY / "apps" / "desktop" / "src-tauri" / "tauri.conf.json").read_text(
            encoding="utf-8"
        )
    )
    return str(config["version"])


def _mitmproxy_version() -> str:
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("mitmproxy=="):
            return line.partition("==")[2]
    raise ValueError("mitmproxy must be pinned exactly")


def _runtime_components() -> list[dict[str, Any]]:
    distributions = {
        canonicalize_name(distribution.metadata["Name"]): distribution
        for distribution in metadata.distributions()
        if distribution.metadata.get("Name")
    }
    pending = ["mitmproxy"]
    visited: set[str] = set()
    components: list[dict[str, Any]] = []
    while pending:
        package = pending.pop()
        normalized = canonicalize_name(package)
        if normalized in visited:
            continue
        distribution = distributions.get(normalized)
        if distribution is None:
            raise ValueError(f"runtime dependency is not installed: {package}")
        visited.add(normalized)
        name = distribution.metadata["Name"]
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": distribution.version,
            "purl": f"pkg:pypi/{canonicalize_name(name)}@{distribution.version}",
        }
        license_name = distribution.metadata.get("License")
        if license_name and license_name.upper() != "UNKNOWN":
            component["licenses"] = [{"license": {"name": license_name}}]
        components.append(component)
        for requirement_text in distribution.requires or []:
            requirement = Requirement(requirement_text)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    return sorted(components, key=lambda item: (item["name"].lower(), item["version"]))


def build_sbom(artifact_name: str, artifact_hash: str, triple: str) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": NAME,
                "version": _project_version(),
                "hashes": [{"alg": "SHA-256", "content": artifact_hash}],
                "properties": [
                    {"name": "codeischeap:artifact", "value": artifact_name},
                    {"name": "codeischeap:target", "value": triple},
                ],
            }
        },
        "components": _runtime_components(),
    }


def signature_info(executable: Path) -> dict[str, Any]:
    system = platform.system().lower()
    if system == "windows":
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            raise RuntimeError("PowerShell is required to inspect Authenticode signatures")
        escaped = str(executable).replace("'", "''")
        command = (
            "$utf8 = [System.Text.UTF8Encoding]::new(); "
            "[Console]::OutputEncoding = $utf8; $OutputEncoding = $utf8; "
            f"Get-AuthenticodeSignature -LiteralPath '{escaped}' | "
            "Select-Object Status,@{n='Subject';e={$_.SignerCertificate.Subject}},"
            "@{n='Thumbprint';e={$_.SignerCertificate.Thumbprint}} | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        details = json.loads(result.stdout)
        valid = details.get("Status") == 0 or details.get("Status") == "Valid"
        return {
            "scheme": "authenticode",
            "status": "valid" if valid else "unsigned",
            "identity": details.get("Subject"),
            "thumbprint": details.get("Thumbprint"),
        }
    if system == "darwin":
        verify = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        details = subprocess.run(
            ["codesign", "-dvv", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        identity = next(
            (
                line.partition("=")[2]
                for line in details.stderr.splitlines()
                if line.startswith("Authority=")
            ),
            None,
        )
        ad_hoc = any(line.strip() == "Signature=adhoc" for line in details.stderr.splitlines())
        return {
            "scheme": "codesign",
            "status": "valid" if verify.returncode == 0 and not ad_hoc else "unsigned",
            "identity": identity,
            "thumbprint": None,
        }
    return {
        "scheme": "artifact-attestation",
        "status": "not_verified",
        "identity": None,
        "thumbprint": None,
    }


def _build_executable(triple: str) -> Path:
    raw_name = f"{NAME}.exe" if sys.platform == "win32" else NAME
    raw_executable = DIST / raw_name
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
        "--add-data",
        f"{POLICY_PATH}{';' if sys.platform == 'win32' else ':'}.",
        "--collect-all",
        "mitmproxy",
        "--collect-all",
        "mitmproxy_rs",
        str(ROOT / "entrypoint.py"),
    ]
    subprocess.run(command, check=True, stdout=sys.stderr)
    executable = DIST / executable_name(triple)
    if executable.exists():
        executable.unlink()
    raw_executable.replace(executable)
    return executable


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    arguments = parser.parse_args()
    triple = target_triple()
    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    executable = DIST / executable_name(triple)
    if not arguments.skip_build:
        executable = _build_executable(triple)
    if not executable.is_file():
        raise FileNotFoundError(f"packaged sidecar is missing: {executable}")

    shutil.copy2(POLICY_PATH, DIST / POLICY_FILENAME)
    version = subprocess.run(
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    probe = subprocess.run(
        [sys.executable, str(ROOT / "verify_packaged_sidecar.py"), str(executable)],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    if probe.returncode != 0:
        detail = probe.stderr.strip() or probe.stdout.strip() or "no probe output"
        raise RuntimeError(f"packaged sidecar integration probe failed: {detail}")
    probe_result = json.loads(probe.stdout)
    artifact_hash = sha256_file(executable)
    sbom_path = DIST / SBOM_FILENAME
    sbom_path.write_text(
        json.dumps(build_sbom(executable.name, artifact_hash, triple), indent=2) + "\n",
        encoding="utf-8",
    )
    signature = signature_info(executable)
    probe_passed = all(
        probe_result.get(field)
        for field in (
            "started",
            "forwarding_preserved",
            "prompt_preserved",
            "response_preserved",
            "compressed_response_preserved",
            "stream_credentials_removed",
            "non_target_tunnel",
            "http2_preserved",
            "transport_context_preserved",
        )
    ) and probe_result.get("credential_canaries_in_envelope") == 0
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "name": NAME,
        "version": _project_version(),
        "target_triple": triple,
        "python_version": platform.python_version(),
        "mitmproxy_version": _mitmproxy_version(),
        "packaging": "pyinstaller-onefile",
        "artifact": {
            "file": executable.name,
            "bytes": executable.stat().st_size,
            "sha256": artifact_hash,
            "max_bytes": MAX_ACCEPTABLE_BYTES,
        },
        "capture_contract": {
            "ipc_protocol": "0.3",
            "envelope": "0.1",
            "policy": "0.1",
            "policy_file": POLICY_FILENAME,
            "policy_sha256": sha256_file(DIST / POLICY_FILENAME),
            "allowed_environment": ALLOWED_ENVIRONMENT,
        },
        "sbom": {"file": SBOM_FILENAME, "sha256": sha256_file(sbom_path)},
        "signature": signature,
        "version_output": version,
        "integration_probe": probe_result,
        "bundle_ready": executable.stat().st_size <= MAX_ACCEPTABLE_BYTES and probe_passed,
        "release_ready": signature["status"] == "valid" and probe_passed,
    }
    manifest_path = DIST / MANIFEST_FILENAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    subprocess.run(
        [sys.executable, str(ROOT / "verify_sidecar_bundle.py"), str(DIST)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
