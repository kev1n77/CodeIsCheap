"""Validate a packaged sidecar bundle before bundling or release."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from package_sidecar import signature_info


MANIFEST_FILENAME = "sidecar-manifest.json"
EXPECTED_SCHEMA_VERSION = "0.1"
EXPECTED_CAPTURE_CONTRACT = {
    "ipc_protocol": "0.3",
    "envelope": "0.1",
    "policy": "0.1",
}
EXPECTED_ENVIRONMENT = {
    "CIC_CAPTURE_HOSTS",
    "CIC_CAPTURE_IPC_ADDR",
    "CIC_CAPTURE_IPC_TOKEN",
    "CIC_CAPTURE_POLICY_PATH",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_path(bundle: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("bundle file name must stay in the bundle directory")
    return bundle / name


def validate_bundle(bundle: Path, require_signature: bool = False) -> dict[str, Any]:
    manifest = json.loads((bundle / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        raise ValueError("sidecar manifest schema version is unsupported")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise ValueError("sidecar artifact metadata is missing")
    executable = bundle_path(bundle, artifact.get("file"))
    if not executable.is_file():
        raise ValueError("sidecar executable is missing")
    if executable.stat().st_size != artifact.get("bytes"):
        raise ValueError("sidecar executable size does not match the manifest")
    if executable.stat().st_size > artifact.get("max_bytes", 0):
        raise ValueError("sidecar executable exceeds the size limit")
    if sha256_file(executable) != artifact.get("sha256"):
        raise ValueError("sidecar executable hash does not match the manifest")

    contract = manifest.get("capture_contract")
    if not isinstance(contract, dict):
        raise ValueError("sidecar capture contract is missing")
    if any(
        contract.get(field) != version
        for field, version in EXPECTED_CAPTURE_CONTRACT.items()
    ):
        raise ValueError("sidecar capture contract version is unsupported")
    if set(contract.get("allowed_environment", [])) != EXPECTED_ENVIRONMENT:
        raise ValueError("sidecar environment contract is broader than expected")
    policy = bundle_path(bundle, contract.get("policy_file"))
    if sha256_file(policy) != contract.get("policy_sha256"):
        raise ValueError("capture policy hash does not match the manifest")

    sbom = manifest.get("sbom")
    if not isinstance(sbom, dict):
        raise ValueError("sidecar SBOM metadata is missing")
    sbom_path = bundle_path(bundle, sbom.get("file"))
    if sha256_file(sbom_path) != sbom.get("sha256"):
        raise ValueError("sidecar SBOM hash does not match the manifest")
    sbom_content = json.loads(sbom_path.read_text(encoding="utf-8"))
    if sbom_content.get("bomFormat") != "CycloneDX" or not sbom_content.get("components"):
        raise ValueError("sidecar SBOM is incomplete")

    probe = manifest.get("integration_probe")
    if not isinstance(probe, dict) or not all(
        probe.get(field)
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
    ):
        raise ValueError("sidecar integration probe did not pass")
    if probe.get("credential_canaries_in_envelope") != 0:
        raise ValueError("sidecar integration probe found credential canaries")
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        raise ValueError("sidecar signature metadata is missing")
    observed_signature = signature_info(executable)
    for field in ("scheme", "status", "identity", "thumbprint"):
        if signature.get(field) != observed_signature.get(field):
            raise ValueError("sidecar platform signature does not match the manifest")
    if require_signature and observed_signature.get("status") != "valid":
        raise ValueError("sidecar release requires a valid platform signature")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    arguments = parser.parse_args()
    try:
        manifest = validate_bundle(arguments.bundle, arguments.require_signature)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(
        json.dumps(
            {
                "valid": True,
                "artifact": manifest["artifact"]["file"],
                "target_triple": manifest["target_triple"],
                "signature": manifest["signature"]["status"],
            }
        )
    )


if __name__ == "__main__":
    main()
