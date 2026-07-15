import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


SIDECAR_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SIDECAR_ROOT))

from package_sidecar import executable_name, signature_info, target_triple  # noqa: E402
from install_sidecar_bundle import install_bundle  # noqa: E402
from verify_sidecar_bundle import validate_bundle  # noqa: E402


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def write_bundle(bundle: Path) -> dict:
    executable = b"synthetic-sidecar"
    policy = b'{"version":"0.1"}\n'
    sbom = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "library", "name": "mitmproxy", "version": "12.2.3"}],
        }
    ).encode()
    (bundle / "sidecar.bin").write_bytes(executable)
    (bundle / "capture-policy.v0.1.json").write_bytes(policy)
    (bundle / "sidecar-sbom.cdx.json").write_bytes(sbom)
    manifest = {
        "schema_version": "0.1",
        "target_triple": "x86_64-unknown-linux-gnu",
        "artifact": {
            "file": "sidecar.bin",
            "bytes": len(executable),
            "sha256": sha256(executable),
            "max_bytes": 1024,
        },
        "capture_contract": {
            "ipc_protocol": "0.1",
            "envelope": "0.1",
            "policy": "0.1",
            "policy_file": "capture-policy.v0.1.json",
            "policy_sha256": sha256(policy),
            "allowed_environment": [
                "CIC_CAPTURE_HOSTS",
                "CIC_CAPTURE_IPC_ADDR",
                "CIC_CAPTURE_IPC_TOKEN",
                "CIC_CAPTURE_POLICY_PATH",
            ],
        },
        "sbom": {
            "file": "sidecar-sbom.cdx.json",
            "sha256": sha256(sbom),
        },
        "signature": signature_info(bundle / "sidecar.bin"),
        "integration_probe": {
            "started": True,
            "forwarding_preserved": True,
            "credential_canaries_in_envelope": 0,
            "prompt_preserved": True,
            "response_preserved": True,
            "compressed_response_preserved": True,
            "stream_credentials_removed": True,
            "non_target_tunnel": True,
        },
    }
    (bundle / "sidecar-manifest.json").write_text(json.dumps(manifest))
    return manifest


class PackagingTests(unittest.TestCase):
    def test_target_triples_match_tauri_sidecar_names(self) -> None:
        cases = [
            ("Windows", "AMD64", "x86_64-pc-windows-msvc", ".exe"),
            ("Darwin", "arm64", "aarch64-apple-darwin", ""),
            ("Linux", "x86_64", "x86_64-unknown-linux-gnu", ""),
        ]
        for system, machine, expected, suffix in cases:
            with self.subTest(system=system, machine=machine):
                triple = target_triple(system, machine)
                self.assertEqual(triple, expected)
                self.assertEqual(
                    executable_name(triple),
                    f"codeischeap-mitmproxy-{expected}{suffix}",
                )

    def test_bundle_validation_checks_hash_contract_and_signature_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            manifest = write_bundle(bundle)

            self.assertEqual(validate_bundle(bundle)["target_triple"], manifest["target_triple"])
            with self.assertRaisesRegex(ValueError, "valid platform signature"):
                validate_bundle(bundle, require_signature=True)

            manifest["signature"]["status"] = "valid"
            (bundle / "sidecar-manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "signature does not match"):
                validate_bundle(bundle)

            manifest["signature"] = signature_info(bundle / "sidecar.bin")
            (bundle / "sidecar-manifest.json").write_text(json.dumps(manifest))
            (bundle / "sidecar.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "size does not match"):
                validate_bundle(bundle)

    def test_installer_replaces_only_after_staged_bundle_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            manifest = write_bundle(bundle)
            destination = root / "resources" / "sidecar"
            destination.mkdir(parents=True)
            (destination / "old-file").write_text("old")
            (destination / ".gitkeep").write_text("")

            installed = install_bundle(bundle, destination)

            self.assertEqual(installed["artifact"]["file"], manifest["artifact"]["file"])
            self.assertFalse((destination / "old-file").exists())
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    "sidecar.bin",
                    "capture-policy.v0.1.json",
                    "sidecar-sbom.cdx.json",
                    "sidecar-manifest.json",
                    ".gitkeep",
                },
            )
            self.assertEqual(validate_bundle(destination)["artifact"], manifest["artifact"])


if __name__ == "__main__":
    unittest.main()
