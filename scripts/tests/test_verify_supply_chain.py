from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from verify_supply_chain import collect_violations


PINNED_ACTION = "a" * 40


class SupplyChainPolicyTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(
            f"steps:\n  - uses: actions/checkout@{PINNED_ACTION}\n", encoding="utf-8"
        )
        (root / ".github" / "workflows" / "release.yml").write_text(
            """on:
  push:
    tags:
      - "v*"
environment: release
CODEISCHEAP_UPDATER_PUBLIC_KEY
TAURI_SIGNING_PRIVATE_KEY
WINDOWS_CERTIFICATE_BASE64
APPLE_CERTIFICATE_BASE64
--require-signature
Get-AuthenticodeSignature
xcrun stapler validate
scripts/prepare_release.py prepare
scripts/prepare_release.py verify
readiness_args=(--repository-root . --tag
if [[ "$RELEASE_VERSION" == *-* ]]
python scripts/verify_release_readiness.py "${readiness_args[@]}"
notes_file="release/notes/${RELEASE_TAG}.md"
release-readiness.v0.1.json
--draft
""",
            encoding="utf-8",
        )
        owners = "* @owner\n" + "\n".join(
            f"{path} @owner"
            for path in (
                "/.github/",
                "/apps/desktop/src-tauri/",
                "/crates/capture-ipc/",
                "/crates/capture-policy/",
                "/crates/proxy-recovery/",
                "/crates/sidecar-runtime/",
                "/crates/storage/",
                "/policies/",
                "/release/",
                "/sidecars/",
            )
        )
        (root / ".github" / "CODEOWNERS").write_text(owners, encoding="utf-8")
        (root / ".github" / "dependabot.yml").write_text(
            "\n".join(
                f"- package-ecosystem: {ecosystem}"
                for ecosystem in ("cargo", "npm", "pip", "github-actions")
            ),
            encoding="utf-8",
        )

        (root / "apps" / "desktop" / "src-tauri").mkdir(parents=True)
        (root / "apps" / "desktop" / "src-tauri" / "capabilities").mkdir()
        (root / "apps" / "desktop" / "src-tauri" / "capabilities" / "default.json").write_text(
            json.dumps(
                {
                    "identifier": "default",
                    "windows": ["main"],
                    "permissions": [
                        "core:event:allow-listen",
                        "core:event:allow-unlisten",
                        "dialog:allow-save",
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "apps" / "desktop" / "package.json").write_text(
            json.dumps({"dependencies": {"react": "19.2.7"}}), encoding="utf-8"
        )
        (root / "package.json").write_text(json.dumps({"private": True}), encoding="utf-8")
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {},
                        "node_modules/@codeischeap/desktop": {
                            "resolved": "apps/desktop",
                            "link": True,
                        },
                        "node_modules/react": {
                            "resolved": "https://registry.example/react.tgz",
                            "integrity": "sha512-synthetic",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        (root / "sidecars" / "mitmproxy").mkdir(parents=True)
        (root / "sidecars" / "mitmproxy" / "requirements.txt").write_text(
            "mitmproxy==12.2.3\n", encoding="utf-8"
        )
        (root / "sidecars" / "mitmproxy" / "requirements-build.txt").write_text(
            "-r requirements.txt\npyinstaller==6.21.0\n", encoding="utf-8"
        )

        (root / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (root / "apps" / "desktop" / "src-tauri" / "Cargo.lock").write_text(
            "version = 4\n", encoding="utf-8"
        )
        (root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.96.1"\n', encoding="utf-8"
        )

    def test_valid_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            self.assertEqual(collect_violations(root), [])

    def test_movable_and_unpinned_dependencies_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / ".github" / "workflows" / "ci.yml").write_text(
                "steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8"
            )
            (root / "apps" / "desktop" / "package.json").write_text(
                json.dumps({"dependencies": {"react": "^19.2.7"}}), encoding="utf-8"
            )
            (root / "sidecars" / "mitmproxy" / "requirements.txt").write_text(
                "mitmproxy>=12\n", encoding="utf-8"
            )
            (root / "Cargo.toml").write_text(
                '[package]\nname = "fixture"\nversion = "0.1.0"\n'
                '[dependencies]\nexample = { git = "https://example.invalid/repo" }\n',
                encoding="utf-8",
            )
            (root / ".github" / "workflows" / "release.yml").write_text(
                "on: workflow_dispatch\n", encoding="utf-8"
            )

            violations = "\n".join(collect_violations(root))
            self.assertIn("action actions/checkout must use a full commit SHA", violations)
            self.assertIn("dependencies.react must use an exact version", violations)
            self.assertIn("requirement must use ==", violations)
            self.assertIn("git dependency must pin a full rev SHA", violations)
            self.assertIn("must run from version tags", violations)

    def test_broad_or_remote_desktop_capabilities_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            capability = root / "apps" / "desktop" / "src-tauri" / "capabilities" / "default.json"
            capability.write_text(
                json.dumps(
                    {
                        "identifier": "default",
                        "windows": ["*"],
                        "local": False,
                        "remote": {"urls": ["https://example.test"]},
                        "permissions": ["core:default", "dialog:default"],
                    }
                ),
                encoding="utf-8",
            )

            violations = "\n".join(collect_violations(root))
            self.assertIn("only the main window may match", violations)
            self.assertIn("remote origins are forbidden", violations)
            self.assertIn("local app access is required", violations)
            self.assertIn("permissions must be limited", violations)


if __name__ == "__main__":
    unittest.main()
