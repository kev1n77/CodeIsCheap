from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from prepare_release import ReleaseError, prepare_release, validate_tag, verify_release


class ReleasePreparationTests(unittest.TestCase):
    def repository(self, root: Path, version: str = "1.2.3") -> Path:
        repository = root / "repository"
        (repository / "apps/desktop/src-tauri").mkdir(parents=True)
        (repository / "apps/desktop/src-tauri/tauri.conf.json").write_text(
            json.dumps({"version": version}), encoding="utf-8"
        )
        (repository / "apps/desktop/package.json").write_text(
            json.dumps({"version": version}), encoding="utf-8"
        )
        (repository / "apps/desktop/src-tauri/Cargo.toml").write_text(
            f'[package]\nname = "desktop"\nversion = "{version}"\n',
            encoding="utf-8",
        )
        return repository

    def release_input(self, root: Path) -> Path:
        release_input = root / "input"
        windows = release_input / "release-windows-x86_64"
        macos = release_input / "release-darwin-x86_64"
        windows.mkdir(parents=True, exist_ok=True)
        macos.mkdir(parents=True, exist_ok=True)
        (windows / "CodeIsCheap_1.2.3_x64-setup.exe").write_bytes(b"windows-installer")
        (windows / "CodeIsCheap_1.2.3_x64-setup.nsis.zip").write_bytes(
            b"windows-updater"
        )
        (windows / "CodeIsCheap_1.2.3_x64-setup.nsis.zip.sig").write_text(
            "w" * 64, encoding="utf-8"
        )
        (windows / "CodeIsCheap_1.2.3_x64_en-US.msi").write_bytes(b"windows-msi")
        (macos / "CodeIsCheap_aarch.app.tar.gz").write_bytes(b"macos-updater")
        (macos / "CodeIsCheap_aarch.app.tar.gz.sig").write_text(
            "m" * 64, encoding="utf-8"
        )
        (macos / "CodeIsCheap_1.2.3_x64.dmg").write_bytes(b"macos-dmg")
        return release_input

    def test_prepares_latest_json_and_integrity_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            manifest = prepare_release(
                self.repository(root),
                self.release_input(root),
                output,
                "v1.2.3",
                "example/CodeIsCheap",
                "2026-07-21T00:00:00Z",
                "Signed release",
            )

            self.assertEqual(manifest["version"], "1.2.3")
            latest = json.loads((output / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                set(latest["platforms"]), {"windows-x86_64", "darwin-x86_64"}
            )
            self.assertTrue(
                latest["platforms"]["windows-x86_64"]["url"].endswith(
                    "CodeIsCheap_1.2.3_x64-setup.nsis.zip"
                )
            )
            self.assertEqual(verify_release(output)["tag"], "v1.2.3")

    def test_rejects_version_mismatch_missing_signatures_and_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.repository(root)
            release_input = self.release_input(root)
            with self.assertRaises(ReleaseError):
                validate_tag(repository, "v1.2.4")
            (release_input / "release-darwin-x86_64/CodeIsCheap_aarch.app.tar.gz.sig").unlink()
            with self.assertRaises(ReleaseError):
                prepare_release(
                    repository,
                    release_input,
                    root / "missing-signature",
                    "v1.2.3",
                    "example/CodeIsCheap",
                    "2026-07-21T00:00:00Z",
                    "Release",
                )

            release_input = self.release_input(root)
            output = root / "output"
            prepare_release(
                repository,
                release_input,
                output,
                "v1.2.3",
                "example/CodeIsCheap",
                "2026-07-21T00:00:00Z",
                "Release",
            )
            updater = output / "CodeIsCheap_1.2.3_x64-setup.nsis.zip"
            updater.write_bytes(b"tampered")
            with self.assertRaises(ReleaseError):
                verify_release(output)


if __name__ == "__main__":
    unittest.main()
