"""Bundled mitmdump entrypoint that always loads the CodeIsCheap addon."""

from pathlib import Path
import sys

from mitmproxy.tools.main import mitmdump


def main() -> None:
    bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    addon = bundle_root / "codeischeap_addon.py"
    sys.argv[1:1] = ["--script", str(addon)]
    mitmdump()


if __name__ == "__main__":
    main()
