from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import unittest
from urllib.parse import unquote


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTATION_ROOT = REPOSITORY_ROOT / "docs"


class DocumentationParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: list[str] = []
        self.h1_count = 0
        self.main_count = 0
        self.nav_count = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id:
            self.ids.append(element_id)
        href = attributes.get("href")
        if tag == "a" and href:
            self.links.append(href)
        if tag == "h1":
            self.h1_count += 1
        elif tag == "main":
            self.main_count += 1
        elif tag == "nav":
            self.nav_count += 1


class DocumentationTests(unittest.TestCase):
    def test_pages_have_landmarks_unique_ids_and_valid_local_links(self) -> None:
        parsers: dict[str, DocumentationParser] = {}
        for path in sorted(DOCUMENTATION_ROOT.glob("*.html")):
            parser = DocumentationParser()
            parser.feed(path.read_text(encoding="utf-8"))
            parsers[path.name] = parser
            self.assertEqual(parser.h1_count, 1, path)
            self.assertEqual(parser.main_count, 1, path)
            self.assertEqual(parser.nav_count, 1, path)
            duplicate_ids = [
                element_id
                for element_id, count in Counter(parser.ids).items()
                if count > 1
            ]
            self.assertEqual(duplicate_ids, [], path)

        self.assertIn("support.html", parsers)
        for source_name, parser in parsers.items():
            for href in parser.links:
                if href.startswith(("http://", "https://", "mailto:")):
                    continue
                target, _, fragment = href.partition("#")
                target_name = unquote(target) if target else source_name
                target_path = DOCUMENTATION_ROOT / target_name
                self.assertTrue(target_path.is_file(), f"{source_name}: {href}")
                if fragment and target_name in parsers:
                    self.assertIn(
                        fragment,
                        parsers[target_name].ids,
                        f"{source_name}: {href}",
                    )


if __name__ == "__main__":
    unittest.main()
