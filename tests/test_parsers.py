from __future__ import annotations

import unittest

from vina.parsers.tool_outputs import parse_urls, unique_lines


class ParserTests(unittest.TestCase):
    def test_unique_lines_preserves_order(self) -> None:
        self.assertEqual(unique_lines("a\na\nb\n"), ["a", "b"])

    def test_parse_urls(self) -> None:
        urls = parse_urls("see https://example.com/a and http://test.local/b")
        self.assertEqual(urls, ["https://example.com/a", "http://test.local/b"])


if __name__ == "__main__":
    unittest.main()
