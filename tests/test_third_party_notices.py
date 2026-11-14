from __future__ import annotations

import unittest

from scripts.check_third_party_notices import (
    normalize_license_expression,
    parse_notice_crates,
)
from scripts.generate_third_party_notices import normalize_notice_text


class ThirdPartyNoticesTests(unittest.TestCase):
    def test_normalizes_cargo_tree_license_expressions(self) -> None:
        self.assertEqual(normalize_license_expression("MIT/Apache-2.0"), "MIT OR Apache-2.0")
        self.assertEqual(
            normalize_license_expression("Apache-2.0  /  MIT (*)"),
            "Apache-2.0 OR MIT",
        )
        self.assertEqual(
            normalize_license_expression("(MIT or Apache-2.0) and Unicode-3.0"),
            "(MIT OR Apache-2.0) AND Unicode-3.0",
        )

    def test_parses_normalized_crate_rows(self) -> None:
        text = """
<!-- BEGIN THIRD-PARTY CRATES -->
| Crate | Version | License expression | Source |
| --- | --- | --- | --- |
| example | 1.2.3 | MIT / Apache-2.0 | https://example.invalid |
<!-- END THIRD-PARTY CRATES -->
"""
        self.assertEqual(
            parse_notice_crates(text),
            {("example", "1.2.3", "MIT OR Apache-2.0")},
        )

    def test_normalizes_generated_notice_line_endings(self) -> None:
        self.assertEqual(normalize_notice_text("one  \r\ntwo\t\r\n\r\n"), "one\ntwo\n")


if __name__ == "__main__":
    unittest.main()
