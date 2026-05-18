import io
import unittest
from contextlib import redirect_stdout

from cve_scraper.output import (
    format_group_heading,
    format_new_finds_diff,
    print_manual_report,
)
from cve_scraper.parse import ParseResult
from cve_scraper.version_match import VersionMode


class OutputTests(unittest.TestCase):
    def test_format_group_heading(self):
        self.assertEqual(format_group_heading("mariadb", "11.8"), "mariadb (11.8):")
        self.assertEqual(format_group_heading("libarchive", "all"), "libarchive:")

    def test_format_new_finds_empty(self):
        text = format_new_finds_diff({}, lambda c: f"{c}:")
        self.assertIn("no new CVEs", text)

    def test_format_new_finds_grouped(self):
        new_finds = {"mariadb11.8": {"11.8.6": ["CVE-A", "CVE-B"]}}
        text = format_new_finds_diff(new_finds, lambda c: "mariadb (11.8):")
        self.assertIn("mariadb (11.8):", text)
        self.assertIn("11.8.6:", text)
        self.assertIn("CVE-A", text)

    def test_print_manual_stream_mode(self):
        results = [ParseResult("CVE-TEST-0001", ("11.8.6",))]
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_manual_report("mariadb (11.8):", results, VersionMode.STREAM)
        out = buf.getvalue()
        self.assertIn("11.8.6:", out)
        self.assertIn("CVE-TEST-0001", out)

    def test_print_manual_fix_mode_flat(self):
        results = [ParseResult("CVE-TEST-0001", ("11.8.6",))]
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_manual_report("mariadb (11.8.6):", results, VersionMode.FIX)
        out = buf.getvalue()
        self.assertIn("CVE-TEST-0001", out)
        self.assertNotIn("  11.8.6:", out)


if __name__ == "__main__":
    unittest.main()
