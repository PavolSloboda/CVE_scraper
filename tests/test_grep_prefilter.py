import tempfile
import unittest
from pathlib import Path

from cve_scraper.repo import read_repo
from support import fixture_path


class GrepPrefilterTests(unittest.TestCase):
    def test_finds_mariadb_json_without_literal_component_line(self):
        # CVE JSON contains "MariaDB", not the our_components token mariadb11.8.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "git"
            target = root / "cves" / "2026" / "0xxx" / "CVE-TEST-0001.json"
            target.parent.mkdir(parents=True)
            target.write_text(
                fixture_path("cve_mariadb_less_than.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            files = read_repo(str(root), ["mariadb"], start_year=2026, end_year=2026)
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].endswith("CVE-TEST-0001.json"))

    def test_component_line_grep_uses_product_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "git"
            target = root / "cves" / "2026" / "0xxx" / "CVE-TEST-0001.json"
            target.parent.mkdir(parents=True)
            target.write_text(
                fixture_path("cve_mariadb_less_than.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            from cve_scraper.components import grep_products_from_lines

            products = grep_products_from_lines(["mariadb11.8"])
            self.assertEqual(products, ["mariadb"])
            files = read_repo(str(root), products)
            self.assertEqual(len(files), 1)


if __name__ == "__main__":
    unittest.main()
