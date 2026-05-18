import json
import unittest
from pathlib import Path

from cve_scraper.parse import cve_matches_query, parse_json
from cve_scraper.version_match import (
    build_manual_query,
    normalize_identifier,
    parse_component_name,
    parse_manual_version,
    parse_version_tuple,
)
from support import load_fixture

CVE_SAMPLE = Path("/home/psloboda/.CVE_scrape/git/cves/2026/35xxx/CVE-2026-35549.json")
CVE_RANGE_SAMPLE = Path(
    "/home/psloboda/.CVE_scrape/git/cves/2026/32xxx/CVE-2026-32710.json"
)


class VersionMatchTests(unittest.TestCase):
    def test_parse_component_name(self):
        self.assertEqual(parse_component_name("mariadb11.8").product, "mariadb")
        self.assertEqual(parse_component_name("mariadb11.8").stream, (11, 8))
        self.assertEqual(parse_component_name("libarchive").mode.value, "any")

    def test_manual_version_modes(self):
        self.assertEqual(parse_manual_version("all")[0].value, "any")
        self.assertEqual(parse_manual_version("11.8")[0].value, "stream")
        self.assertEqual(parse_manual_version("11.8.6")[0].value, "fix")

    def test_parse_version_tuple(self):
        self.assertEqual(parse_version_tuple("11.8.6"), (11, 8, 6))
        self.assertIsNone(parse_version_tuple("n/a"))
        self.assertIsNone(parse_version_tuple("all"))

    def test_normalize_identifier(self):
        self.assertEqual(normalize_identifier("MariaDB"), "mariadb")
        self.assertEqual(normalize_identifier("PostgreSQL"), "postgresql")

    def test_mariadb_less_than_fixture(self):
        data = load_fixture("cve_mariadb_less_than.json")
        self.assertTrue(cve_matches_query(data, build_manual_query("mariadb", "11.8.6")))
        self.assertTrue(cve_matches_query(data, build_manual_query("mariadb", "11.8")))
        self.assertFalse(cve_matches_query(data, build_manual_query("mariadb", "12.3")))
        stream_result = parse_json(data, "mariadb", "11.8")
        self.assertEqual(stream_result.cve_id, "CVE-TEST-0001")
        self.assertIn("11.8.6", stream_result.fix_versions)

    def test_mariadb_inline_range_fixture(self):
        data = load_fixture("cve_mariadb_inline_range.json")
        result = parse_json(data, "mariadb", "11.8")
        self.assertEqual(result.cve_id, "CVE-TEST-0002")
        self.assertIn("11.8.6", result.fix_versions)

    def test_optional_live_cve_repo_samples(self):
        if not CVE_SAMPLE.exists():
            self.skipTest("local CVE repo not present")
        data = json.loads(CVE_SAMPLE.read_text(encoding="utf-8"))
        self.assertTrue(cve_matches_query(data, parse_component_name("mariadb11.8")))
        if CVE_RANGE_SAMPLE.exists():
            data2 = json.loads(CVE_RANGE_SAMPLE.read_text(encoding="utf-8"))
            result = parse_json(data2, "mariadb", "11.8")
            self.assertIn("11.8.6", result.fix_versions)


if __name__ == "__main__":
    unittest.main()
