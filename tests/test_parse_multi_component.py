import unittest

from cve_scraper.parse import match_components_in_record
from support import load_fixture


class MultiComponentParseTests(unittest.TestCase):
    def test_single_record_matches_multiple_components(self):
        data = load_fixture("cve_mariadb_less_than.json")
        results = match_components_in_record(data, ["mariadb11.8", "mariadb12.3"])
        self.assertIn("mariadb11.8", results)
        self.assertNotIn("mariadb12.3", results)
        self.assertEqual(results["mariadb11.8"].cve_id, "CVE-TEST-0001")


if __name__ == "__main__":
    unittest.main()
