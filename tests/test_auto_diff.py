import unittest

from cve_scraper.auto_state import diff_finds


class AutoDiffTests(unittest.TestCase):
    def test_diff_finds_reports_only_new_cves(self):
        previous = {
            "mariadb11.8": {"11.8.6": ["CVE-2026-35549"]},
        }
        current = {
            "mariadb11.8": {
                "11.8.6": ["CVE-2026-35549", "CVE-2026-32710"],
                "unknown": ["CVE-2025-13699"],
            },
        }
        new_finds = diff_finds(current, previous)
        self.assertEqual(new_finds["mariadb11.8"]["11.8.6"], ["CVE-2026-32710"])
        self.assertEqual(new_finds["mariadb11.8"]["unknown"], ["CVE-2025-13699"])

    def test_diff_finds_empty_when_unchanged(self):
        finds = {"libarchive": {"3.7.7": ["CVE-2025-25724"]}}
        self.assertEqual(diff_finds(finds, finds), {})


if __name__ == "__main__":
    unittest.main()
