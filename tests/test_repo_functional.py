import tempfile
import unittest
from pathlib import Path

from cve_scraper.repo import get_files_with_match, read_repo
from support import write_mini_cve_repo


class RepoFunctionalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.tmp.name) / "git"
        self.repo_root.mkdir()
        write_mini_cve_repo(self.repo_root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_grep_finds_mariadb_files(self):
        year_dir = self.repo_root / "cves" / "2026"
        files = list(get_files_with_match(str(year_dir), ["mariadb"]))
        basenames = {Path(path).name for path in files}
        self.assertIn("CVE-TEST-0001.json", basenames)
        self.assertIn("CVE-TEST-0002.json", basenames)
        self.assertNotIn("CVE-TEST-9999.json", basenames)

    def test_grep_no_match_returns_empty(self):
        year_dir = self.repo_root / "cves" / "2026"
        files = list(get_files_with_match(str(year_dir), ["nonexistentpkg"]))
        self.assertEqual(files, [])

    def test_read_repo_year_filter(self):
        files = read_repo(str(self.repo_root), ["mariadb"], start_year=2026, end_year=2026)
        years = {Path(path).parts[-3] for path in files}
        self.assertEqual(years, {"2026"})

    def test_read_repo_union_multiple_packages(self):
        files = read_repo(str(self.repo_root), ["libarchive", "postgresql"])
        basenames = {Path(path).name for path in files}
        self.assertIn("CVE-TEST-0004.json", basenames)
        self.assertIn("CVE-TEST-0005.json", basenames)


if __name__ == "__main__":
    unittest.main()
