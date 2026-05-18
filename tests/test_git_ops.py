import tempfile
import unittest
from pathlib import Path

import git

from cve_scraper.git_ops import (
    filter_files_to_git_changes,
    get_changed_cve_files,
    get_head_revision,
)
from support import fixture_path


class GitOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.git_root = Path(self.tmp.name) / "git"
        self.git_root.mkdir()
        self.repo = git.Repo.init(self.git_root)
        cve_dir = self.git_root / "cves" / "2026" / "0xxx"
        cve_dir.mkdir(parents=True)
        self.cve_file = cve_dir / "CVE-TEST-0001.json"
        self.cve_file.write_text(
            fixture_path("cve_mariadb_less_than.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.repo.index.add([str(self.cve_file.relative_to(self.git_root))])
        self.repo.index.commit("initial")
        self.rev1 = self.repo.head.commit.hexsha

    def tearDown(self):
        self.tmp.cleanup()

    def test_head_revision(self):
        self.assertEqual(get_head_revision(str(self.git_root)), self.rev1)

    def test_first_run_none_means_all_candidates(self):
        self.assertIsNone(get_changed_cve_files(str(self.git_root), None))

    def test_same_revision_no_changes(self):
        self.assertEqual(get_changed_cve_files(str(self.git_root), self.rev1), [])

    def test_detects_modified_file(self):
        self.cve_file.write_text("{}", encoding="utf-8")
        self.repo.index.add([str(self.cve_file.relative_to(self.git_root))])
        self.repo.index.commit("update")
        changed = get_changed_cve_files(str(self.git_root), self.rev1)
        self.assertEqual(changed, [str(self.cve_file)])

    def test_filter_files_to_git_changes(self):
        candidates = ["/a.json", "/b.json"]
        changed = ["/a.json"]
        self.assertEqual(filter_files_to_git_changes(candidates, changed), ["/a.json"])
        self.assertEqual(filter_files_to_git_changes(candidates, None), candidates)


if __name__ == "__main__":
    unittest.main()
