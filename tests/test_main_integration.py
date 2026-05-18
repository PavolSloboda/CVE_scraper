import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cve_scraper.auto_run import run_automatic_report
from cve_scraper.auto_state import load_auto_state
from cve_scraper.git_ops import filter_files_to_git_changes
from cve_scraper.main import _display_label_for_component, _process_cve_files
from cve_scraper.paths import expand_path
from support import write_mini_cve_repo


class MainIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.git_root = self.root / "git"
        self.git_root.mkdir()
        self.paths = write_mini_cve_repo(self.git_root)
        self.components_path = self.root / "our_components"
        self.components_path.write_text("mariadb11.8\nlibarchive\n", encoding="utf-8")
        self.state_path = self.root / "auto_state.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_process_cve_files_multiple_components(self):
        files = [
            str(self.paths["cve_mariadb_less_than.json"]),
            str(self.paths["cve_libarchive.json"]),
        ]
        matches = _process_cve_files(files, ["mariadb11.8", "libarchive"])
        self.assertEqual(matches["mariadb11.8"][0].cve_id, "CVE-TEST-0001")
        self.assertEqual(matches["libarchive"][0].cve_id, "CVE-TEST-0004")

    @patch("cve_scraper.auto_run.send_notification")
    def test_automatic_pipeline_no_stdout(self, _mock_notify):
        files = [
            str(self.paths["cve_mariadb_less_than.json"]),
            str(self.paths["cve_libarchive.json"]),
        ]
        matches = _process_cve_files(files, ["mariadb11.8", "libarchive"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_automatic_report(
                git_location=expand_path(self.git_root),
                components=["mariadb11.8", "libarchive"],
                matches=matches,
                heading_for_component=_display_label_for_component,
                diff_file="last.diff",
                keep_diff=False,
                state_path=self.state_path,
                head_revision="rev1",
            )
        self.assertEqual(buf.getvalue(), "")
        self.assertTrue((self.git_root / "last.diff").exists())
        state = load_auto_state(self.state_path)
        self.assertIn("mariadb11.8", state["last_finds"])

    def test_git_change_filter_limits_files(self):
        candidates = list(map(str, self.paths.values()))
        only_one = [str(self.paths["cve_mariadb_less_than.json"])]
        filtered = filter_files_to_git_changes(candidates, only_one)
        self.assertEqual(filtered, only_one)

    def test_cli_manual_requires_package(self):
        repo_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(repo_root / "scrape.py"), "-n", "-g", str(self.git_root)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("package", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
