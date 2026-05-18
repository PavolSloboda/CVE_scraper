import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cve_scraper.auto_run import (
    archive_diff_file,
    resolve_diff_path,
    run_automatic_report,
)
from cve_scraper.auto_state import load_auto_state
from cve_scraper.parse import ParseResult


def _heading(component):
    if component == "mariadb11.8":
        return "mariadb (11.8):"
    return f"{component}:"


class AutoRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.git_loc = self.root / "git"
        self.git_loc.mkdir()
        self.state_path = self.root / "auto_state.json"

    def tearDown(self):
        self.tmp.cleanup()

    @patch("cve_scraper.auto_run.send_notification")
    def test_first_run_writes_diff_and_state(self, mock_notify):
        matches = {
            "mariadb11.8": [
                ParseResult("CVE-TEST-0001", ("11.8.6",)),
            ],
        }
        report = run_automatic_report(
            git_location=self.git_loc,
            components=["mariadb11.8"],
            matches=matches,
            heading_for_component=_heading,
            diff_file="last.diff",
            keep_diff=False,
            state_path=self.state_path,
            head_revision="rev1",
        )
        diff_text = (self.git_loc / "last.diff").read_text(encoding="utf-8")
        self.assertIn("CVE-TEST-0001", diff_text)
        self.assertIn("11.8.6:", diff_text)
        self.assertEqual(report, diff_text.strip())
        mock_notify.assert_called_once_with(report)

        state = load_auto_state(self.state_path)
        self.assertEqual(state["last_git_revision"], "rev1")
        self.assertEqual(state["last_finds"]["mariadb11.8"]["11.8.6"], ["CVE-TEST-0001"])

    @patch("cve_scraper.auto_run.send_notification")
    def test_second_run_only_new_cves_in_diff(self, mock_notify):
        save_matches = {
            "mariadb11.8": [ParseResult("CVE-TEST-0001", ("11.8.6",))],
        }
        with patch("cve_scraper.auto_run.send_notification"):
            run_automatic_report(
                git_location=self.git_loc,
                components=["mariadb11.8"],
                matches=save_matches,
                heading_for_component=_heading,
                diff_file="last.diff",
                keep_diff=False,
                state_path=self.state_path,
                head_revision="rev1",
            )

        matches = {
            "mariadb11.8": [
                ParseResult("CVE-TEST-0001", ("11.8.6",)),
                ParseResult("CVE-TEST-0002", ("11.8.6",)),
            ],
        }
        report = run_automatic_report(
            git_location=self.git_loc,
            components=["mariadb11.8"],
            matches=matches,
            heading_for_component=_heading,
            diff_file="last.diff",
            keep_diff=False,
            state_path=self.state_path,
            head_revision="rev2",
        )
        self.assertIn("CVE-TEST-0002", report)
        self.assertNotIn("CVE-TEST-0001", report)
        state = load_auto_state(self.state_path)
        self.assertEqual(len(state["last_finds"]["mariadb11.8"]["11.8.6"]), 2)

    @patch("cve_scraper.auto_run.send_notification")
    def test_no_new_cves_message(self, mock_notify):
        matches = {"mariadb11.8": [ParseResult("CVE-TEST-0001", ("11.8.6",))]}
        kwargs = dict(
            git_location=self.git_loc,
            components=["mariadb11.8"],
            matches=matches,
            heading_for_component=_heading,
            diff_file="last.diff",
            keep_diff=False,
            state_path=self.state_path,
            head_revision="rev1",
        )
        with patch("cve_scraper.auto_run.send_notification"):
            run_automatic_report(**kwargs)
        report = run_automatic_report(**{**kwargs, "head_revision": "rev2"})
        self.assertIn("no new CVEs", report)

    def test_keep_diff_archives_previous(self):
        diff_path = self.git_loc / "last.diff"
        diff_path.write_text("old report\n", encoding="utf-8")
        archive_diff_file(diff_path, self.git_loc)
        self.assertFalse(diff_path.exists())
        archived = list((self.git_loc / "old").glob("*.diff"))
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0].read_text(encoding="utf-8"), "old report\n")

    def test_resolve_diff_relative_and_absolute(self):
        rel = resolve_diff_path(self.git_loc, "reports/x.diff")
        self.assertEqual(rel, self.git_loc / "reports" / "x.diff")
        absolute = resolve_diff_path(self.git_loc, "/tmp/abs.diff")
        self.assertEqual(absolute, Path("/tmp/abs.diff"))


if __name__ == "__main__":
    unittest.main()
