import json
import tempfile
import unittest
from pathlib import Path

from cve_scraper.auto_state import diff_finds, load_auto_state, save_auto_state


class AutoStateTests(unittest.TestCase):
    def test_load_missing_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = load_auto_state(Path(tmp) / "missing.json")
            self.assertIsNone(state["last_git_revision"])
            self.assertEqual(state["last_finds"], {})

    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auto_state.json"
            finds = {"mariadb11.8": {"11.8.6": ["CVE-A"]}}
            save_auto_state(finds, "deadbeef", path)
            loaded = load_auto_state(path)
            self.assertEqual(loaded["last_git_revision"], "deadbeef")
            self.assertEqual(loaded["last_finds"], finds)

    def test_load_corrupt_json_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{broken", encoding="utf-8")
            state = load_auto_state(path)
            self.assertEqual(state["last_finds"], {})

    def test_diff_new_component(self):
        previous = {}
        current = {"libarchive": {"3.7.7": ["CVE-1"]}}
        self.assertEqual(diff_finds(current, previous), current)


if __name__ == "__main__":
    unittest.main()
