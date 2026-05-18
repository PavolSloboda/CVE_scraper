import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

# stderr from get_json_from_file may not be captured under unittest discovery;
# these tests assert return values only.

from cve_scraper.parse import ParseResult, get_json_from_file, parse_json
from support import fixture_path, load_fixture


class ParseFunctionalTests(unittest.TestCase):
    def test_load_fixture_file(self):
        path = fixture_path("cve_mariadb_less_than.json")
        data = get_json_from_file(str(path))
        self.assertEqual(data["cveMetadata"]["cveId"], "CVE-TEST-0001")

    def test_invalid_json_returns_none(self):
        data = get_json_from_file(str(fixture_path("invalid.json")))
        self.assertIsNone(data)

    def test_missing_file_returns_none(self):
        err = io.StringIO()
        with redirect_stderr(err):
            data = get_json_from_file("/nonexistent/CVE-404.json")
        self.assertIsNone(data)

    def test_stream_match_less_than(self):
        data = load_fixture("cve_mariadb_less_than.json")
        result = parse_json(data, "mariadb", "11.8")
        self.assertEqual(result, ParseResult("CVE-TEST-0001", ("11.8.6",)))

    def test_fix_match_less_than(self):
        data = load_fixture("cve_mariadb_less_than.json")
        result = parse_json(data, "mariadb", "11.8.6")
        self.assertEqual(result, ParseResult("CVE-TEST-0001", ("11.8.6",)))

    def test_stream_rejects_other_branch(self):
        data = load_fixture("cve_mariadb_less_than.json")
        self.assertIsNone(parse_json(data, "mariadb", "12.3"))

    def test_inline_range_stream(self):
        data = load_fixture("cve_mariadb_inline_range.json")
        result = parse_json(data, "mariadb", "11.8")
        self.assertEqual(result.cve_id, "CVE-TEST-0002")
        self.assertIn("11.8.6", result.fix_versions)

    def test_bare_version_stream_unknown_bucket(self):
        data = load_fixture("cve_mariadb_bare_version.json")
        result = parse_json(data, "mariadb", "11.8")
        self.assertEqual(result, ParseResult("CVE-TEST-0003", ("unknown",)))

    def test_component_name_automatic_query(self):
        data = load_fixture("cve_mariadb_less_than.json")
        result = parse_json(data, "mariadb11.8")
        self.assertEqual(result.cve_id, "CVE-TEST-0001")

    def test_libarchive_any_mode(self):
        data = load_fixture("cve_libarchive.json")
        result = parse_json(data, "libarchive", "all")
        self.assertEqual(result.cve_id, "CVE-TEST-0004")
        self.assertIn("3.7.7", result.fix_versions)

    def test_postgresql_stream_18(self):
        data = load_fixture("cve_postgresql.json")
        result = parse_json(data, "postgresql", "18")
        self.assertEqual(result.cve_id, "CVE-TEST-0005")
        self.assertIn("18.2", result.fix_versions)

    def test_description_fallback_fix_version(self):
        data = load_fixture("cve_description_fix.json")
        result = parse_json(data, "widgets", "2.3")
        self.assertEqual(result.cve_id, "CVE-TEST-0006")
        self.assertIn("2.3.4", result.fix_versions)

    def test_wrong_product_no_match(self):
        data = load_fixture("cve_no_match.json")
        self.assertIsNone(parse_json(data, "mariadb", "11.8"))

    def test_process_file_roundtrip(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"cveMetadata":{"cveId":"CVE-TEST-TMP"},"containers":{"cna":{"affected":[{"vendor":"MariaDB","product":"MariaDB","versions":[{"lessThan":"11.8.6","status":"affected","version":"11.8.0"}]}]}}}')
            path = handle.name
        try:
            loaded = get_json_from_file(path)
            result = parse_json(loaded, "mariadb", "11.8.6")
            self.assertEqual(result.cve_id, "CVE-TEST-TMP")
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
