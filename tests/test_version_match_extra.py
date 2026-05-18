import unittest

from cve_scraper.version_match import (
    VersionMode,
    build_manual_query,
    extract_fix_labels_from_descriptions,
    iter_product_identifiers,
    product_matches_target,
)
from support import load_fixture


class VersionMatchExtraTests(unittest.TestCase):
    def test_purl_identifier(self):
        affected = {
            "packageURL": "pkg:rpm/fedora/mariadb@11.8.6?arch=x86_64",
            "versions": [],
        }
        ids = set(iter_product_identifiers(affected))
        self.assertIn("mariadb", ids)

    def test_package_name_identifier(self):
        affected = {"packageName": "postgresql", "vendor": "n/a", "versions": []}
        self.assertTrue(product_matches_target(affected, "postgresql"))

    def test_description_extract_widgets_stream(self):
        data = load_fixture("cve_description_fix.json")
        query = build_manual_query("widgets", "2.3")
        labels = extract_fix_labels_from_descriptions(data, query)
        self.assertIn("2.3.4", labels)

    def test_fix_query_does_not_use_description_stream_patterns(self):
        data = load_fixture("cve_description_fix.json")
        query = build_manual_query("widgets", "2.3.4")
        self.assertEqual(query.mode, VersionMode.FIX)
        labels = extract_fix_labels_from_descriptions(data, query)
        self.assertEqual(labels, set())


if __name__ == "__main__":
    unittest.main()
