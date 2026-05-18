import unittest

from cve_scraper.components import grep_products_from_lines
from cve_scraper.version_match import (
    VersionMode,
    parse_component_name,
    split_component_and_stream,
)


class ComponentParsingTests(unittest.TestCase):
    def test_split_mariadb_stream(self):
        self.assertEqual(split_component_and_stream("mariadb11.8"), ("mariadb", "11.8"))

    def test_split_hyphenated_product(self):
        self.assertEqual(
            split_component_and_stream("spring-boot2.3"),
            ("spring-boot", "2.3"),
        )

    def test_split_apache_tomcat(self):
        self.assertEqual(
            split_component_and_stream("apache-tomcat9.0"),
            ("apache-tomcat", "9.0"),
        )

    def test_log4j_is_whole_product(self):
        self.assertEqual(split_component_and_stream("log4j"), ("log4j", None))
        query = parse_component_name("log4j")
        self.assertEqual(query.product, "log4j")
        self.assertEqual(query.mode, VersionMode.ANY)

    def test_libarchive_no_stream(self):
        query = parse_component_name("libarchive")
        self.assertEqual(query.mode, VersionMode.ANY)

    def test_grep_terms_use_product_only(self):
        terms = grep_products_from_lines(["mariadb11.8", "postgresql18", "libarchive"])
        self.assertEqual(terms, ["libarchive", "mariadb", "postgresql"])


if __name__ == "__main__":
    unittest.main()
