import unittest

from cve_scraper.version_match import product_matches_target


class ProductMatchTests(unittest.TestCase):
    def test_vendor_or_product_exact(self):
        self.assertTrue(
            product_matches_target(
                {"vendor": "MariaDB", "product": "MariaDB", "versions": []},
                "mariadb",
            )
        )
        self.assertTrue(
            product_matches_target(
                {"vendor": "MariaDB", "product": "server", "versions": []},
                "mariadb",
            )
        )
        self.assertTrue(
            product_matches_target(
                {"vendor": "n/a", "product": "PostgreSQL", "versions": []},
                "postgresql",
            )
        )

    def test_cpe_vendor_product(self):
        self.assertTrue(
            product_matches_target(
                {
                    "vendor": "mariadb",
                    "product": "mariadb",
                    "cpes": ["cpe:2.3:a:mariadb:mariadb:-:*:*:*:*:node.js:*:*"],
                    "versions": [],
                },
                "mariadb",
            )
        )

    def test_compound_name_does_not_substring_match(self):
        self.assertFalse(
            product_matches_target(
                {
                    "vendor": "HackerOne",
                    "product": "mariadb node module",
                    "versions": [],
                },
                "mariadb",
            )
        )
        self.assertFalse(
            product_matches_target(
                {
                    "vendor": "Openshift Enterprise",
                    "product": "openshift/mariadb-apb",
                    "versions": [],
                },
                "mariadb",
            )
        )

    def test_na_only_entry(self):
        self.assertFalse(
            product_matches_target(
                {"vendor": "n/a", "product": "n/a", "versions": []},
                "mariadb",
            )
        )


if __name__ == "__main__":
    unittest.main()
