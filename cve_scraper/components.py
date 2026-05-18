"""Parse our_components lines and derive grep search terms."""

from cve_scraper.version_match import MatchQuery, parse_component_name


def grep_products_from_lines(lines: list[str]) -> list[str]:
    # Grep must search product names only (e.g. mariadb), not mariadb11.8.
    return sorted({parse_component_name(line).product for line in lines})
