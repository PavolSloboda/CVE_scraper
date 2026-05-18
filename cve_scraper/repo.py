"""Discover CVE JSON files via grep (coarse pre-filter)."""

import os
import re
import subprocess
from sys import stderr

# Limit grep -e batches to stay below typical ARG_MAX.
GREP_BATCH_SIZE = 40

_YEAR_IN_PATH = re.compile(r"/cves/(\d{4})/")


def _year_from_path(path: str) -> int | None:
    normalized = path.replace(os.sep, "/")
    match = _YEAR_IN_PATH.search(normalized)
    if not match:
        return None
    return int(match.group(1))


def _path_in_year_range(path: str, start_year: int | None, end_year: int | None) -> bool:
    year = _year_from_path(path)
    if year is None:
        return True
    if start_year and year < start_year:
        return False
    if end_year and year > end_year:
        return False
    return True


def _grep_product_in_tree(cves_root: str, product: str) -> list[str]:
    # Fixed-string, case-insensitive; -w avoids matching "go" inside "category".
    try:
        result = subprocess.run(
            ["grep", "-RlwiF", product, cves_root],
            capture_output=True,
            text=True,
            check=True,
        )
        return [line for line in result.stdout.splitlines() if line]
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return []
        print(f"Error running grep for {product!r}: {e.stderr}", file=stderr)
        raise SystemExit(3) from e


def get_files_with_match(directory: str, packages: list[str]):
    # Calls the system grep and captures the output (one product per invocation).
    found: set[str] = set()
    for product in packages:
        found.update(_grep_product_in_tree(directory, product))
    return iter(sorted(found))


def read_repo(git_location, products, start_year=None, end_year=None):
    # Walk cves/ once per product name; filter paths by year from cves/YYYY/.
    cves_root = os.path.join(git_location, "cves")
    if not os.path.isdir(cves_root):
        return []

    unique_products = sorted(set(products))
    files: set[str] = set()
    for product in unique_products:
        for path in _grep_product_in_tree(cves_root, product):
            if _path_in_year_range(path, start_year, end_year):
                files.add(path)
    return sorted(files)
