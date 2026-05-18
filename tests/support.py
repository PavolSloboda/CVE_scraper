import json
import shutil
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def fixture_path(name: str) -> Path:
    return FIXTURES_DIR / name


def write_mini_cve_repo(root: Path) -> dict[str, Path]:
    """Lay out cves/<year>/<bucket>/*.json under root for grep/read_repo tests."""
    paths = {}
    layout = {
        "cve_mariadb_less_than.json": ("2026", "0xxx", "CVE-TEST-0001.json"),
        "cve_mariadb_inline_range.json": ("2026", "0xxx", "CVE-TEST-0002.json"),
        "cve_mariadb_bare_version.json": ("2025", "1xxx", "CVE-TEST-0003.json"),
        "cve_libarchive.json": ("2025", "1xxx", "CVE-TEST-0004.json"),
        "cve_postgresql.json": ("2026", "1xxx", "CVE-TEST-0005.json"),
        "cve_no_match.json": ("2026", "9xxx", "CVE-TEST-9999.json"),
    }
    for filename, (year, bucket, dest_name) in layout.items():
        target_dir = root / "cves" / year / bucket
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / dest_name
        shutil.copy(fixture_path(filename), target)
        paths[filename] = target
    return paths
