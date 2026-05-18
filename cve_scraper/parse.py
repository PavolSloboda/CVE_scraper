import json
from dataclasses import dataclass
from sys import stderr

from cve_scraper.version_match import (
    VersionMode,
    build_manual_query,
    affected_matches_query,
    extract_fix_labels_from_descriptions,
    extract_fix_versions,
    parse_component_name,
)


@dataclass(frozen=True)
class ParseResult:
    cve_id: str
    fix_versions: tuple[str, ...]


def get_json_from_file(file):
    try:
        with open(file, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as e:
        print(f"Exception caught when trying to open {file}: {e}", file=stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Exception caught when trying to parse {file}: {e}", file=stderr)
        return None


def _iter_affected_records(data):
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    for affected in cna.get("affected") or []:
        yield affected
    for adp in containers.get("adp") or []:
        for affected in adp.get("affected") or []:
            yield affected


def _cve_id_from_record(data) -> str | None:
    metadata = data.get("cveMetadata") or {}
    cve_id = metadata.get("cveId")
    if cve_id:
        return cve_id
    return data.get("id")


def _resolve_query(component_or_package, version=None):
    if version is None:
        return parse_component_name(component_or_package)
    return build_manual_query(component_or_package, version)


def cve_matches_query(data, query) -> bool:
    for affected in _iter_affected_records(data):
        if affected_matches_query(affected, query):
            return True
    return False


def _collect_fix_versions(data, query) -> set[str]:
    labels: set[str] = set()
    for affected in _iter_affected_records(data):
        labels |= extract_fix_versions(affected, query)
    if query.mode == VersionMode.STREAM and query.stream is not None:
        labels |= extract_fix_labels_from_descriptions(data, query.stream)
    return labels


def parse_json(data, component_or_package, version=None):
    query = _resolve_query(component_or_package, version)
    if not cve_matches_query(data, query):
        return None

    cve_id = _cve_id_from_record(data)
    if cve_id is None:
        return None

    fix_versions = _collect_fix_versions(data, query)
    if query.mode == VersionMode.STREAM and not fix_versions:
        fix_versions = {"unknown"}

    return ParseResult(cve_id=cve_id, fix_versions=tuple(sorted(fix_versions)))
