import json
from sys import stderr

from cve_scraper.version_match import (
    MatchQuery,
    build_manual_query,
    affected_matches_query,
    parse_component_name,
)


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


def _resolve_query(component_or_package, version=None) -> MatchQuery:
    if version is None:
        return parse_component_name(component_or_package)
    return build_manual_query(component_or_package, version)


def cve_matches_query(data, query: MatchQuery) -> bool:
    for affected in _iter_affected_records(data):
        if affected_matches_query(affected, query):
            return True
    return False


def parse_json(data, component_or_package, version=None):
    query = _resolve_query(component_or_package, version)
    if not cve_matches_query(data, query):
        return None
    return _cve_id_from_record(data)
