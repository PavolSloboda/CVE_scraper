from cve_scraper.version_match import VersionMode, version_sort_key


def format_version_label(version):
    if version is None:
        return None
    normalized = version.strip().lower()
    if normalized in ("all", "*"):
        return None
    return version


def format_group_heading(package, version=None):
    version_label = format_version_label(version)
    if version_label:
        return f"{package} ({version_label}):"
    return f"{package}:"


def _group_by_fix_version(query_mode, parse_results):
    grouped = {}
    for result in parse_results:
        if query_mode == VersionMode.FIX:
            for fix_version in result.fix_versions:
                grouped.setdefault(fix_version, set()).add(result.cve_id)
            continue
        if not result.fix_versions:
            grouped.setdefault("unknown", set()).add(result.cve_id)
            continue
        for fix_version in result.fix_versions:
            grouped.setdefault(fix_version, set()).add(result.cve_id)
    return grouped


def print_grouped_by_fix(heading, fix_groups):
    print(heading)
    for fix_version in sorted(fix_groups, key=version_sort_key):
        print(f"  {fix_version}:")
        for cve_id in sorted(fix_groups[fix_version]):
            print(f"    {cve_id}")


def print_flat_cves(heading, cve_ids):
    print(heading)
    for cve_id in sorted(cve_ids):
        print(f"  {cve_id}")


def print_manual_report(heading, parse_results, query_mode):
    if query_mode == VersionMode.FIX:
        cve_ids = {result.cve_id for result in parse_results}
        print_flat_cves(heading, cve_ids)
        return
    if query_mode in (VersionMode.STREAM, VersionMode.ANY):
        fix_groups = _group_by_fix_version(query_mode, parse_results)
        print_grouped_by_fix(heading, fix_groups)
        return
    cve_ids = {result.cve_id for result in parse_results}
    print_flat_cves(heading, cve_ids)


def print_component_report(heading, parse_results, query_mode):
    print_manual_report(heading, parse_results, query_mode)
