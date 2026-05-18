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


def print_manual_report(groups):
    for heading in sorted(groups):
        print(heading)
        for cve_id in sorted(groups[heading]):
            print(f"  {cve_id}")


def print_component_report(component, cve_ids):
    print(f"{component}:")
    for cve_id in sorted(cve_ids):
        print(f"  {cve_id}")
