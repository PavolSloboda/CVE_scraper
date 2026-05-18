"""Orchestrate git sync, file discovery, parsing, and printing."""

from pathlib import Path
from sys import stderr

from cve_scraper.auto_run import run_automatic_report
from cve_scraper.cli import build_parser
from cve_scraper.git_ops import (
    filter_files_to_git_changes,
    get_changed_cve_files,
    get_head_revision,
)
from cve_scraper.git_sync import refresh_git
from cve_scraper.output import format_group_heading, print_component_report, print_manual_report
from cve_scraper.components import grep_products_from_lines
from cve_scraper.parse import get_json_from_file, match_components_in_record
from cve_scraper.paths import expand_path
from cve_scraper.repo import read_repo
from cve_scraper.version_match import (
    VersionMode,
    build_manual_query,
    parse_component_name,
)


def _load_our_components(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"And expection occured while trying to read {path}", file=stderr)
        raise SystemExit(2) from e


def _process_cve_files(files, components, version=None):
    # One JSON load per file; match all components in a single affected[] scan.
    matches = {component: [] for component in components}
    for file in files:
        in_json = get_json_from_file(file)
        if in_json is None:
            continue
        # go over very single component and check it
        for component, result in match_components_in_record(
            in_json, components, version
        ).items():
            matches[component].append(result)
    return matches


def _query_for_component(component, version=None):
    if version is None:
        return parse_component_name(component)
    return build_manual_query(component, version)


def _display_label_for_component(component, version=None):
    query = _query_for_component(component, version)
    if version is not None:
        return format_group_heading(component, version)
    if query.mode == VersionMode.STREAM and query.stream is not None:
        stream_label = ".".join(str(part) for part in query.stream)
        return format_group_heading(query.product, stream_label)
    return f"{component}:"


def main():
    parser = build_parser()
    args = parser.parse_args()

    git_location = expand_path(args.git_location)
    git_location_str = str(git_location)
    our_components_path = str(expand_path(args.our_components))

    if args.automatic_mode:
        components = _load_our_components(our_components_path)
    else:
        if args.package is None:
            print(
                "The -p|--package arguments must be set unless starting in automatic mode",
                file=stderr,
            )
            parser.print_help()
            raise SystemExit(1)
        components = [args.package]

    if not args.no_pull:
        refresh_git(git_location_str, args.git_url)
    elif not git_location.exists():
        print(
            f"The git location {git_location_str} does not exist, do not run with -n/--no-pull "
            "unless you have already cloned the repository",
            file=stderr,
        )
        raise SystemExit(1)

    # Grep uses product names only (mariadb), not combined lines (mariadb11.8).
    grep_products = (
        grep_products_from_lines(components)
        if args.automatic_mode
        else [args.package.lower()]
    )
    candidate_files = read_repo(
        git_location_str, grep_products, args.start_year, args.end_year
    )

    if args.automatic_mode:
        from cve_scraper.auto_state import load_auto_state

        state = load_auto_state()
        changed_files = get_changed_cve_files(
            git_location_str, state.get("last_git_revision")
        )
        files = filter_files_to_git_changes(candidate_files, changed_files)
        version = None
        matches = _process_cve_files(files, components, version)
        head_revision = get_head_revision(git_location_str)
        run_automatic_report(
            git_location=git_location,
            components=components,
            matches=matches,
            heading_for_component=_display_label_for_component,
            diff_file=args.diff_file,
            keep_diff=args.keep_diff,
            head_revision=head_revision,
        )
        return

    files = candidate_files
    version = args.version
    matches = _process_cve_files(files, components, version)

    query = build_manual_query(args.package, args.version)
    heading = format_group_heading(args.package, args.version)
    results = matches.get(args.package, [])
    print_manual_report(heading, results, query.mode)


if __name__ == "__main__":
    main()
