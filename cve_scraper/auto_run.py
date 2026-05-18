"""Automatic mode: diff against last run, write last.diff, notify-send."""

import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from cve_scraper.auto_state import diff_finds, load_auto_state, save_auto_state
from cve_scraper.output import format_new_finds_diff, _group_by_fix_version
from cve_scraper.paths import DEFAULT_AUTO_STATE
from cve_scraper.version_match import parse_component_name


NOTIFY_HEADER = "CVE auto scrape finds:"


def resolve_diff_path(git_location: Path, diff_file: str) -> Path:
    # Relative to the CVE git clone root (-g).
    diff_path = Path(diff_file)
    if diff_path.is_absolute():
        return diff_path
    return git_location / diff_path


def archive_diff_file(diff_path: Path, git_location: Path) -> None:
    if not diff_path.exists():
        return
    old_dir = git_location / "old"
    old_dir.mkdir(parents=True, exist_ok=True)
    created = datetime.fromtimestamp(diff_path.stat().st_mtime)
    stamp = created.strftime("%Y-%m-%d-%H-%M-%S")
    destination = old_dir / f"{stamp}.diff"
    suffix = 1
    while destination.exists():
        destination = old_dir / f"{stamp}_{suffix}.diff"
        suffix += 1
    shutil.move(str(diff_path), str(destination))


def finds_from_matches(components, matches) -> dict[str, dict[str, list[str]]]:
    finds = {}
    for component in components:
        query = parse_component_name(component)
        results = matches.get(component, [])
        fix_groups = _group_by_fix_version(query.mode, results)
        if fix_groups:
            finds[component] = {
                fix: sorted(cve_ids) for fix, cve_ids in fix_groups.items()
            }
    return finds


def send_notification(body: str) -> None:
    subprocess.run(
        ["notify-send", NOTIFY_HEADER, body],
        check=False,
    )


def run_automatic_report(
    *,
    git_location: Path,
    components,
    matches,
    heading_for_component,
    diff_file: str,
    keep_diff: bool,
    state_path: Path | None = None,
    head_revision: str,
) -> str:
    diff_path = resolve_diff_path(git_location, diff_file)
    state = load_auto_state(state_path or DEFAULT_AUTO_STATE)
    current_finds = finds_from_matches(components, matches)
    new_finds = diff_finds(current_finds, state.get("last_finds", {}))

    report = format_new_finds_diff(new_finds, heading_for_component).rstrip("\n")

    if keep_diff and diff_path.exists():
        archive_diff_file(diff_path, git_location)

    diff_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.write_text(report + "\n", encoding="utf-8")

    save_auto_state(
        current_finds,
        head_revision,
        path=state_path or DEFAULT_AUTO_STATE,
    )

    send_notification(report)
    return report
