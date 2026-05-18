"""Persistent state for automatic mode (not used by manual runs)."""

import json
from pathlib import Path

from cve_scraper.paths import DEFAULT_AUTO_STATE, expand_path

# component -> fix_version -> [CVE-IDs]
FindsMap = dict[str, dict[str, list[str]]]


def _empty_state() -> dict:
    return {"last_git_revision": None, "last_finds": {}}


def load_auto_state(path: Path | None = None) -> dict:
    state_path = expand_path(path or DEFAULT_AUTO_STATE)
    if not state_path.exists():
        return _empty_state()
    try:
        with open(state_path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _empty_state()
    if not isinstance(data, dict):
        return _empty_state()
    data.setdefault("last_git_revision", None)
    data.setdefault("last_finds", {})
    return data


def save_auto_state(
    last_finds: FindsMap,
    last_git_revision: str,
    path: Path | None = None,
) -> None:
    state_path = expand_path(path or DEFAULT_AUTO_STATE)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "last_git_revision": last_git_revision,
        "last_finds": last_finds,
    }
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def diff_finds(current: FindsMap, previous: FindsMap) -> FindsMap:
    # CVE IDs present in current but not in the previous automatic run.
    new_finds: FindsMap = {}
    for component, fix_groups in current.items():
        for fix_version, cve_ids in fix_groups.items():
            known = set(previous.get(component, {}).get(fix_version, []))
            added = sorted(cve_id for cve_id in cve_ids if cve_id not in known)
            if added:
                new_finds.setdefault(component, {})[fix_version] = added
    return new_finds
