"""Git helpers for automatic mode (revision tracking, changed CVE files)."""

from pathlib import Path

import git


def get_head_revision(git_location: str) -> str:
    repo = git.Repo(git_location)
    return repo.head.commit.hexsha


def get_changed_cve_files(git_location: str, since_revision: str | None) -> list[str] | None:
    # None => no prior revision (first automatic run): parse all grep candidates.
    if since_revision is None:
        return None
    repo = git.Repo(git_location)
    if since_revision == repo.head.commit.hexsha:
        return []
    output = repo.git.diff("--name-only", since_revision, "HEAD", "--", "cves")
    if not output.strip():
        return []
    root = Path(git_location)
    return [str(root / line) for line in output.splitlines() if line.endswith(".json")]


def filter_files_to_git_changes(
    candidate_files: list[str],
    changed_files: list[str] | None,
) -> list[str]:
    if changed_files is None:
        return candidate_files
    changed_set = set(changed_files)
    return [path for path in candidate_files if path in changed_set]
