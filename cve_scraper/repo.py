import os
import subprocess
from sys import stderr


def get_files_with_match(directory: str, packages: list[str]):
    try:
        # Calls the system grep and captures the output
        result = subprocess.run(
            ["grep", "-RlPi", "|".join(packages), directory],
            capture_output=True,
            text=True,
            check=True,
        )
        found = result.stdout

    except subprocess.CalledProcessError as e:
        # grep returns a non-zero exit code if no matches are found
        if e.returncode == 1:
            return iter(())
        print(f"Error running grep: {e.stderr}", file=stderr)
        raise SystemExit(3) from e
    return iter(found.splitlines())


# this will read the repository and return it as json
def read_repo(git_location, packages, start_year=None, end_year=None):
    CVE_dirs = os.listdir(f"{git_location}/cves")
    files = []

    for CVE_dir in CVE_dirs:
        # skip the jsons, only take the dirs
        if ".json" in CVE_dir:
            continue
        # skip anything too early
        if start_year and int(CVE_dir) < start_year:
            continue
        # skip anything too late
        if end_year and int(CVE_dir) > end_year:
            continue

        year_dir = os.path.join(cves_root, cve_dir)
        files.extend(get_files_with_match(year_dir, packages))

    return files
