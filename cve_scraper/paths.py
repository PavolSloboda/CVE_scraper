"""Default paths under ~/.CVE_scrape (or CVE_SCRAPE_HOME)."""

import os
from pathlib import Path

# Override base directory for all defaults below.
CVE_SCRAPE_HOME = Path(
    os.environ.get("CVE_SCRAPE_HOME", Path.home() / ".CVE_scrape")
).expanduser()

DEFAULT_GIT_LOCATION = CVE_SCRAPE_HOME / "git"
DEFAULT_OUR_COMPONENTS = CVE_SCRAPE_HOME / "our_components"
DEFAULT_AUTO_STATE = CVE_SCRAPE_HOME / "auto_state.json"

DEFAULT_GIT_URL = "https://github.com/CVEProject/cvelistV5.git"


def expand_path(path: str | Path) -> Path:
    return Path(path).expanduser()
