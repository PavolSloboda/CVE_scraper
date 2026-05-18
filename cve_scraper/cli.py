"""Command-line argument definitions."""

import argparse

from cve_scraper.paths import (
    DEFAULT_GIT_LOCATION,
    DEFAULT_GIT_URL,
    DEFAULT_OUR_COMPONENTS,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--package",
        help="The package to filter the CVEs for (manual mode; one package only)",
    )
    parser.add_argument(
        "-v",
        "--version",
        default="all",
        help="The versions to filter the CVEs for (default is to not filter for versions",
    )
    parser.add_argument(
        "-n",
        "--no-pull",
        action="store_true",
        help="Do not pull the repo (mostly for a debugging speedup or consecutive runs)",
    )
    parser.add_argument(
        "-g",
        "--git-location",
        default=str(DEFAULT_GIT_LOCATION),
        help="The location of the git containing the CVEs",
    )
    parser.add_argument(
        "-u",
        "--git-url",
        default=DEFAULT_GIT_URL,
        help="The url of the git repository",
    )
    parser.add_argument(
        "-s",
        "--start-year",
        type=int,
        help="The start year to filter from (speeds up the parsing",
    )
    parser.add_argument(
        "-e",
        "--end-year",
        type=int,
        help="The end year to filter to (speeds up the parsing",
    )

    parser.add_argument(
        "-a",
        "--automatic-mode",
        action="store_true",
        help="Signifies the automatic mode which checks for all our components and any new CVEs which have been reported for them",
    )
    parser.add_argument(
        "-o",
        "--our-components",
        default=str(DEFAULT_OUR_COMPONENTS),
        help="File specifying all of our components",
    )
    parser.add_argument(
        "-d",
        "--diff-file",
        default="last.diff",
        help="Automatic mode: report path relative to -g (default: last.diff)",
    )
    parser.add_argument(
        "-k",
        "--keep-diff",
        action="store_true",
        help="Automatic mode: archive previous diff under <git-location>/old/ before overwrite",
    )

    return parser
