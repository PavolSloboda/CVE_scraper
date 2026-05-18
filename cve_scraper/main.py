from sys import stderr

from cve_scraper.cli import build_parser
from cve_scraper.git_sync import refresh_git
from cve_scraper.parse import get_json_from_file, parse_json
from cve_scraper.paths import expand_path
from cve_scraper.repo import read_repo


def _load_our_components(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"And expection occured while trying to read {path}", file=stderr)
        raise SystemExit(2) from e


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    git_location = str(expand_path(args.git_location))
    our_components_path = str(expand_path(args.our_components))

    if args.automatic_mode:
        packages = _load_our_components(our_components_path)
    else:
        if args.package is None:
            print(
                "The -p|--package arguments must be set unless starting in automatic mode",
                file=stderr,
            )
            parser.print_help()
            raise SystemExit(1)
        else:
            packages = [args.package]
    else:
        packages = _load_our_components(our_components_path)

    if not args.no_pull:
        refresh_git(git_location, args.git_url)
    elif not expand_path(git_location).exists():
        print(
            f"The git location {git_location} does not exist, do not run with -n/--no-pull "
            "unless you have already cloned the repository",
            file=stderr,
        )
        raise SystemExit(1)

    files = read_repo(git_location, packages, args.start_year, args.end_year)

    # TODO: this will run the automatic mode which checks all of our components
    if args.automatic_mode:
        try:
            f = open(our_components_path, "r")
            our_components = f.read()
        except Exception as e:
            print(
                f"Hit an exception while trying to read {our_components_path}: {e}",
                file=stderr,
            )
            raise SystemExit(2) from e
        our_component_list = our_components.split("\n")
        # go over very single component and check it
        # TODO: no need to itterate over every file for every component, this is redundant
        # also TODO: get rid of the code duplication
        for component in our_component_list:
            # skip any empty lines
            if component != "":
                print(component)
                for file in files:
                    in_json = get_json_from_file(file)
                    parse_json(in_json, component)
    else:
        for file in files:
            in_json = get_json_from_file(file)
            parse_json(in_json, args.package, args.version)


if __name__ == "__main__":
    main()
