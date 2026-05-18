#!/usr/bin/env python3

import argparse
import git
import os
from tqdm import tqdm
from sys import stderr
import json
import subprocess

# TODO: will need to read aaaall of the json from all the files
# and then parse it, first filtering it by component so the further
# filtering does not take the whole day

# TODO: I need to think about the use cases as well since I want this
# to run automatically for all our components periodically
# which the implementation does not support yet
# this is more of the call for a release just about to be shipped
# in an errata use case

def _init_args():
    parser =  argparse.ArgumentParser()
    parser.add_argument('-p', '--package',  help='The package to filter the CVEs for')
    parser.add_argument('-v', '--versions', nargs='+', help='The versions to filter the CVEs for (default is to not filter for versions')
    # TODO: this is objectively wrong and should be fixed
    parser.add_argument('-g', '--git-location', default='/home/psloboda/.CVE_scrape/git', help='The location of the git containing the CVEs')
    parser.add_argument('-u', '--git-url', default='https://github.com/CVEProject/cvelistV5.git', help='The url of the git repository')

    # WIP: theoretically it should, we will see, maybe I am lying
    parser.add_argument('-s', '--start-year', type=int, help='The start year to filter from (speeds up the parsing')
    parser.add_argument('-e', '--end-year', type=int, help='The end year to filter to (speeds up the parsing')

    parser.add_argument('-a', '--automatic-mode', action='store_true', help='Signifies the automatic mode which checks for all our components and any new CVEs which have been reported for them')
    parser.add_argument('-o', '--our-components', default='/home/psloboda/.CVE_scrape/our_components', help='File specifying all of our components' )

    return parser

# progress bar, snatched from here: 
# https://stackoverflow.com/questions/51045540/python-progress-bar-for-git-clone
class CloneProgress(git.RemoteProgress):
    def __init__(self):
        super().__init__()
        self.pbar = tqdm()

    def update(self, op_code, cur_count, max_count=None, message=''):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()

# clones the git repository if not cloned yet
# and pulls the origin
def refresh_git(git_location, url):
    if not os.path.exists(git_location):
        print(f"Cloning the repository here: {git_location}")
        repo = git.Repo.clone_from(url, git_location, progress=CloneProgress())
        print("Repository cloned")
    repo = git.Repo(git_location)
    origin = repo.remotes.origin
    print("Pulling the latest changes")
    origin.pull()
    print("Pulled")

def get_files_with_match(dir, packages):
    try:
        # Calls the system grep and captures the output
        result = subprocess.run(
            ['grep', '-RlPi', f"{'|'.join(packages)}", dir],
            capture_output=True,
            text=True,
            check=True
        )
        found = result.stdout
        
    except subprocess.CalledProcessError as e:
        # grep returns a non-zero exit code if no matches are found
        if e.returncode == 1:
            print(f"No matches found for '{packages}'.")
        else:
            print(f"Error running grep: {e.stderr}")
        exit(3)
    return iter(found.splitlines())

# this will read the repository and return it as json
def read_repo(git_location, packages, start_year=None, end_year=None):
    CVE_dirs = os.listdir(f"{git_location}/cves")
    files = []

    for CVE_dir in CVE_dirs:
        # skip the jsons, only take the dirs
        if '.json' in CVE_dir:
            continue
        # skip anything too early
        if start_year and int(CVE_dir) < start_year:
            continue
        # skip anything too late
        if end_year and int(CVE_dir) > end_year:
            continue

        # TODO: this is very ugly
        # mayhaps first try to find the "vendor": "xyz" in the files using
        # some handy linux utils and just load the files that matter
        # to save computing time
        

        files += get_files_with_match(f"{git_location}/cves/{CVE_dir}", packages)
       # subdirs = os.listdir(f"{git_location}/cves/{CVE_dir}")
       #for subdir in subdirs:
       #    files = os.listdir(f"{git_location}/cves/{CVE_dir}/{subdir}")
       #    for CVE_file in files:
       #        try:
       #            with open(f"{git_location}/cves/{CVE_dir}/{subdir}/{CVE_file}", 'r') as f:
       #                f_contents = json.loads(f.read())
       #        except Exception as e:
       #            print(f"Exception caught when trying to open {git_location}/cves/{CVE_dir}/{subdir}/{CVE_file}: {e}", file=stderr)
       #            exit(2)
       #        json_list.append(f_contents)

    #print(json_list[0])
    return files

def get_json_from_file(file):
    pass

def parse_json(input, package, versions=None):
    pass


if __name__ == '__main__':
    parser = _init_args()
    args = parser.parse_args()

    if not args.automatic_mode:
        if args.package == None:
            print(f"The -p|--package arguments must be set unless starting in automatic mode", file=stderr)
            parser.print_help()
            exit(1)
        else:
            packages = [args.package]
    else:
        try:
           with open(args.our_components, 'r') as f:
               packages = f.read()
        except Exception as e:
            print(f"And expection occured while trying to read {args.our_components}", file=stderr)
            exit(2)

    refresh_git(args.git_location, args.git_url)
    files = read_repo(args.git_location, packages, args.start_year, args.end_year)

    # TODO: this will run the automatic mode which checks all of our components
    if args.automatic_mode:
        try:
            f = open(args.our_components, 'r')
            our_components = f.read()
        except Exception as e:
            print(f"Hit an exception while trying to read {args.our_components}: {e}", file=stderr)
            exit(2)
        our_component_list = our_components.split('\n')
        # go over very single component and check it
        # TODO: no need to itterate over every file for every component, this is redundant
        # also TODO: get rid of the code duplication
        for component in our_component_list:
            # skip any empty lines
            if component != '':
                print(component)
                for file in files:
                    in_json = get_json_from_file(file)
                    parse_json(in_json, component)
    else:
        for file in files:
            in_json = get_json_from_file(file)
            parse_json(in_json, args.package, args.versions)
