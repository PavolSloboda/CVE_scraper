"""Clone or pull the cvelistV5 git repository."""

import os

import git
from tqdm import tqdm


# progress bar, snatched from here:
# https://stackoverflow.com/questions/51045540/python-progress-bar-for-git-clone
class CloneProgress(git.RemoteProgress):
    def __init__(self):
        super().__init__()
        self.pbar = tqdm()

    def update(self, op_code, cur_count, max_count=None, message=""):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()


# clones the git repository if not cloned yet
# and pulls the origin
def refresh_git(git_location: str, url):
    if not os.path.exists(git_location):
        print(f"Cloning the repository here: {git_location}")
        git.Repo.clone_from(url, git_location, progress=CloneProgress())
        print("Repository cloned")

    repo = git.Repo(git_location)
    origin = repo.remotes.origin
    print("Pulling the latest changes")
    origin.pull()
    print("Pulled")
