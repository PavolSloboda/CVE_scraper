# Cursor Agent Guidelines

## 1. Workspace Boundaries & External Data
* **Project Confinement:** You are restricted to the current project directory for all code creation, modification, and writing.
* **The CVE Database (`~/.CVE_scrape`):** * You are granted **STRICTLY READ-ONLY** access to `~/.CVE_scrape`.
    * **NEVER** attempt to write to, modify, delete, or re-clone this directory. Modifying or removing this directory is an absolute last resort and requires explicit, multi-step confirmation from me.
    * Treat the data inside `~/.CVE_scrape` as immutable.

## 2. Execution Permissions & Throttling
* **Ask Before Running:** You have the capability to run the project, but you **MUST explicitly ask for my permission** and wait for my confirmation first.
* **Execution Throttling (Crucial):** Be aware that running the program triggers a `git pull` on the massive CVE repository. Do **NOT** suggest running the program in quick succession or repeatedly during debugging, as this wastes time and network resources.

## 3. Version Control (Git) Protocol
* **Committing:** You may stage changes and write commit messages, but **ONLY after summarizing the proposed commit and asking for my explicit approval**.
* **Pushing & Branching:** * **NEVER** push code directly to the `master` or `main` branches.
    * You may create and push to separate feature branches, but **ONLY after explicitly asking for my permission**. 

## 4. Automation Best Practices (Git Repo Scraping)
* **File System Efficiency:** When searching or parsing the CVE repository, use efficient file reading methods. Avoid loading the entire massive dataset into memory all at once; stream files or process them in chunks where possible.
* **Offline/Dev Mode:** When writing the code, ensure the `git pull` functionality is modular. It is highly recommended to implement a `--no-pull` flag or an offline development mode so we can test the parsing logic locally without triggering the network request.
* **Robust Error Handling:** File structures in large repos can be inconsistent. Handle missing files, unexpected JSON/text structures, or corrupted data gracefully without crashing the main parsing loop.

## 5. Code Comments
* **Do not remove existing comments** unless they are a `TODO:` comment that has been fully addressed by the change.
* **If you want to remove any other comment** (or rewrite comment text), **confirm with me first**.
* When refactoring or splitting files, **move comments with the code they describe**; do not drop them for brevity.