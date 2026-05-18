# CVE_scraper

Filter [CVE JSON 5](https://github.com/CVEProject/cvelistV5) records for packages and versions you care about (errata checks, release notes, component tracking).

## Requirements

- Python 3.10+
- `grep` on `PATH`
- Network access for the first clone / routine `git pull` (unless you use `--no-pull`)

```bash
pip install -r requirements.txt
```

## Data layout (`~/.CVE_scrape`)

All runtime files live under `~/.CVE_scrape` (override the base directory with `CVE_SCRAPE_HOME`):

| Path | Purpose |
|------|---------|
| `git/` | Clone of [cvelistV5](https://github.com/CVEProject/cvelistV5.git) |
| `git/last.diff` | Latest automatic-mode report (default `-d`; overwritten each `-a` run) |
| `git/old/*.diff` | Archived reports when using `-k` / `--keep-diff` |
| `our_components` | One component per line for automatic mode (`-a`) |
| `auto_state.json` | Automatic-mode baseline (`last_finds`, last git revision); not touched by manual runs |

Copy the sample component list:

```bash
mkdir -p ~/.CVE_scrape
cp examples/our_components ~/.CVE_scrape/our_components
```

### Sample `our_components`

Each line is `product` + optional **stream** suffix (no separator). Hyphens are allowed in the product (`spring-boot2.3`). Names like `log4j` are treated as a product with no stream suffix. Example: `mariadb11.8` → grep `mariadb`, match MariaDB on the 11.8 line:

```
mariadb11.8
mariadb12.3
postgresql18
libarchive
```

See [`examples/our_components`](examples/our_components).

## Usage

Entry point: `scrape.py` (or `python -m cve_scraper.main`).

### Manual mode (one package per run)

Always pass **`-p`** (product) and **`-v`** (version). Default for `-v` is `all`.

| `-v` value | Meaning | Example |
|------------|---------|---------|
| `all` or `*` | Any affected version for that product | `-p libarchive -v all` |
| Two-part (e.g. `11.8`, `18`) | **Stream**: CVEs affecting that release line | `-p mariadb -v 11.8` |
| Three-part (e.g. `11.8.6`) | **Fix / errata**: CVEs fixed in that release | `-p mariadb -v 11.8.6` |

Use the most specific version you care about; broader `-v` returns broader results.

**Stream output** groups CVEs by inferred fix version:

```
mariadb (11.8):
  11.8.6:
    CVE-2026-35549
  unknown:
    CVE-2025-13699
```

**Fix output** is a flat list under the requested version:

```
mariadb (11.8.6):
  CVE-2026-35549
```

**Examples:**

```bash
# CVEs affecting MariaDB 11.8.x (grouped by fix version)
./scrape.py -p mariadb -v 11.8

# CVEs fixed in MariaDB 11.8.6 (shipping / errata)
./scrape.py -p mariadb -v 11.8.6

# All libarchive CVEs in the database (flat, by fix when known)
./scrape.py -p libarchive -v all

# Limit years (faster)
./scrape.py -p mariadb -v 11.8 -s 2025 -e 2026

# Use existing clone, skip network pull (dev / repeat runs)
./scrape.py -n -p mariadb -v 11.8 -s 2026 -e 2026
```

### Automatic mode

Reads `~/.CVE_scrape/our_components`, pulls the CVE repo (unless `-n`), and:

1. Parses **new or changed** CVE JSON files since the last automatic run (git revision in `auto_state.json`).
2. Compares matches to **`last_finds`** and keeps only **new** CVE IDs per component and fix-version bucket.
3. Writes that report to **`<git-location>/<diff-file>`** (default `last.diff` under `-g`).
4. Sends a desktop notification via **`notify-send`** (header: `CVE auto scrape finds:`; body: the report text).
5. Updates `auto_state.json` with the full current find set (manual runs do not touch this file).

Automatic mode does not print the report to stdout (only the diff file and notification). Errors still go to stderr.

```bash
./scrape.py -a
./scrape.py -a -n                              # no git pull
./scrape.py -a -d reports/current.diff         # diff path relative to -g
./scrape.py -a -k                              # archive previous diff to <g>/old/YYYY-MM-DD-H-M-S.diff
```

**First automatic run:** every match is treated as new (full baseline written to the diff file and state file).

**Later runs:** only CVEs not present in the previous `last_finds` appear in the diff and notification.

Example diff file:

```
mariadb (11.8):
  11.8.6:
    CVE-2026-32710
```

If nothing is new: `(no new CVEs since last automatic run.)`

Requires `notify-send` (typically `libnotify`; on Fedora: `dnf install libnotify`).

### Cron example (twice a week)

Adjust paths and schedule to taste. Example: Monday and Thursday at 08:00, with archived diffs:

```bash
crontab -e
```

Add:

```cron
0 8 * * 1,4 /usr/bin/python3 /path/to/CVE_scraper/scrape.py -a -k >> /tmp/cve_scraper_cron.log 2>&1
```

Use the full path to `scrape.py`. Ensure the cron environment can run `notify-send` (often needs `DISPLAY` / `DBUS_SESSION_BUS_ADDRESS` for your logged-in session; headless cron may write `last.diff` but skip visible notifications unless you set those variables).

For a user systemd timer instead of cron, create a unit that runs the same command on your preferred calendar.

### Other flags

| Flag | Description |
|------|-------------|
| `-g PATH` | CVE git clone location (default: `~/.CVE_scrape/git`) |
| `-u URL` | Clone URL (default: cvelistV5) |
| `-o PATH` | Component list for `-a` (default: `~/.CVE_scrape/our_components`) |
| `-n` / `--no-pull` | Do not clone/pull; repo must already exist |
| `-s` / `-e` | Limit to CVE years under `cves/YYYY/` |
| `-d PATH` | Automatic mode: diff report relative to `-g` (default: `last.diff`) |
| `-k` / `--keep-diff` | Automatic mode: move previous diff to `<g>/old/<timestamp>.diff` before overwrite |

## How it works (short)

1. **Update** the cvelistV5 clone (`git pull`, unless `-n`).
2. **Pre-filter** with `grep` over `cves/<year>/` (fast, text-based).
3. **Parse** JSON: match `containers.cna` / `containers.adp` `affected` data and version ranges.
4. **Print** results in the format above.

## Limitations

These are constraints of the current design, not a roadmap:

- **Grep pre-filter** — Automatic mode greps for the **product** name (`mariadb` from `mariadb11.8`), not the full `our_components` line. Uses fixed-string, case-insensitive whole-word grep (`-Fwi`) per product. Very short names (e.g. `go`) can still over-match English words; prefer distinctive product tokens where possible.
- **CVE record quality** — Vendors use different JSON shapes (`lessThan`, `>= x, < y`, bare `version`, descriptions only). Fix versions are inferred from those fields and English description patterns; records without a fix bound appear under `unknown`.
- **Product matching** — `-p` must match a normalized **vendor**, **product**, **packageName**, **CPE** vendor/product, or **PURL** name from the CVE record (not substring search inside long product titles). Use the name that appears in the JSON/CPE (e.g. `postgresql`, not a distro package alias).
- **Version heuristics** — `-v` with three numeric segments is treated as a fix query; one- or two-part values are stream queries. Values like `11.8.0` are fix queries, not stream.
- **Scope** — Manual mode: one `-p` per run. Automatic mode only parses CVE files added or changed since the last automatic run (by git revision); matching is still validated against `last_finds` in `auto_state.json`.
- **Performance** — Full history without `-s`/`-e` walks many years and runs grep per year; first clone and each pull download a large repo.
- **Dependencies** — Requires system `grep`; JSON traversal is in-memory per file (one CVE file at a time, not the whole dataset at once).

## Project layout

```
scrape.py              # entry point
cve_scraper/
  main.py              # orchestration
  cli.py               # arguments
  paths.py             # ~/.CVE_scrape defaults
  git_sync.py          # clone / pull
  repo.py              # grep + year walk
  parse.py             # JSON load + match
  version_match.py     # version / product logic
  output.py            # formatted printing
  auto_state.py        # last_finds + revision persistence
  auto_run.py          # diff file, notify-send, archiving
  git_ops.py           # git revision / changed-file helpers
examples/
  our_components       # sample component list
tests/
  test_version_match.py
```

## Tests

```bash
cd /path/to/CVE_scraper
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Fixture-based tests run offline. A few tests optionally use `~/.CVE_scrape/git` when present.
