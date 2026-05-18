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
| `our_components` | One component per line for automatic mode (`-a`) |

Copy the sample component list:

```bash
mkdir -p ~/.CVE_scrape
cp examples/our_components ~/.CVE_scrape/our_components
```

### Sample `our_components`

Each line is `product` + optional **stream** suffix (no separator), e.g. `mariadb11.8` → MariaDB on the 11.8 line:

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

Reads `~/.CVE_scrape/our_components` and checks each line (same matching rules as stream entries like `mariadb11.8`):

```bash
./scrape.py -a
./scrape.py -a -n    # no git pull
```

Output uses the same grouping as manual stream queries (product + stream heading, then fix version buckets).

### Other flags

| Flag | Description |
|------|-------------|
| `-g PATH` | CVE git clone location (default: `~/.CVE_scrape/git`) |
| `-u URL` | Clone URL (default: cvelistV5) |
| `-o PATH` | Component list for `-a` (default: `~/.CVE_scrape/our_components`) |
| `-n` / `--no-pull` | Do not clone/pull; repo must already exist |
| `-s` / `-e` | Limit to CVE years under `cves/YYYY/` |

## How it works (short)

1. **Update** the cvelistV5 clone (`git pull`, unless `-n`).
2. **Pre-filter** with `grep` over `cves/<year>/` (fast, text-based).
3. **Parse** JSON: match `containers.cna` / `containers.adp` `affected` data and version ranges.
4. **Print** results in the format above.

## Limitations

These are constraints of the current design, not a roadmap:

- **Grep pre-filter** — Candidate files are chosen by searching raw JSON text for the product/component name. That is fast but not semantically exact; parsing still filters, but grep must see the name somewhere in the file.
- **CVE record quality** — Vendors use different JSON shapes (`lessThan`, `>= x, < y`, bare `version`, descriptions only). Fix versions are inferred from those fields and English description patterns; records without a fix bound appear under `unknown`.
- **Product matching** — `-p` must match a normalized **vendor**, **product**, **packageName**, **CPE** vendor/product, or **PURL** name from the CVE record (not substring search inside long product titles). Use the name that appears in the JSON/CPE (e.g. `postgresql`, not a distro package alias).
- **Version heuristics** — `-v` with three numeric segments is treated as a fix query; one- or two-part values are stream queries. Values like `11.8.0` are fix queries, not stream.
- **Scope** — Manual mode: one `-p` per run. Automatic mode runs the same full grep-and-parse pass for every line in `our_components` each time.
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
examples/
  our_components       # sample component list
tests/
  test_version_match.py
```

## Tests

```bash
python3 -m unittest tests.test_version_match -v
```

Uses local `~/.CVE_scrape/git` when present.
