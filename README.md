# AuthTrail

Offline OpenSSH authentication investigation CLI. Python 3.10–3.14, Linux; no runtime dependencies. AuthTrail produces explainable findings and grouped timelines from exported logs. Findings are investigation leads, not proof of compromise.

## Install from the command line

Requires Linux and Python 3.10–3.14. Install the versioned release in an isolated tool environment with [pipx](https://pipx.pypa.io/):

```sh
pipx install https://github.com/botchx86/authtrail/releases/download/v0.4.3/authtrail-0.4.3-py3-none-any.whl
authtrail --version
authtrail --help
```

If `authtrail` is not on your PATH, run `pipx ensurepath` and reopen your terminal.

With [uv](https://docs.astral.sh/uv/), use:

```sh
uv tool install https://github.com/botchx86/authtrail/releases/download/v0.4.3/authtrail-0.4.3-py3-none-any.whl
```

Or use Python's built-in virtual environment support:

```sh
python3 -m venv ~/.venvs/authtrail
~/.venvs/authtrail/bin/python -m pip install https://github.com/botchx86/authtrail/releases/download/v0.4.3/authtrail-0.4.3-py3-none-any.whl
~/.venvs/authtrail/bin/authtrail --help
```

Analyze your exported logs (use the year the events occurred):

```sh
authtrail /path/to/auth.log --year 2026 --strict --compact-json --json report.json --html report.html
```

No root privileges or API keys are needed when you have read access to the exported files. This project is distributed through GitHub Releases; `pip install authtrail` from PyPI is not the documented installation method.

### Download and verify a release

```sh
curl -fLO https://github.com/botchx86/authtrail/releases/download/v0.4.3/authtrail-0.4.3-py3-none-any.whl
curl -fLO https://github.com/botchx86/authtrail/releases/download/v0.4.3/SHA256SUMS
sha256sum --ignore-missing --check SHA256SUMS
pipx install ./authtrail-0.4.3-py3-none-any.whl
```

Checksums detect corrupted downloads; they are not independently signed provenance. The release also includes a source distribution.

### Try the included examples or contribute

```sh
git clone https://github.com/botchx86/authtrail.git
cd authtrail
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
authtrail examples/logs/scenarios.log --year 2026 --config examples/config/config.json \
  --strict --compact-json --json report.json --html report.html
```

For future releases, install the new versioned wheel with `pipx install --force URL` (or `uv tool install --force URL`). Remove with `pipx uninstall authtrail` or `uv tool uninstall authtrail`, matching your installation method.

## Detection

- Repeated failures against one account from one source on one host.
- One source attempting many accounts on one host.
- Success after repeated failures from that source.
- Distributed failures against one account or across accounts on one host.
- Success following distributed failures against the same host/account.

Defaults: five per-account failures or five distinct accounts in 300 seconds. Distributed rules require ten failures and five sources in 300 seconds. Windows are inclusive. Bursts retain subsequent evidence until their rolling counts drop below thresholds. Equal-time successes are processed before failures, and ambiguity is reported; their actual sequence is unknown.

Grouping defaults to shared sources and a 300-second gap, with explicit pairwise relationships. `--group-by account` or `either` broadens grouping. Common accounts or shared infrastructure can join unrelated activity.

## Configuration

JSON keys: `window`, `failures`, `users`, `distributed_sources`, `distributed_failures`, `distributed_window`, `incident_gap`, `exclude_source`, `exclude_user`. Numeric values must be positive integers. Exclusion values are lists of IP/CIDR strings or exact case-sensitive account names. Unknown keys are rejected. CLI flags override individual saved settings; exclusion flags replace the corresponding saved list.

```sh
authtrail examples/logs/scenarios.log --year 2026 --config examples/config/config.json \
  --distributed-window 3600 --group-by source --strict --min-events 10
```

`--strict` rejects malformed authentication records and zero usable events. `--min-events N` sets a minimum usable count. Unsupported prefixes are counted as ignored, so review per-file counts even when strict mode passes. Exit 0 means completed, including findings; exit 2 means argument, input, quality, limit or output failure.

## Input and evidence

Supports traditional syslog and ISO 8601 timestamps, `sshd` and `sshd-session`, IPv4/IPv6, plain text and gzip. Recognizes Failed/Accepted authentication messages. It does not support Windows events, journal JSON or arbitrary PAM-only formats.

Traditional syslog omits year and offset: supply `--year` and `--timezone=+00:00` (UTC default). Split traditional logs across New Year or daylight-saving changes. ISO timestamps retain their offsets. Hostnames are not canonicalized across aliases.

Repeated records in one file are preserved. Overlapping records across files use maximum occurrence count: five copies plus three copies count as five. Independent identical records across files remain ambiguous. Reports retain file and line provenance. Exclusions remove events before all rules.

JSON schema 3 embeds evidence. `--compact-json` selects schema 4 with one event table and ID references. IDs depend on input path, line and raw content and are not stable across relocated exports. HTML is standalone and escapes log text. Reports include effective settings, tool version, quality statistics and diagnostics.

Report aliases to inputs or configuration, including hard links, are rejected. Each report is written to a restricted temporary file and atomically replaced. Two output files are separate transactions; a failed second write can leave a completed first report. Run in directories controlled by the analyst; filesystem checks are not protection against hostile concurrent directory changes.

## Operational limits

This is a bounded offline analyzer, not a streaming service. Default limits are 100,000 retained events and 65,536 encoded bytes per line. Exceeding them aborts without writing reports. Override with `--max-events` and `--max-line-bytes` only after sizing memory. Input, evidence and generated reports remain in memory; compact JSON reduces output duplication, not the full analysis memory footprint. Dense overlapping findings can make incident grouping expensive.

Use read-only exports, an unprivileged account and protected report storage. Start with a small representative export, inspect ignored/malformed counts and exclusions, and compare known cases against findings. No network requests or automatic response actions occur.

## Validation

```sh
python -m unittest discover -s tests -v
python scripts/benchmark.py --events 100000
```

Tests cover core rules, boundaries, isolation, malformed input, compressed files, overlapping exports, same-time ordering, hard links, atomic write failure, quality gates and resource limits. CI tests Python 3.10–3.14 and installs a wheel outside the source directory.

Examples are synthetic, not sanitized production logs. `scenarios.log` covers benign retries, shared NAT, excluded backup automation, distributed attempts, subsequent success and slow attempts. Default example settings yield six findings in two investigations; a one-hour distributed window additionally detects the slow attempts. This is not a measured production false-positive rate.

See `docs/validation.md` for measured checks and remaining deployment acceptance work.

## v0.4.1 hardening

Inputs must be regular UTF-8 files (plain or gzip); invalid encoding fails instead of silently modifying evidence. `--max-input-bytes` limits total decompressed input to 256 MiB by default, including ignored and duplicate lines. Event and line limits still apply separately. FIFOs and other non-regular inputs are rejected.

Incident grouping uses per-entity interval representatives, with only the genuine relationships needed to connect each group. This avoids constructing a quadratic graph for dense overlapping findings. Duplicate JSON configuration keys are rejected to prevent ambiguous settings. The test suite includes independent randomized reference comparisons and injected storage failures.

## Support and contributions

See [docs/support.md](docs/support.md) for supported versions and deployment acceptance, [CONTRIBUTING.md](CONTRIBUTING.md) for local checks and fixture requirements, and [docs/releasing.md](docs/releasing.md) for the release procedure. Bug reports have a structured template. Tagged releases are tested and packaged automatically into a draft for maintainer review.

PyPI publication requires verified project ownership and trusted-publisher setup; installation from the GitHub release remains the documented method. External human review and representative real-world log validation remain open acceptance activities, not completed audits.

See [docs/beta.md](docs/beta.md) for reproducible acceptance checks and privacy-safe feedback.

## Repository layout

```text
src/authtrail/       CLI, parsing, detection, investigation and report modules
tests/               Unit, regression, adversarial and reference tests
docs/                Beta acceptance, support, release and validation guides
examples/logs/       Synthetic OpenSSH input logs
examples/config/     Example rule settings
examples/reports/    Generated sample JSON and HTML reports
scripts/             Developer benchmark tools
.github/             CI, release workflows and contribution templates
```

For development, run `python -m pip install -e .` before invoking the CLI or tests. The `src` layout keeps tests from accidentally importing an uninstalled checkout. Released installation commands above remain versioned; source-checkout commands use the current branch layout.
