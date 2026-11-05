# AuthTrail

Offline OpenSSH authentication investigation CLI. Python 3.10–3.14, Linux; no runtime dependencies. AuthTrail produces explainable findings and grouped timelines from exported logs. Findings are investigation leads, not proof of compromise.

## Install and run

```sh
python -m venv .venv
. .venv/bin/activate
pip install .
authtrail examples/scenarios.log --year 2026 --config examples/config.json \
  --strict --compact-json --json report.json --html report.html
```

From a source checkout, `python -m authtrail` also works. `authtrail --help` lists options.

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
authtrail examples/scenarios.log --year 2026 --config examples/config.json \
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

See `VALIDATION.md` for measured checks and remaining deployment acceptance work.

## v0.4.1 hardening

Inputs must be regular UTF-8 files (plain or gzip); invalid encoding fails instead of silently modifying evidence. `--max-input-bytes` limits total decompressed input to 256 MiB by default, including ignored and duplicate lines. Event and line limits still apply separately. FIFOs and other non-regular inputs are rejected.

Incident grouping uses per-entity interval representatives, with only the genuine relationships needed to connect each group. This avoids constructing a quadratic graph for dense overlapping findings. Duplicate JSON configuration keys are rejected to prevent ambiguous settings. The test suite includes independent randomized reference comparisons and injected storage failures.
