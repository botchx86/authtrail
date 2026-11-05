# AuthTrail

An offline Python CLI that turns exported OpenSSH authentication logs into explainable investigation leads. Python 3.10+; no runtime dependencies. Version 0.3.0.

## Try it

From this directory:

```sh
python -m authtrail examples/auth.log --year 2026 --json report.json --html report.html
```

The synthetic example produces three findings, including a successful login after failures. Alice's single failed attempt followed by success does not meet the default account threshold.

Optional installation in a virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate
pip install .
authtrail --help
```

## Analyze your logs

```sh
python -m authtrail /var/log/auth.log.1.gz /var/log/auth.log --year 2026 \
  --timezone=+00:00 --window 300 --failures 5 --users 5 \
  --exclude-source 192.0.2.0/24 --json findings.json --html findings.html
```

Supply explicit paths; shells can expand globs. Reports include original log text, filenames and line numbers. Keep reports protected like the source logs. No network connections are made. Excluded sources are omitted from analysis; the report records the exclusions and counts.

## Detection rules

- **Repeated failures:** five failures against one account from one source on one host within five minutes.
- **Many accounts:** one source attempts five distinct accounts on one host within five minutes. This is a possible enumeration or spraying pattern; SSH logs do not reveal whether the same password was tried.
- **Success after failures:** an accepted login follows five failures for the same account, source, and host within five minutes. Any accepted authentication method qualifies, including a public key.

Thresholds and window are configurable. Events are sorted by UTC timestamp. Evidence windows include events exactly on the boundary. Repeated-failure and many-account findings emit on threshold crossing and rearm when counts drop below the threshold. Successful authentication clears that account's recent failures. Separate rules may share evidence. Findings include the initial threshold window and subsequent failures while the rule remains above its threshold. A burst closes when the rolling count falls below the threshold; an account success also closes its repeated-failure burst. Each finding records `triggered_at`, start/end, event count, failure count, and full evidence. Success-after-failure evidence remains bounded to the correlation window. Many-account evidence contains failures only; successes clear an account’s pending failures but do not appear in that rule’s evidence.

## Supported input and limits

Supports traditional `Nov  1 12:00:00 host sshd[123]: ...` syslog and ISO 8601 timestamp prefixes, with `sshd` or `sshd-session`, with or without a PID. Recognizes OpenSSH `Failed METHOD for [invalid user] USER from IP port ...` and `Accepted METHOD ...` lines, IPv4 and IPv6, plain text and gzip rotations.

Traditional syslog has no year or timezone: `--year` is required, and `--timezone` supplies a fixed offset (UTC by default). Split traditional logs spanning New Year or daylight-saving offset changes into separate runs. ISO timestamps with offsets retain their explicit timezone. Equal timestamps retain input order; coarse timestamps may leave actual event order uncertain.

Unrecognized lines are counted as ignored; recognized SSH Accepted/Failed messages with unsupported structure, invalid timestamps or invalid IPs are counted as malformed. Reports include per-file counts and up to 20 diagnostic locations with reasons. Diagnostic entries omit raw log text. The terminal warns when no usable events remain. Completely unrecognized prefixes are still ignored, so review input quality before relying on a clean report. This version does not ingest journal JSON, Windows events, PAM-only failures, or arbitrary vendor formats. A zero-finding report does not establish that activity is safe or telemetry complete.

Identical timestamp/host/raw-line records are counted once across overlapping inputs. Truly identical records within a file are also collapsed. All parsed events and report evidence are held in memory, so start with bounded exports. This is a triage tool, not a SIEM or proof of compromise. Baseline automation and shared NAT sources before interpreting findings.

Exit codes: `0` completed (with or without findings); `2` input, argument, or output error. Existing report files are overwritten. Input paths cannot be used as report paths.

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests cover correlations, complete burst evidence, rearming after gaps and successes, window boundaries, ordering, host/account isolation, IPv6, timestamp/process variants, malformed records, gzip overlap, exclusions, per-file statistics and HTML escaping.

## v0.2 changes

- Incremental account counts and queues replace repeated scans of the entire active window on each event. Sorting still costs O(n log n); events and full evidence remain in memory.
- Complete failure-burst evidence with separate trigger and end timestamps.
- JSON schema version 2 added finding summaries, per-file statistics and bounded parsing diagnostics.
- Broader OpenSSH prefix support and expanded regression/integration tests.

Windows logs and persistent history remain future work.

## v0.3: distributed rules, configuration and investigations

Run the mixed synthetic scenario:

```sh
python -m authtrail examples/scenarios.log --year 2026 --config examples/config.json \
  --json examples/scenarios-report.json --html examples/scenarios-report.html
```

Two new rules require **both** 10 failed attempts and five distinct source IPs inside five minutes by default:

- `distributed_account`: sources target the same account on the same host.
- `distributed_host`: sources target the same host, across any accounts.

Both retain complete failure bursts and rearm when either rolling threshold drops below its limit. They operate on failures independently of subsequent successes; a successful login does not erase evidence of a distributed campaign. Threshold counts are indicators, not proof of coordination. Shared proxies, NAT gateways and automation require local tuning. Host and account rules can overlap.

JSON configuration uses these optional keys (unknown keys or invalid types are rejected):

| Key | Default | Meaning |
| --- | --- | --- |
| `window` | 300 | Existing per-source rule window, seconds |
| `failures` | 5 | Per-account failure threshold |
| `users` | 5 | Distinct accounts per source |
| `distributed_sources` | 5 | Distinct IPs for distributed rules |
| `distributed_failures` | 10 | Failure count for distributed rules |
| `distributed_window` | 300 | Distributed rule window, seconds |
| `incident_gap` | 300 | Maximum gap when grouping related finding intervals |
| `exclude_source` | [] | IP addresses or CIDRs excluded before detection |
| `exclude_user` | [] | Exact, case-sensitive usernames excluded before detection |

Each key has a corresponding CLI flag with hyphens, e.g. `--distributed-window 3600` or `--exclude-user backup`. Explicit CLI flags override the corresponding saved key; repeated exclusion flags replace that saved list rather than appending to it. Existing CLI commands remain valid. JSON keeps the tool dependency-free on Python 3.10. Configuration currently controls fixed rule thresholds and exclusions, not arbitrary rule expressions or per-rule enable/disable settings.

Example for slower activity:

```sh
python -m authtrail examples/scenarios.log --year 2026 --config examples/config.json \
  --distributed-window 3600 --json slow-report.json
```

Schema version 3 adds `incidents`, with deterministic IDs, finding indexes, severity, sources, accounts, and a timestamp-sorted timeline. Findings on the same host group when their intervals overlap or fall within `incident_gap`, and share a source IP or account. Relationships are transitive. Timelines deduplicate evidence shared by multiple rules. Only detected evidence appears in these timelines; they do not include every benign event on the host. Findings retain their individual evidence and trigger times. Distributed findings use `source_ip: null` and a `source_ips` list.

HTML reports show grouped investigations followed by individual findings, with expandable evidence. Reports use no scripts or external resources.

### Validation scenarios

`examples/scenarios.log` is **synthetic**, with documentation IP ranges and no production data. It includes:

- A legitimate password mistake and successful retry.
- Three users behind shared NAT, each with a mistake followed by success.
- A noisy backup account excluded by the example configuration.
- Multiple sources targeting `deploy`, followed by repeated failures and a successful login.
- Multiple sources trying distinct accounts on another host.
- Slow attempts spread across 27 minutes, detected only with a longer window.

The default example configuration produces findings on `target` and `edge`, grouped into two investigations; `office` and `slow` produce none. Increasing the distributed window to one hour also detects `slow`. This checks known scenario expectations, not a measured production false-positive rate. Sanitized real-world log validation is still needed before claiming operational accuracy.

The suite now has 23 tests, covering distinct-source thresholds, host/account isolation, slow activity, inclusive boundaries, rearming, complete evidence, configuration validation and overrides, grouped timeline deduplication, and benign fixture expectations alongside the earlier tests. Processing still holds input and evidence in memory; grouping many findings may be quadratic in the number of findings.
