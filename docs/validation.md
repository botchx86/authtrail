# Release validation — 2026-11-05

## Verified locally

- 34 tests passed on CPython 3.10.22, 3.11.18, 3.12.16, 3.13.18 and host Python 3.14.
- Wheel build and clean-environment CLI installation checked.
- Full synthetic 100,000-event analysis with compact JSON: 6.22 seconds, peak child RSS 368,676 KiB, output 53.5 MiB on this development host. This is one workload, not a performance guarantee.
- Regression checks cover input/report hard-link aliases, failed atomic replacement, event and line limits, malformed gzip, conservative tied-event ordering, independent configuration defaults and mutable evidence isolation.
- Example HTML/JSON reports regenerated.

## Deployment acceptance still required

No production logs or target deployment environment were supplied. Before relying on alerts, run a representative read-only export in the intended environment, inspect parsing coverage and exclusions, confirm known benign/attack examples, measure memory and runtime, and tune thresholds. Synthetic tests cannot establish real-world false-positive/false-negative rates.

The supported release scope is bounded offline Linux/OpenSSH analysis. This does not certify streaming operation, adversarial shared-directory safety, Windows/macOS operation or an unlimited log size. Review GitHub Actions for remote CI results on the exact deployed commit.

## Iterative hardening — v0.4.1

- Independent list-based references checked both success rules over 100 deterministic randomized workloads (10,000 events per rule).
- Independent all-pairs graph checked incident grouping across 100 randomized workloads in each of three grouping modes.
- 5,000 random malformed strings exercised the parser.
- Failure injection covers disk full, permission failure and interrupted fsync; existing reports survived and temporary files were removed.
- Dense grouping measurements: 1,000 / 10,000 / 50,000 overlapping findings completed in 0.006 / 0.051 / 0.316 seconds. The interval index stores a spanning forest of genuine finding relationships rather than every redundant edge.
- Added invalid UTF-8, duplicate configuration keys, FIFO rejection and decompressed input budget regressions.
- CI actions updated to verified v6 commit hashes and the runner pinned to Ubuntu 24.04.

These checks improve engineering confidence, but do not substitute for environment-specific detection validation. Randomized seeds are fixed so failures are reproducible.
