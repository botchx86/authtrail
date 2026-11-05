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
