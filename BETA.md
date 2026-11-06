# Public beta acceptance

Install the latest published GitHub release following README.md. PyPI installation is not available until ownership and trusted publishing are configured.

## Reproducible baseline

```sh
git clone https://github.com/botchx86/authtrail.git
cd authtrail
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
authtrail examples/scenarios.log --year 2026 --config examples/config.json --strict --compact-json --json beta.json --html beta.html
```

Expected: 44 retained events, eight excluded events, six findings and two investigations. `office` and `slow` should not trigger. Adding `--distributed-window 3600` should include the slow scenario.

## Representative export acceptance

Use read-only exported logs from systems you are authorized to analyze. Do not upload logs or generated evidence reports to public issues. Record:

- Tool/Python version, distribution, OpenSSH version if known, installation method.
- Export format, year and UTC offset assumptions; whether exports cross New Year or daylight-saving changes.
- Total, parsed, ignored, malformed, excluded and duplicate counts per file.
- Whether independently known successes/failures are parsed with correct account, host, IP and timestamp.
- Known benign activity flagged, known suspicious activity missed, exact thresholds and exclusions.
- Runtime, peak memory if measured, and output size.

Redact identifiers locally or create a synthetic reproduction before filing feedback. Never redistribute third-party logs without permission and a compatible license. Preserve originals privately so evidence can be checked.

## Acceptance checklist

Installation, --help and --version succeed outside the checkout; baseline counts match; representative events parse correctly; quality failures are visible; reports open and link evidence to source lines; thresholds are tuned; resource use fits the environment; no sensitive data is posted publicly.

A beta is accepted for a particular deployment only after its owner records these results. Passing synthetic tests is not a universal accuracy claim. Request an independent human review of parser/detection semantics, report safety and this acceptance record before relying on the tool operationally.
