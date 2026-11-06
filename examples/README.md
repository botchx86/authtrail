# Examples

All logs are synthetic and use documentation IP addresses. Run from the repository root after installation:

```sh
authtrail examples/logs/scenarios.log --year 2026 --config examples/config/config.json --strict --json report.json --html report.html
```

`logs/` contains inputs; `config/` contains settings; `reports/` contains generated sample reports. The reports may show paths from their generation environment; generate fresh reports for current line references. See ../docs/beta.md for expected results.
