# Contributing

Use Linux and Python 3.10–3.14. Clone the repository, create a branch, and run:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Include a regression test for detection, parsing or evidence changes. Explain expected behavior, actual behavior and validation. Preserve original evidence and document changes to report schemas. Keep runtime dependencies minimal. Do not attach sensitive logs: use a minimal synthetic reproduction with documentation IP ranges and invented account names.

Before submitting, check the installed CLI from outside the checkout. CI tests supported Python versions, builds a wheel and runs an installed-package smoke test. A successful test suite does not establish detection accuracy in every environment.

For parser contributions, state the source format and whether fixtures are synthetic or sanitized. Sanitized fixtures require permission to redistribute, provenance, a license and removal of identifying data. Never label synthetic fixtures as production evidence.

Security reports follow SECURITY.md. Contributors should communicate respectfully and provide reproducible evidence for technical claims.
