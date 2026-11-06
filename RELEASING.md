# Releasing

1. Update pyproject.toml and authtrail/__init__.py to the same version.
2. Run supported-version tests and update documentation/validation evidence.
3. Push main and verify CI. Create and push an annotated vVERSION tag on the reviewed commit.
4. The release workflow independently tests all supported runtimes, builds and checks source/wheel metadata, tests the source distribution, installs the wheel outside the checkout and computes SHA256SUMS. It creates a draft GitHub release with those assets.
5. Review the draft, download and verify artifacts, add user-facing notes, then publish it. Existing published releases must not be replaced with different bytes.

## Optional PyPI publication

GitHub Releases remain the supported distribution channel. PyPI publication is not configured and no PyPI ownership is assumed. Before enabling it, verify availability/ownership of the package name, configure a PyPI project and GitHub trusted publisher using a protected environment, and validate on TestPyPI. Never commit API tokens. Update install instructions only after a verified installation from the actual PyPI project succeeds.

Independent review should be performed by a human maintainer other than the author where available. Automated checks are not represented as an independent security audit.

## Prepared trusted-publishing workflow

The manual `pypi.yml` workflow is disabled unless the repository variable `PYPI_ENABLED` equals `true`. It downloads a published release's exact assets, verifies checksums, validates distributions and publishes through OIDC with attestations. No API token is stored.

Before enabling, the PyPI owner must configure a pending/trusted publisher with:

- Project: `authtrail` (check availability again; an absent project does not reserve ownership).
- GitHub owner: `botchx86`; repository: `authtrail`.
- Workflow: `pypi.yml`; environment: `pypi`.

Configure the GitHub `pypi` environment with required maintainer reviewers and restrict deployment to the reviewed default branch. Exercise the equivalent flow on TestPyPI before production publication. Only then enable the variable and manually dispatch with a reviewed published release tag. Do not claim `pipx install authtrail` works until public-index installation is verified.
