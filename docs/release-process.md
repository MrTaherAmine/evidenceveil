# Release Process

Run tests with branch coverage, Ruff, strict mypy, dependency/security scans, build wheel/sdist, `twine check`, install the wheel in a clean environment, exercise the synthetic end-to-end flow, verify repository fixtures contain only synthetic/reserved indicators, then tag and publish through reviewed GitHub Actions. External publication requires explicit maintainer authorization.
