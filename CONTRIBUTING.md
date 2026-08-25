# Contributing

Contributions are welcome, especially bug reports, tests, format improvements, policy improvements, documentation fixes, and carefully scoped security hardening.

## Ground rules

- Use **synthetic fixtures only**.
- Never commit customer logs, production secrets, real incident evidence, `.evlt` vaults, private keys, credentials, or other sensitive material.
- Keep changes focused and avoid unrelated refactors in the same pull request.
- Preserve local-first behavior and secure defaults unless a change is explicitly justified.
- Do not weaken validation, security checks, or error handling simply to make tests pass.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Required checks

Before opening a pull request, run:

```bash
pytest --cov=evidenceveil --cov-branch --cov-report=term-missing
ruff check .
ruff format --check .
mypy src/
python -m pip check
pip-audit
bandit -q -r src/evidenceveil
```

For packaging or release-related changes, also run:

```bash
python -m build
twine check dist/*
```

## Pull requests

A good pull request should include:

- a clear problem statement
- the scope of the change
- tests for new behavior or bug fixes
- any compatibility or security impact
- exact validation results for checks you actually ran

If fixing a bug, link the relevant issue when one exists.

## Security reports

Do not disclose vulnerabilities or sensitive reproduction material in a public issue or pull request. Follow [SECURITY.md](SECURITY.md) instead.
