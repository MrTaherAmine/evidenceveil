# Changelog

## 1.0.1 — Unreleased

- Fixed reversible IPv4 pseudonymization collisions by expanding public-IP synthetic space and adding deterministic collision resolution so distinct originals cannot silently converge.
- Added fail-closed mapping integrity guards to prevent fake→real overwrite conflicts in transformation mappings.
- Included archive detection hardening from PR #1 for `.tar`, `.tar.gz`, and `.tgz` inputs.

## 1.0.0 — 2026-08-24

Initial public release: local-first discovery, policy-driven sanitization, deterministic keyed transformations, authenticated reversible vaults, residual-risk auditing, utility validation, offline reports, bundle verification, restoration, plugins, synthetic fixtures, and CI.

- Added persistent author attribution to CLI identity, doctor metadata, manifests, HTML/Markdown/JSON reports, and restoration manifests.
- Fixed CSV discovery record counting and semantic scanning.

- Final release hardening: upgraded `cryptography` to the 50.x line after dependency audit findings, corrected bundle-level audit scoping, modernized packaging metadata, completed the Apache-2.0 license text, and aligned documentation with the capabilities actually shipped in v1.0.0.
