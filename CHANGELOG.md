# Changelog

## 1.0.1 — 2026-08-25

Maintenance release focused on reversible pseudonymization correctness and archive detection.

- Fixed public IPv4 pseudonym collisions that could silently overwrite reverse mappings and restore the wrong original address.
- Expanded the public IPv4 synthetic namespace to the special-use `198.18.0.0/15` benchmarking range and added deterministic collision probing with fail-closed exhaustion behavior.
- Scoped forward mappings by semantic/namespace so identical raw values transformed in different contexts cannot contaminate each other.
- Added deterministic IP pre-seeding for order-independent allocation during full sanitization runs.
- Added defensive fake→real and original→fake mapping conflict checks.
- Made text restoration non-cascading so restored originals cannot be accidentally transformed again by later mapping replacements.
- Added regression coverage for Issue #2, explicit collision-path coverage, cross-semantic mapping tests, reversed-order allocation tests, and a 1,000-public-IP deterministic round-trip stress test.
- Included the `.tar`, `.tar.gz`, and `.tgz` detection ordering fix contributed in PR #1.

## 1.0.0 — 2026-08-24

Initial public release: local-first discovery, policy-driven sanitization, deterministic keyed transformations, authenticated reversible vaults, residual-risk auditing, utility validation, offline reports, bundle verification, restoration, plugins, and synthetic fixtures.

- Added persistent author attribution to CLI identity, doctor metadata, manifests, HTML/Markdown/JSON reports, and restoration manifests.
- Fixed CSV discovery record counting and semantic scanning.

- Final release hardening: upgraded `cryptography` to the 50.x line after dependency audit findings, corrected bundle-level audit scoping, modernized packaging metadata, completed the Apache-2.0 license text, and aligned documentation with the capabilities actually shipped in v1.0.0.
