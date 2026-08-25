# Security Policy

EvidenceVeil processes untrusted security evidence, so security and data-integrity reports are treated seriously.

## Supported versions

| Version | Security support |
|---|---|
| 1.0.x | Supported |
| < 1.0.0 | Not supported |

Users should run the latest available 1.0.x maintenance release.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for suspected vulnerabilities, exploit details, sensitive evidence, credentials, vault material, or reproduction data that could expose a real environment.

Report security concerns privately to:

- **Taher Amine ELHOUARI**
- **Email:** contact@taheramine.org
- **Website:** https://www.taheramine.org

Include, where possible:

- affected EvidenceVeil version
- operating system and Python version
- a concise impact description
- minimal reproduction steps using **synthetic data only**
- whether the issue affects confidentiality, integrity, restoration correctness, file handling, cryptography, or command execution

Do not attach real incident evidence, customer logs, credentials, private keys, production tokens, or `.evlt` vaults.

## Security-sensitive areas

Examples of issues that should be reported privately include:

- sanitization bypasses that expose original sensitive values
- reversible-mapping corruption or incorrect restoration
- vault confidentiality or integrity failures
- path traversal, unsafe archive extraction, or symlink bypasses
- unexpected command or code execution
- unsafe handling of secrets or temporary files
- cryptographic misuse that materially weakens the documented security model
- dependency vulnerabilities with a credible impact on EvidenceVeil

## Safe testing

Use synthetic fixtures and isolated test environments. Never test a vulnerability report with real customer evidence in a public issue or public pull request.

EvidenceVeil is designed to operate locally. The project does not intentionally perform network requests during sanitization, discovery, auditing, restoration, or reporting.

## Disclosure

Please allow reasonable time for investigation, remediation, regression testing, and release preparation before public disclosure. Confirmed issues may be credited in release notes unless the reporter requests otherwise.
