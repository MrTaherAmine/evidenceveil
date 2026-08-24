# Threat Model

EvidenceVeil treats evidence, archives, filenames, free text, policies, and plugins as potential attack surfaces. Controls include safe YAML loading, no `eval`, no shell execution, archive traversal checks, symlink rejection in discovery, bounded archive limits, HTML encoding, terminal escape sanitization helpers, CSV formula neutralization, authenticated vault encryption, Argon2id passphrase KDF, unique AEAD nonces, atomic writes, restricted temporary files where practical, and sensitive-value-free normal CLI output.

Residual risks include untrusted plugins, OS swap/crash dumps, unknown schema extensions, false negatives in detectors, linkage through rare behavior, cross-release correlation, and unsupported binary formats.
