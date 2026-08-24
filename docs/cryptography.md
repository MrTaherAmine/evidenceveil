# Cryptography Design

EvidenceVeil does not implement custom cryptographic primitives. Deterministic pseudonym material is derived with HMAC-SHA-256 and domain separation. Vault passphrases are transformed with Argon2id. Vault payloads are authenticated and encrypted with ChaCha20-Poly1305 using unique random nonces. The vault stores the master mapping key only inside the authenticated ciphertext and never stores the passphrase.

Python, general-purpose operating systems, and SSDs cannot guarantee secure memory erasure or secure deletion.
