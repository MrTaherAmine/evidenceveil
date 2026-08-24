# Key Management

Default to per-run keys. Reusing a key enables cross-run correlation and should be deliberate. Keep `.evlt` vaults outside sanitized bundles and outside repositories. For production use, obtain passphrases from an approved secret manager or interactive prompt rather than shell history.
