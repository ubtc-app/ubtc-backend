-- 007_argon2_recovery.sql
-- Adds per-row salt for Argon2id recovery key hashing.
-- Old SHA-256 hashes remain readable for legacy fallback (NULL salt => legacy).

ALTER TABLE vault_recovery
    ADD COLUMN IF NOT EXISTS recovery_key_salt TEXT,
    ADD COLUMN IF NOT EXISTS hash_algo TEXT NOT NULL DEFAULT 'sha256_legacy';

COMMENT ON COLUMN vault_recovery.recovery_key_salt IS '16-byte random salt, hex-encoded; NULL for legacy SHA-256 rows';
COMMENT ON COLUMN vault_recovery.hash_algo IS 'sha256_legacy | argon2id';