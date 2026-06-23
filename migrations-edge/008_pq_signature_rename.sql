-- 008_pq_signature_rename.sql
-- The transfer_requests.pq_signature column was being used to STORE
-- server-generated PQ SECRET keys (mis-named). Backend then signed messages
-- with the stored secret and verified against its own stored public key,
-- which is cryptographic theatre. Rename column so any forgotten reader
-- fails loudly. Existing rows preserved for audit; column dropped after
-- a soak period (see 009_drop_legacy_pq.sql to be added later).

ALTER TABLE transfer_requests
    RENAME COLUMN pq_signature TO _legacy_pq_secret_do_not_read;

COMMENT ON COLUMN transfer_requests._legacy_pq_secret_do_not_read IS
    'DEPRECATED: previously stored server-side PQ secret key. No longer written. To be dropped in a later migration. Do NOT read.';