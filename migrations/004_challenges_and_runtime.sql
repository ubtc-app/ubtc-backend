-- 004_challenges_and_runtime.sql
--
-- 1. `challenges` — server-issued single-use nonces for the v2 quantum-signed
--    spend flow. Client requests a challenge, signs op||params||nonce with
--    its ML-DSA-65 secret key, submits the signature; server consumes the
--    challenge on verify so the same signature cannot be replayed.
--
-- 2. Consolidate the runtime tables the application has been using since
--    002/003 but which never had migration files. These CREATE IF NOT EXISTS
--    statements are safe on a DB that already has them; on a fresh DB they
--    bring the schema up to what the code expects.

CREATE TABLE IF NOT EXISTS challenges (
    id             TEXT PRIMARY KEY,
    wallet_address TEXT NOT NULL,
    operation      TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    params_hash    TEXT NOT NULL,
    consumed       BOOLEAN NOT NULL DEFAULT false,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_challenges_wallet  ON challenges(wallet_address);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);

-- Runtime tables — code references these but no prior migration created them.
CREATE TABLE IF NOT EXISTS ubtc_users (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT NOT NULL UNIQUE,
    wallet_address TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ubtc_wallets (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    wallet_address  TEXT NOT NULL UNIQUE,
    wallet_name     TEXT,
    public_key      TEXT NOT NULL DEFAULT '',  -- ML-DSA-65 PK (base64)
    sphincs_pk      TEXT NOT NULL DEFAULT '',  -- SPHINCS+-SHAKE-256s-simple PK (hex)
    kyber_pk        TEXT NOT NULL DEFAULT '',  -- ML-KEM-1024 PK (hex)
    balance         TEXT NOT NULL DEFAULT '0',
    uusdt_balance   TEXT NOT NULL DEFAULT '0',
    uusdc_balance   TEXT NOT NULL DEFAULT '0',
    linked_vault_id TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ubtc_wallets ADD COLUMN IF NOT EXISTS sphincs_pk TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS ubtc_proofs (
    id                       TEXT PRIMARY KEY,
    proof_id                 TEXT NOT NULL UNIQUE,
    sender_vault_id          TEXT NOT NULL,
    recipient_wallet_address TEXT NOT NULL,
    proof_data               JSONB NOT NULL,
    downloaded               BOOLEAN NOT NULL DEFAULT false,
    downloaded_at            TIMESTAMPTZ,
    redeemed                 BOOLEAN NOT NULL DEFAULT false,
    redeemed_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nullifiers (
    id            TEXT PRIMARY KEY,
    nullifier_hex TEXT NOT NULL UNIQUE,
    bitcoin_txid  TEXT,
    spent_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ubtc_anchors (
    id             TEXT PRIMARY KEY,
    vault_id       TEXT NOT NULL,
    owner_wallet   TEXT NOT NULL,
    txid           TEXT NOT NULL,
    vout           INTEGER NOT NULL DEFAULT 0,
    amount_sats    BIGINT NOT NULL DEFAULT 546,
    ubtc_amount    DOUBLE PRECISION NOT NULL DEFAULT 0,
    anchor_address TEXT,
    spent          BOOLEAN NOT NULL DEFAULT false,
    spent_txid     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ubtc_transfers (
    id                  TEXT PRIMARY KEY,
    from_vault_id       TEXT NOT NULL,
    to_address          TEXT NOT NULL,
    ubtc_amount         TEXT NOT NULL,
    taproot_placeholder BOOLEAN NOT NULL DEFAULT true,
    status              TEXT NOT NULL DEFAULT 'completed',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
    id               TEXT PRIMARY KEY,
    from_vault_id    TEXT,
    from_user_id     TEXT,
    to_user_id       TEXT,
    amount           TEXT NOT NULL,
    transaction_type TEXT NOT NULL,
    description      TEXT,
    status           TEXT NOT NULL DEFAULT 'completed',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vault_utxos (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL,
    txid        TEXT NOT NULL,
    vout        INTEGER NOT NULL DEFAULT 0,
    amount_sats BIGINT NOT NULL DEFAULT 0,
    spent       BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vault_notifications (
    id         TEXT PRIMARY KEY,
    vault_id   TEXT NOT NULL,
    message    TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'info',
    dismissed  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- transfer_requests is the legacy OTP-driven flow. The v2 spend path uses
-- challenges (above), not stored secret keys. The `pq_signature` column on
-- this table MUST NEVER hold a secret key — the application code that wrote
-- secret keys into it has been removed.
CREATE TABLE IF NOT EXISTS transfer_requests (
    id                  TEXT PRIMARY KEY,
    vault_id            TEXT NOT NULL,
    destination_address TEXT NOT NULL,
    ubtc_amount         TEXT NOT NULL,
    otp_secret          TEXT NOT NULL,
    otp_code            TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    expires_at          TIMESTAMPTZ NOT NULL,
    pq_public_key       TEXT,
    pq_signature        TEXT,
    qrng_entropy        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- v2 schema additions on existing tables (idempotent).
ALTER TABLE vaults
    ADD COLUMN IF NOT EXISTS account_type       TEXT NOT NULL DEFAULT 'current',
    ADD COLUMN IF NOT EXISTS mast_address       TEXT,
    ADD COLUMN IF NOT EXISTS taproot_pubkey     TEXT,
    ADD COLUMN IF NOT EXISTS taproot_secret_key TEXT,
    ADD COLUMN IF NOT EXISTS protocol_key_hash  TEXT;
