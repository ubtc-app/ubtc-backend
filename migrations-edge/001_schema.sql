-- Edge replica schema — mirrors runtime tables expected by the binary,
-- plus `tripwire_events` for request telemetry.
--
-- Operator note: this database must live on its own Postgres instance.
-- Sharing credentials with the v2 backend's DB defeats the entire purpose.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS vaults (
    id                  TEXT PRIMARY KEY,
    deposit_address     TEXT NOT NULL,
    user_pubkey         TEXT NOT NULL DEFAULT '',
    internal_key        TEXT NOT NULL DEFAULT '',
    recovery_blocks     INTEGER NOT NULL DEFAULT 144,
    utxo_txid           TEXT,
    utxo_vout           INTEGER,
    btc_amount_sats     BIGINT NOT NULL DEFAULT 0,
    confirmations       INTEGER NOT NULL DEFAULT 0,
    ubtc_minted         TEXT NOT NULL DEFAULT '0',
    status              TEXT NOT NULL DEFAULT 'active',
    network             TEXT NOT NULL DEFAULT 'regtest',
    account_type        TEXT NOT NULL DEFAULT 'current',
    mast_address        TEXT,
    taproot_pubkey      TEXT,
    taproot_secret_key  TEXT,
    protocol_key_hash   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at        TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mints (
    id               TEXT PRIMARY KEY,
    vault_id         TEXT NOT NULL,
    ubtc_amount      TEXT NOT NULL,
    btc_price_usd    TEXT NOT NULL,
    collateral_ratio TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    burned_at        TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS burns (
    id                TEXT PRIMARY KEY,
    vault_id          TEXT NOT NULL,
    ubtc_burned       TEXT NOT NULL,
    btc_released_sats BIGINT,
    spend_txid        TEXT,
    kind              TEXT NOT NULL DEFAULT 'partial',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    public_key      TEXT NOT NULL DEFAULT '',
    kyber_pk        TEXT NOT NULL DEFAULT '',
    balance         TEXT NOT NULL DEFAULT '0',
    uusdt_balance   TEXT NOT NULL DEFAULT '0',
    uusdc_balance   TEXT NOT NULL DEFAULT '0',
    linked_vault_id TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    id             TEXT PRIMARY KEY,
    nullifier_hex  TEXT NOT NULL UNIQUE,
    bitcoin_txid   TEXT,
    spent_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL,
    message     TEXT NOT NULL,
    type        TEXT NOT NULL DEFAULT 'info',
    dismissed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

-- Tripwire telemetry — one row per request hitting the edge replica.
-- The application's main DB role should NOT have SELECT on this table; only
-- the dedicated `tripwire_writer` role does (created in migration 003).
CREATE TABLE IF NOT EXISTS tripwire_events (
    id           TEXT PRIMARY KEY,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    ip           TEXT NOT NULL DEFAULT 'unknown',
    user_agent   TEXT NOT NULL DEFAULT '',
    body         TEXT NOT NULL DEFAULT '',
    signals      JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tw_path    ON tripwire_events(path);
CREATE INDEX IF NOT EXISTS idx_tw_ip      ON tripwire_events(ip);
CREATE INDEX IF NOT EXISTS idx_tw_created ON tripwire_events(created_at DESC);
