CREATE TABLE IF NOT EXISTS vaults (
    id               TEXT PRIMARY KEY,
    deposit_address  TEXT NOT NULL UNIQUE,
    user_pubkey      TEXT NOT NULL,
    internal_key     TEXT NOT NULL,
    recovery_blocks  INTEGER NOT NULL DEFAULT 144,
    utxo_txid        TEXT,
    utxo_vout        INTEGER,
    btc_amount_sats  BIGINT NOT NULL DEFAULT 0,
    confirmations    INTEGER NOT NULL DEFAULT 0,
    ubtc_minted      TEXT NOT NULL DEFAULT '0',
    status TEXT NOT NULL DEFAULT 'pending_deposit'
           CHECK (status IN ('pending_deposit','active','closed')),
    network      TEXT NOT NULL DEFAULT 'testnet',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,
    closed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_vaults_status  ON vaults(status);
CREATE INDEX IF NOT EXISTS idx_vaults_address ON vaults(deposit_address);