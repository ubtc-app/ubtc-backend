CREATE TABLE IF NOT EXISTS burns (
    id                TEXT PRIMARY KEY,
    vault_id          TEXT NOT NULL REFERENCES vaults(id),
    ubtc_burned       TEXT NOT NULL,
    btc_released_sats BIGINT,
    spend_txid        TEXT,
    kind TEXT NOT NULL DEFAULT 'partial'
         CHECK (kind IN ('partial','full')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_burns_vault ON burns(vault_id);