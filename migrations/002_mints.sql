CREATE TABLE IF NOT EXISTS mints (
    id               TEXT PRIMARY KEY,
    vault_id         TEXT NOT NULL REFERENCES vaults(id),
    ubtc_amount      TEXT NOT NULL,
    btc_price_usd    TEXT NOT NULL,
    collateral_ratio TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
           CHECK (status IN ('active','burned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    burned_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mints_vault  ON mints(vault_id);
CREATE INDEX IF NOT EXISTS idx_mints_status ON mints(status);