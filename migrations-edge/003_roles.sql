-- Privilege split for tripwire telemetry.
--
-- Two Postgres roles are used by the edge replica:
--
--   `ubtc_edge`     — main app role. Has SELECT/INSERT/UPDATE/DELETE on the
--                     replica tables (vaults, ubtc_wallets, etc). Has NO
--                     SELECT on tripwire_events: even if an attacker pivots
--                     through the app, they cannot read the surveillance log.
--
--   `tripwire_writer` — telemetry role used by the edge process for the
--                     SECOND DB connection (TRIPWIRE_DATABASE_URL). Has
--                     INSERT-only on tripwire_events. Cannot SELECT, UPDATE,
--                     or DELETE.
--
-- For full isolation, point TRIPWIRE_DATABASE_URL at a SEPARATE Postgres
-- instance the application's `ubtc_edge` role cannot reach at all. The
-- role-split below is the in-cluster fallback.

-- The application role used by DATABASE_URL.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ubtc_edge') THEN
        CREATE ROLE ubtc_edge LOGIN PASSWORD 'change_me_at_deploy';
    END IF;
END$$;

GRANT CONNECT ON DATABASE CURRENT_DATABASE() TO ubtc_edge;
GRANT USAGE ON SCHEMA public TO ubtc_edge;

GRANT SELECT, INSERT, UPDATE, DELETE ON
      vaults, mints, burns,
      ubtc_users, ubtc_wallets, ubtc_proofs,
      nullifiers, ubtc_anchors, ubtc_transfers,
      wallet_transactions, vault_utxos, vault_notifications,
      transfer_requests
TO ubtc_edge;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ubtc_edge;

-- Crucially: ubtc_edge has NO privileges on tripwire_events.
REVOKE ALL ON tripwire_events FROM ubtc_edge;

-- Telemetry role used by TRIPWIRE_DATABASE_URL.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tripwire_writer') THEN
        CREATE ROLE tripwire_writer LOGIN PASSWORD 'change_me_at_deploy';
    END IF;
END$$;

GRANT CONNECT ON DATABASE CURRENT_DATABASE() TO tripwire_writer;
GRANT USAGE ON SCHEMA public TO tripwire_writer;
GRANT INSERT ON tripwire_events TO tripwire_writer;
REVOKE SELECT, UPDATE, DELETE ON tripwire_events FROM tripwire_writer;
