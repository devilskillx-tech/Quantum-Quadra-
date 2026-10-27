-- ENCRYPTED CORE: no payload JSONB, indexes or plaintext search here.
CREATE TABLE IF NOT EXISTS quadra_scope_keys(
    scope_id uuid NOT NULL, version integer NOT NULL,
    wrapped_dek bytea NOT NULL, PRIMARY KEY(scope_id,version)
);
CREATE TABLE IF NOT EXISTS quadra_core_cells(
    cell_id uuid PRIMARY KEY, scope_id uuid NOT NULL,
    memory_kind text NOT NULL, logical_key text NOT NULL,
    creator_type text NOT NULL, status text NOT NULL,
    key_version integer NOT NULL, revision integer NOT NULL,
    payload_sha256 char(64) NOT NULL, encrypted_payload bytea NOT NULL,
    importance double precision NOT NULL DEFAULT 0.5,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS quadra_core_scopes ON quadra_core_cells(scope_id, status);
CREATE TABLE IF NOT EXISTS quadra_sync_receipts(
    event_id uuid PRIMARY KEY, cell_id uuid NOT NULL, scope_id uuid NOT NULL,
    revision integer NOT NULL, acknowledged_at timestamptz NOT NULL DEFAULT now()
);
