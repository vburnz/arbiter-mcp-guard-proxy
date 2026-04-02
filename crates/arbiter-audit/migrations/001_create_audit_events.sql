-- Searchable audit event storage.
-- Audit logs are write-only today. Teams need to query them for incident
-- response and compliance. This table backs the AuditStore query interface.
CREATE TABLE IF NOT EXISTS audit_events (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at             TEXT    NOT NULL,  -- ISO 8601 timestamp
    request_id              TEXT    NOT NULL,  -- UUID
    agent_id                TEXT    NOT NULL,
    delegation_chain        TEXT    NOT NULL DEFAULT '',
    session_id              TEXT    NOT NULL DEFAULT '',
    tool_called             TEXT    NOT NULL,
    arguments               TEXT    NOT NULL DEFAULT 'null', -- JSON
    authorization_decision  TEXT    NOT NULL,
    policy_matched          TEXT,
    anomaly_flags           TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    latency_ms              INTEGER NOT NULL DEFAULT 0,
    upstream_status         INTEGER,
    -- Hash chain fields (nullable, only present when chain is enabled)
    chain_sequence          INTEGER,
    chain_prev_hash         TEXT,
    chain_record_hash       TEXT
);

-- Indexes for the most common query patterns.
CREATE INDEX IF NOT EXISTS idx_audit_events_recorded_at
    ON audit_events (recorded_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_agent_id
    ON audit_events (agent_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_tool_called
    ON audit_events (tool_called);

CREATE INDEX IF NOT EXISTS idx_audit_events_authorization_decision
    ON audit_events (authorization_decision);

CREATE INDEX IF NOT EXISTS idx_audit_events_session_id
    ON audit_events (session_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_chain_sequence
    ON audit_events (chain_sequence);
