-- Task session records.
-- REQ-001: Session state survives process restart.
CREATE TABLE IF NOT EXISTS sessions (
    session_id              TEXT PRIMARY KEY NOT NULL,  -- UUID as text
    agent_id                TEXT NOT NULL,
    delegation_chain_snapshot TEXT NOT NULL DEFAULT '[]', -- JSON array
    declared_intent         TEXT NOT NULL,
    authorized_tools        TEXT NOT NULL DEFAULT '[]', -- JSON array
    time_limit_secs         INTEGER NOT NULL,
    call_budget             INTEGER NOT NULL,
    calls_made              INTEGER NOT NULL DEFAULT 0,
    rate_limit_per_minute   INTEGER,                    -- nullable
    rate_window_start       TEXT NOT NULL,               -- ISO 8601
    rate_window_calls       INTEGER NOT NULL DEFAULT 0,
    rate_limit_window_secs  INTEGER NOT NULL DEFAULT 60,
    data_sensitivity_ceiling TEXT NOT NULL DEFAULT 'public',
    created_at              TEXT NOT NULL,                -- ISO 8601
    status                  TEXT NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_sessions_agent_id ON sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
