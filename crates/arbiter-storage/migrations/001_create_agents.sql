-- Agent identity records.
-- REQ-001: Session, identity, and delegation state survives process restart.
CREATE TABLE IF NOT EXISTS agents (
    id          TEXT PRIMARY KEY NOT NULL,  -- UUID as text
    owner       TEXT NOT NULL,
    model       TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '[]', -- JSON array
    trust_level TEXT NOT NULL DEFAULT 'untrusted',
    created_at  TEXT NOT NULL,              -- ISO 8601
    expires_at  TEXT,                       -- ISO 8601, nullable
    active      INTEGER NOT NULL DEFAULT 1  -- boolean
);
