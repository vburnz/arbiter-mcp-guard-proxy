-- Delegation chain links.
-- REQ-001: Delegation state survives process restart.
CREATE TABLE IF NOT EXISTS delegation_links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    from_agent      TEXT NOT NULL,      -- UUID as text
    to_agent        TEXT NOT NULL,      -- UUID as text
    scope_narrowing TEXT NOT NULL DEFAULT '[]', -- JSON array
    created_at      TEXT NOT NULL,      -- ISO 8601
    expires_at      TEXT               -- ISO 8601, nullable
);

CREATE INDEX IF NOT EXISTS idx_delegation_from ON delegation_links(from_agent);
CREATE INDEX IF NOT EXISTS idx_delegation_to ON delegation_links(to_agent);
