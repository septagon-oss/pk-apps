CREATE TABLE IF NOT EXISTS poll_polls (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    slug       TEXT NOT NULL,
    title      TEXT NOT NULL,
    options    TEXT NOT NULL,
    author_id  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(slug)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_poll_polls_public_slug
    ON poll_polls(slug);

CREATE INDEX IF NOT EXISTS idx_poll_polls_tenant_created
    ON poll_polls(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS poll_votes (
    poll_id      TEXT NOT NULL REFERENCES poll_polls(id),
    option_index INTEGER NOT NULL,
    voter_id     TEXT NOT NULL,
    PRIMARY KEY (poll_id, voter_id)
);

CREATE INDEX IF NOT EXISTS idx_poll_votes_poll
    ON poll_votes(poll_id);
