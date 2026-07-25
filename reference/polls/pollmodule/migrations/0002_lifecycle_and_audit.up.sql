ALTER TABLE poll_polls ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE poll_polls ADD COLUMN status TEXT NOT NULL DEFAULT 'draft';
ALTER TABLE poll_polls ADD COLUMN closes_at TEXT;
ALTER TABLE poll_polls ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';

UPDATE poll_polls
   SET status = 'published',
       updated_at = created_at
 WHERE updated_at = '';

ALTER TABLE poll_votes ADD COLUMN created_at TEXT NOT NULL DEFAULT '';
ALTER TABLE poll_votes ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';

UPDATE poll_votes
   SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
 WHERE created_at = '';

CREATE TABLE IF NOT EXISTS poll_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS poll_audit_outbox (
    event_id    TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    details     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    delivered_at TEXT
);
