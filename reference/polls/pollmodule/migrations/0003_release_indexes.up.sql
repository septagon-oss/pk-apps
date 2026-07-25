CREATE INDEX IF NOT EXISTS idx_poll_polls_tenant_status_created
    ON poll_polls(tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_poll_polls_public_status_slug
    ON poll_polls(status, slug);

CREATE INDEX IF NOT EXISTS idx_poll_audit_outbox_pending
    ON poll_audit_outbox(delivered_at, created_at);
