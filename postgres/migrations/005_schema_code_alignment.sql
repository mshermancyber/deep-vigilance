-- Aligns the schema with columns/tables the application code actually reads and
-- writes. Without these, container-scan, SBOM-export, binary-scan, webhook
-- dead-lettering, and notification status updates fail at runtime because the
-- INSERT/UPDATE statements reference columns/tables that never existed.

BEGIN;

-- container_scans: code inserts digest, platform, options, severity_score and
-- allows ORDER BY severity_score.
ALTER TABLE container_scans ADD COLUMN IF NOT EXISTS digest VARCHAR(128);
ALTER TABLE container_scans ADD COLUMN IF NOT EXISTS platform VARCHAR(100);
ALTER TABLE container_scans ADD COLUMN IF NOT EXISTS options JSONB DEFAULT '{}'::jsonb;
ALTER TABLE container_scans ADD COLUMN IF NOT EXISTS severity_score INTEGER DEFAULT 0;

-- binary_scans: code inserts name, options, severity_score and allows
-- ORDER BY severity_score.
ALTER TABLE binary_scans ADD COLUMN IF NOT EXISTS name VARCHAR(500);
ALTER TABLE binary_scans ADD COLUMN IF NOT EXISTS options JSONB DEFAULT '{}'::jsonb;
ALTER TABLE binary_scans ADD COLUMN IF NOT EXISTS severity_score INTEGER DEFAULT 0;

-- sbom_exports: code inserts status + include_* flags + options, and the worker
-- (not the API request) populates file_path later, so it must be nullable.
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS status VARCHAR(30) NOT NULL DEFAULT 'queued';
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS include_vulnerabilities BOOLEAN DEFAULT TRUE;
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS include_licenses BOOLEAN DEFAULT TRUE;
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS include_metadata BOOLEAN DEFAULT TRUE;
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS options JSONB DEFAULT '{}'::jsonb;
ALTER TABLE sbom_exports ADD COLUMN IF NOT EXISTS sbom_content JSONB;
ALTER TABLE sbom_exports ALTER COLUMN file_path DROP NOT NULL;

-- webhook_dead_letters: written by webhook-service when a webhook exhausts retries.
CREATE TABLE IF NOT EXISTS webhook_dead_letters (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhook_dead_letters_webhook ON webhook_dead_letters(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_dead_letters_org ON webhook_dead_letters(org_id);

-- notifications: the notification worker updates delivery status by id.
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY,
    org_id UUID REFERENCES organizations(id),
    channel VARCHAR(30),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    sent_at TIMESTAMPTZ,
    response_status INTEGER,
    response_body TEXT,
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications(org_id);

COMMIT;
