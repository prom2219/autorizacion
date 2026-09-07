CREATE TABLE IF NOT EXISTS access_requests (
    request_id UUID PRIMARY KEY,
    installation_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    windows_user TEXT NOT NULL,
    operating_system TEXT NOT NULL,
    app_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDIENTE'
        CHECK (status IN ('PENDIENTE', 'APROBADO', 'EXPIRADO')),
    code_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    action_token_hash TEXT,
    action_expires_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS access_requests_installation_idx
    ON access_requests (installation_id, created_at DESC);

ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS action_token_hash TEXT;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS action_expires_at TIMESTAMPTZ;
ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_status_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_status_check
    CHECK (status IN ('PENDIENTE', 'APROBADO', 'RECHAZADO', 'BLOQUEADO', 'EXPIRADO'));