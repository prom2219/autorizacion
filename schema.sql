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
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS access_requests_installation_idx
    ON access_requests (installation_id, created_at DESC);