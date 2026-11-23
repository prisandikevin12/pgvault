CREATE TABLE IF NOT EXISTS backup_targets (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    target_dsn TEXT NOT NULL,
    storage_endpoint TEXT NOT NULL DEFAULT '',
    storage_region TEXT NOT NULL,
    storage_bucket TEXT NOT NULL,
    storage_access_key TEXT NOT NULL DEFAULT '',
    storage_secret_key TEXT NOT NULL DEFAULT '',
    storage_force_path_style BOOLEAN NOT NULL DEFAULT FALSE,
    sanity_query TEXT NOT NULL DEFAULT '',
    schedule_cron TEXT NOT NULL DEFAULT '',
    interval_seconds INTEGER NOT NULL DEFAULT 86400 CHECK (interval_seconds > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS backup_jobs (
    id BIGSERIAL PRIMARY KEY,
    target_id BIGINT NOT NULL REFERENCES backup_targets(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'verifying', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    run_after TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_jobs_queued_run_after
    ON backup_jobs (run_after ASC, id ASC)
    WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS idx_backup_jobs_target_id
    ON backup_jobs (target_id, created_at DESC);

CREATE TABLE IF NOT EXISTS backup_artifacts (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT NOT NULL UNIQUE REFERENCES backup_jobs(id) ON DELETE CASCADE,
    target_id BIGINT NOT NULL REFERENCES backup_targets(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL,
    wrapped_dek BYTEA NOT NULL,
    plaintext_bytes BIGINT NOT NULL,
    ciphertext_bytes BIGINT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    pg_major_version INTEGER NOT NULL,
    tables_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    verification_passed BOOLEAN NOT NULL DEFAULT FALSE,
    restore_duration_ms BIGINT NOT NULL DEFAULT 0,
    verification_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_artifacts_target_id
    ON backup_artifacts (target_id, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_channels (
    id BIGSERIAL PRIMARY KEY,
    target_id BIGINT REFERENCES backup_targets(id) ON DELETE CASCADE,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('telegram')),
    bot_token TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    notify_on_failure BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_success BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_channels_target_enabled
    ON alert_channels (target_id)
    WHERE enabled = TRUE;
