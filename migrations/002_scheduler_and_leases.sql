ALTER TABLE backup_targets
    ADD COLUMN IF NOT EXISTS last_scheduled_at TIMESTAMPTZ NULL;

ALTER TABLE backup_jobs
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_backup_jobs_stale_lease
    ON backup_jobs (lease_expires_at ASC)
    WHERE status IN ('running', 'verifying') AND lease_expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_backup_jobs_target_active
    ON backup_jobs (target_id)
    WHERE status IN ('queued', 'running', 'verifying');
