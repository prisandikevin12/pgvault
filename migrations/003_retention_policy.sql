ALTER TABLE backup_targets
    ADD COLUMN IF NOT EXISTS retention_keep_last INTEGER NOT NULL DEFAULT 0 CHECK (retention_keep_last >= 0),
    ADD COLUMN IF NOT EXISTS retention_max_age_days INTEGER NOT NULL DEFAULT 0 CHECK (retention_max_age_days >= 0);

ALTER TABLE backup_artifacts
    ADD COLUMN IF NOT EXISTS pruned_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_backup_artifacts_unpruned_target
    ON backup_artifacts (target_id, created_at DESC, id DESC)
    WHERE pruned_at IS NULL;
