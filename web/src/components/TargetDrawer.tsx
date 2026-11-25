"use client";

import { FormEvent, useEffect, useState } from "react";
import { CreateTargetInput, Target, UpdateTargetInput } from "@/lib/api";
import { XIcon } from "@/components/Icons";

interface TargetDrawerProps {
  open: boolean;
  editingTarget: Target | null;
  submitting: boolean;
  onClose: () => void;
  onCreate: (input: CreateTargetInput) => Promise<void>;
  onUpdate: (id: number, input: UpdateTargetInput) => Promise<void>;
}

export function TargetDrawer({
  open,
  editingTarget,
  submitting,
  onClose,
  onCreate,
  onUpdate,
}: TargetDrawerProps) {
  const isEdit = editingTarget !== null;

  const [name, setName] = useState("");
  const [targetDSN, setTargetDSN] = useState("");
  const [storageEndpoint, setStorageEndpoint] = useState("");
  const [storageRegion, setStorageRegion] = useState("us-east-1");
  const [storageBucket, setStorageBucket] = useState("");
  const [storageAccessKey, setStorageAccessKey] = useState("");
  const [storageSecretKey, setStorageSecretKey] = useState("");
  const [forcePathStyle, setForcePathStyle] = useState(false);
  const [intervalSeconds, setIntervalSeconds] = useState(86400);
  const [retentionKeepLast, setRetentionKeepLast] = useState(7);
  const [retentionMaxAgeDays, setRetentionMaxAgeDays] = useState(30);
  const [sanityQuery, setSanityQuery] = useState("");

  useEffect(() => {
    if (!open) return;
    if (editingTarget) {
      setName(editingTarget.name);
      setTargetDSN("");
      setStorageEndpoint(editingTarget.storage_endpoint);
      setStorageRegion(editingTarget.storage_region);
      setStorageBucket(editingTarget.storage_bucket);
      setStorageAccessKey(editingTarget.storage_access_key);
      setStorageSecretKey("");
      setForcePathStyle(editingTarget.storage_force_path_style);
      setIntervalSeconds(editingTarget.interval_seconds);
      setRetentionKeepLast(editingTarget.retention_keep_last);
      setRetentionMaxAgeDays(editingTarget.retention_max_age_days);
      setSanityQuery(editingTarget.sanity_query);
    } else {
      setName("");
      setTargetDSN("");
      setStorageEndpoint("");
      setStorageRegion("us-east-1");
      setStorageBucket("");
      setStorageAccessKey("");
      setStorageSecretKey("");
      setForcePathStyle(false);
      setIntervalSeconds(86400);
      setRetentionKeepLast(7);
      setRetentionMaxAgeDays(30);
      setSanityQuery("");
    }
  }, [open, editingTarget]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (isEdit && editingTarget) {
      const payload: UpdateTargetInput = {
        name: name.trim(),
        storage_endpoint: storageEndpoint.trim(),
        storage_region: storageRegion.trim(),
        storage_bucket: storageBucket.trim(),
        storage_access_key: storageAccessKey.trim(),
        storage_force_path_style: forcePathStyle,
        sanity_query: sanityQuery.trim(),
        interval_seconds: Math.max(1, Number(intervalSeconds) || 86400),
        retention_keep_last: Math.max(0, Number(retentionKeepLast) || 0),
        retention_max_age_days: Math.max(0, Number(retentionMaxAgeDays) || 0),
      };
      if (targetDSN.trim() !== "") {
        payload.target_dsn = targetDSN.trim();
      }
      if (storageSecretKey.trim() !== "") {
        payload.storage_secret_key = storageSecretKey.trim();
      }
      await onUpdate(editingTarget.id, payload);
    } else {
      await onCreate({
        name: name.trim(),
        target_dsn: targetDSN.trim(),
        storage_endpoint: storageEndpoint.trim(),
        storage_region: storageRegion.trim(),
        storage_bucket: storageBucket.trim(),
        storage_access_key: storageAccessKey.trim(),
        storage_secret_key: storageSecretKey.trim(),
        storage_force_path_style: forcePathStyle,
        sanity_query: sanityQuery.trim(),
        interval_seconds: Math.max(1, Number(intervalSeconds) || 86400),
        retention_keep_last: Math.max(0, Number(retentionKeepLast) || 0),
        retention_max_age_days: Math.max(0, Number(retentionMaxAgeDays) || 0),
      });
    }
  };

  return (
    <div
      className="drawer-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <aside className="drawer" role="dialog" aria-label={isEdit ? "Edit Backup Target" : "New Backup Target"}>
        <div className="drawer-header">
          <div>
            <h2 className="drawer-title">
              {isEdit ? `Edit Target · ${editingTarget.name}` : "New Backup Target"}
            </h2>
            <div className="drawer-subtitle">
              Credentials are envelope-encrypted at rest with KEK before storage.
            </div>
          </div>
          <button type="button" className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close">
            <XIcon />
          </button>
        </div>

        <form id="target-drawer-form" className="drawer-body" onSubmit={(e) => void handleSubmit(e)}>
          <div className="form-section">
            <div className="form-section-title">Target Database</div>
            <div className="field">
              <label htmlFor="td-name">Target Name</label>
              <input
                id="td-name"
                className="input"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="prod-customer-db"
                required
              />
            </div>
            <div className="field">
              <label htmlFor="td-dsn">PostgreSQL DSN</label>
              <input
                id="td-dsn"
                className="input mono"
                type="password"
                value={targetDSN}
                onChange={(e) => setTargetDSN(e.target.value)}
                placeholder={
                  isEdit
                    ? "Leave blank to preserve existing encrypted DSN"
                    : "postgres://user:pass@db.example.com:5432/app?sslmode=require"
                }
                required={!isEdit}
              />
            </div>
          </div>

          <div className="form-section">
            <div className="form-section-title">Object Storage (S3 / R2 / MinIO)</div>
            <div className="form-row-2">
              <div className="field">
                <label htmlFor="td-bucket">Bucket</label>
                <input
                  id="td-bucket"
                  className="input mono"
                  type="text"
                  value={storageBucket}
                  onChange={(e) => setStorageBucket(e.target.value)}
                  placeholder="pgvault-backups"
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="td-region">Region</label>
                <input
                  id="td-region"
                  className="input mono"
                  type="text"
                  value={storageRegion}
                  onChange={(e) => setStorageRegion(e.target.value)}
                  placeholder="us-east-1 or auto"
                  required
                />
              </div>
            </div>

            <div className="field">
              <label htmlFor="td-endpoint">Custom Endpoint URL (optional)</label>
              <input
                id="td-endpoint"
                className="input mono"
                type="text"
                value={storageEndpoint}
                onChange={(e) => setStorageEndpoint(e.target.value)}
                placeholder="https://<account>.r2.cloudflarestorage.com"
              />
            </div>

            <div className="form-row-2">
              <div className="field">
                <label htmlFor="td-access">Access Key ID</label>
                <input
                  id="td-access"
                  className="input mono"
                  type="text"
                  value={storageAccessKey}
                  onChange={(e) => setStorageAccessKey(e.target.value)}
                  placeholder="Optional for IAM role"
                />
              </div>
              <div className="field">
                <label htmlFor="td-secret">Secret Access Key</label>
                <input
                  id="td-secret"
                  className="input mono"
                  type="password"
                  value={storageSecretKey}
                  onChange={(e) => setStorageSecretKey(e.target.value)}
                  placeholder={isEdit ? "Leave blank to keep secret" : "••••••••"}
                />
              </div>
            </div>

            <label className="checkbox-line">
              <input
                type="checkbox"
                checked={forcePathStyle}
                onChange={(e) => setForcePathStyle(e.target.checked)}
              />
              Force Path-Style Addressing (enable for LocalStack / MinIO)
            </label>
          </div>

          <div className="form-section">
            <div className="form-section-title">Schedule &amp; Retention Policy</div>
            <div className="field">
              <label htmlFor="td-interval">Schedule Interval (seconds)</label>
              <input
                id="td-interval"
                className="input mono"
                type="number"
                min={60}
                value={intervalSeconds}
                onChange={(e) => setIntervalSeconds(Number(e.target.value))}
                required
              />
              <span className="field-hint">86400 = daily, 3600 = hourly, 600 = every 10m</span>
            </div>
            <div className="form-row-2">
              <div className="field">
                <label htmlFor="td-keep-last">Keep Last (0 = disabled)</label>
                <input
                  id="td-keep-last"
                  className="input mono"
                  type="number"
                  min={0}
                  value={retentionKeepLast}
                  onChange={(e) => setRetentionKeepLast(Number(e.target.value))}
                />
              </div>
              <div className="field">
                <label htmlFor="td-max-age">Max Age Days (0 = disabled)</label>
                <input
                  id="td-max-age"
                  className="input mono"
                  type="number"
                  min={0}
                  value={retentionMaxAgeDays}
                  onChange={(e) => setRetentionMaxAgeDays(Number(e.target.value))}
                />
              </div>
            </div>
          </div>

          <div className="form-section">
            <div className="form-section-title">Restore Verification</div>
            <div className="field">
              <label htmlFor="td-sanity">Read-Only Sanity Query (optional)</label>
              <textarea
                id="td-sanity"
                className="textarea mono"
                rows={2}
                value={sanityQuery}
                onChange={(e) => setSanityQuery(e.target.value)}
                placeholder="SELECT count(*) FROM public.users"
              />
              <span className="field-hint">
                Executed in BEGIN READ ONLY with 5s statement_timeout inside isolated NetworkMode=none container.
              </span>
            </div>
          </div>
        </form>

        <div className="drawer-footer">
          <button type="button" className="btn" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button
            type="submit"
            form="target-drawer-form"
            className="btn btn-primary"
            disabled={submitting}
          >
            {submitting ? "Saving..." : isEdit ? "Save Changes" : "Create Target"}
          </button>
        </div>
      </aside>
    </div>
  );
}
