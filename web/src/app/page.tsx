"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertChannel,
  APIConfig,
  Artifact,
  checkHealth,
  createTarget,
  deleteTarget,
  formatBytes,
  Job,
  listAlerts,
  listArtifacts,
  listJobs,
  listTargets,
  resolveDefaultApiBaseUrl,
  Target,
  triggerBackup,
  upsertTelegramAlert,
} from "@/lib/api";

const STORAGE_KEY_URL = "pgvault_api_base_url";
const STORAGE_KEY_API_KEY = "pgvault_api_key";

type TabKey = "targets" | "jobs" | "alerts";

function jobStatusBadge(status: string): string {
  switch (status) {
    case "succeeded":
      return "badge badge-success";
    case "failed":
      return "badge badge-danger";
    case "running":
    case "verifying":
      return "badge badge-info";
    default:
      return "badge badge-warning";
  }
}

export default function DashboardPage() {
  const [baseUrl, setBaseUrl] = useState(() => resolveDefaultApiBaseUrl());
  const [apiKey, setApiKey] = useState("");
  const [configLoaded, setConfigLoaded] = useState(false);

  const [activeTab, setActiveTab] = useState<TabKey>("targets");
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const [targets, setTargets] = useState<Target[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [alerts, setAlerts] = useState<AlertChannel[]>([]);

  // Create target form state
  const [targetName, setTargetName] = useState("");
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
  const [submittingTarget, setSubmittingTarget] = useState(false);

  // Telegram alert form state
  const [alertTargetId, setAlertTargetId] = useState<string>("global");
  const [telegramBotToken, setTelegramBotToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [notifyOnFailure, setNotifyOnFailure] = useState(true);
  const [notifyOnSuccess, setNotifyOnSuccess] = useState(false);
  const [alertEnabled, setAlertEnabled] = useState(true);
  const [submittingAlert, setSubmittingAlert] = useState(false);

  useEffect(() => {
    const savedUrl = window.localStorage.getItem(STORAGE_KEY_URL);
    const savedKey = window.localStorage.getItem(STORAGE_KEY_API_KEY);
    if (savedUrl && savedUrl.trim() !== "") {
      setBaseUrl(savedUrl);
    } else {
      setBaseUrl(resolveDefaultApiBaseUrl());
    }
    if (savedKey) setApiKey(savedKey);
    setConfigLoaded(true);
  }, []);

  const apiCfg: APIConfig = useMemo(
    () => ({ baseUrl: baseUrl.trim() || resolveDefaultApiBaseUrl(), apiKey }),
    [baseUrl, apiKey]
  );

  const refreshAll = useCallback(
    async (cfg: APIConfig) => {
      setLoading(true);
      setErrorMsg(null);
      try {
        const ok = await checkHealth(cfg);
        setHealthy(ok);
        if (!ok) {
          setErrorMsg(
            `Cannot reach PGVault API at ${cfg.baseUrl}. Check URL and ensure cmd/api is running.`
          );
          return;
        }
        const [t, j, a, al] = await Promise.all([
          listTargets(cfg),
          listJobs(cfg),
          listArtifacts(cfg),
          listAlerts(cfg),
        ]);
        setTargets(t);
        setJobs(j);
        setArtifacts(a);
        setAlerts(al);
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to fetch dashboard data");
      } finally {
        setLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (configLoaded) {
      void refreshAll(apiCfg);
    }
  }, [configLoaded]); // eslint-disable-line react-hooks/exhaustive-deps

  const targetNameById = useMemo(() => {
    const m = new Map<number, string>();
    for (const t of targets) {
      m.set(t.id, t.name);
    }
    return m;
  }, [targets]);

  const verifiedArtifactsCount = useMemo(
    () => artifacts.filter((a) => a.verification_passed).length,
    [artifacts]
  );

  const avgRestoreMs = useMemo(() => {
    const verified = artifacts.filter((a) => a.verification_passed);
    if (verified.length === 0) return 0;
    const sum = verified.reduce((acc, a) => acc + a.restore_duration_ms, 0);
    return Math.round(sum / verified.length);
  }, [artifacts]);

  const handleSaveSettings = (e: FormEvent) => {
    e.preventDefault();
    window.localStorage.setItem(STORAGE_KEY_URL, apiCfg.baseUrl);
    window.localStorage.setItem(STORAGE_KEY_API_KEY, apiCfg.apiKey);
    setSuccessMsg("API connection settings saved in browser localStorage.");
    void refreshAll(apiCfg);
  };

  const handleCreateTarget = async (e: FormEvent) => {
    e.preventDefault();
    setSubmittingTarget(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const created = await createTarget(apiCfg, {
        name: targetName,
        target_dsn: targetDSN,
        storage_endpoint: storageEndpoint,
        storage_region: storageRegion,
        storage_bucket: storageBucket,
        storage_access_key: storageAccessKey,
        storage_secret_key: storageSecretKey,
        storage_force_path_style: forcePathStyle,
        sanity_query: sanityQuery,
        interval_seconds: Number(intervalSeconds) || 86400,
        retention_keep_last: Math.max(0, Number(retentionKeepLast) || 0),
        retention_max_age_days: Math.max(0, Number(retentionMaxAgeDays) || 0),
      });
      setSuccessMsg(`Created target "${created.name}" (#${created.id}). Credentials encrypted at rest.`);
      setTargetName("");
      setTargetDSN("");
      setStorageSecretKey("");
      setSanityQuery("");
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create target");
    } finally {
      setSubmittingTarget(false);
    }
  };

  const handleTriggerBackup = async (target: Target) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const job = await triggerBackup(apiCfg, target.id);
      setSuccessMsg(`Enqueued backup job #${job.id} for "${target.name}" (status: ${job.status}).`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to trigger backup");
    }
  };

  const handleDeleteTarget = async (target: Target) => {
    if (!window.confirm(`Delete backup target "${target.name}" and its history?`)) {
      return;
    }
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      await deleteTarget(apiCfg, target.id);
      setSuccessMsg(`Deleted target "${target.name}".`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to delete target");
    }
  };

  const handleSaveTelegramAlert = async (e: FormEvent) => {
    e.preventDefault();
    setSubmittingAlert(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const saved = await upsertTelegramAlert(apiCfg, {
        target_id: alertTargetId === "global" ? null : Number(alertTargetId),
        bot_token: telegramBotToken,
        chat_id: telegramChatId,
        notify_on_failure: notifyOnFailure,
        notify_on_success: notifyOnSuccess,
        enabled: alertEnabled,
      });
      setSuccessMsg(
        `Saved Telegram alert channel #${saved.id} (Chat ID: ${saved.chat_id}). Bot token stored encrypted.`
      );
      setTelegramBotToken("");
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to save Telegram alert");
    } finally {
      setSubmittingAlert(false);
    }
  };

  return (
    <main className="container">
      <header className="header">
        <div className="brand">
          <h1>PGVault Control Plane</h1>
          <p>Zero-knowledge PostgreSQL backups with automated Docker restore verification</p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          {healthy === true && <span className="badge badge-success">API Connected</span>}
          {healthy === false && <span className="badge badge-danger">API Offline</span>}
          {healthy === null && <span className="badge badge-muted">Checking API...</span>}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            disabled={loading}
            onClick={() => void refreshAll(apiCfg)}
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      {/* Connection Settings */}
      <section className="card">
        <h2>API Connection Settings (localStorage)</h2>
        <form className="form-grid" onSubmit={handleSaveSettings}>
          <div className="field">
            <label htmlFor="api-base-url">API Base URL</label>
            <input
              id="api-base-url"
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.pgvault.example.com"
              required
            />
          </div>
          <div className="field">
            <label htmlFor="api-key">API Key (Bearer / X-API-Key, optional in dev)</label>
            <input
              id="api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="PGVAULT_API_KEY"
            />
          </div>
          <div className="field" style={{ justifyContent: "flex-end" }}>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              Save &amp; Connect
            </button>
          </div>
        </form>
      </section>

      {errorMsg && <div className="banner banner-error">{errorMsg}</div>}
      {successMsg && <div className="banner banner-success">{successMsg}</div>}

      {/* Summary Stats */}
      <section className="grid-4">
        <div className="stat-card">
          <div className="stat-label">Backup Targets</div>
          <div className="stat-value">{targets.length}</div>
          <div className="stat-sub">AES-256-GCM envelope encrypted</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Recent Jobs</div>
          <div className="stat-value">{jobs.length}</div>
          <div className="stat-sub">
            {jobs.filter((j) => j.status === "succeeded").length} succeeded /{" "}
            {jobs.filter((j) => j.status === "failed").length} failed
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Verified Artifacts</div>
          <div className="stat-value">
            {verifiedArtifactsCount} / {artifacts.length}
          </div>
          <div className="stat-sub">
            {avgRestoreMs > 0 ? `Avg restore: ${avgRestoreMs} ms` : "No restore runs yet"}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Telegram Alerts</div>
          <div className="stat-value">
            {alerts.filter((a) => a.enabled).length} active
          </div>
          <div className="stat-sub">{alerts.length} channel(s) configured</div>
        </div>
      </section>

      {/* Tabs */}
      <nav className="tabs">
        <button
          type="button"
          className={`tab-btn ${activeTab === "targets" ? "active" : ""}`}
          onClick={() => setActiveTab("targets")}
        >
          Targets ({targets.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === "jobs" ? "active" : ""}`}
          onClick={() => setActiveTab("jobs")}
        >
          Jobs &amp; Artifacts ({jobs.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === "alerts" ? "active" : ""}`}
          onClick={() => setActiveTab("alerts")}
        >
          Telegram Alerts ({alerts.length})
        </button>
      </nav>

      {/* Targets Tab */}
      {activeTab === "targets" && (
        <>
          <section className="card">
            <h2>Configured Backup Targets</h2>
            {targets.length === 0 ? (
              <div className="empty-state">
                No backup targets configured yet. Create one below to get started.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Storage Destination</th>
                      <th>Sanity Query</th>
                      <th>Schedule</th>
                      <th>Secrets</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map((t) => (
                      <tr key={t.id}>
                        <td>
                          <strong>{t.name}</strong>
                          <div className="mono" style={{ color: "var(--muted)" }}>
                            ID #{t.id}
                          </div>
                        </td>
                        <td>
                          <div className="mono">
                            s3://{t.storage_bucket} ({t.storage_region})
                          </div>
                          {t.storage_endpoint && (
                            <div className="mono" style={{ color: "var(--muted)" }}>
                              {t.storage_endpoint}
                            </div>
                          )}
                        </td>
                        <td className="mono">
                          {t.sanity_query || <span style={{ color: "var(--muted)" }}>None</span>}
                        </td>
                        <td>
                          <div>Every {t.interval_seconds}s</div>
                          <div className="mono" style={{ color: "var(--muted)" }}>
                            Keep: {t.retention_keep_last > 0 ? t.retention_keep_last : "∞"} · MaxAge:{" "}
                            {t.retention_max_age_days > 0 ? `${t.retention_max_age_days}d` : "∞"}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            <span className="badge badge-success">
                              DSN: {t.has_target_dsn ? "Encrypted" : "Missing"}
                            </span>
                            <span className="badge badge-muted">
                              S3 Key: {t.has_storage_secret_key ? "Encrypted" : "Default Chain"}
                            </span>
                          </div>
                        </td>
                        <td>
                          <div className="actions-cell">
                            <button
                              type="button"
                              className="btn btn-primary btn-sm"
                              onClick={() => void handleTriggerBackup(t)}
                            >
                              Backup Now
                            </button>
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => void handleDeleteTarget(t)}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card">
            <h2>Add New Backup Target</h2>
            <form className="form-grid" onSubmit={handleCreateTarget}>
              <div className="field">
                <label htmlFor="target-name">Target Name</label>
                <input
                  id="target-name"
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  placeholder="customer-app-prod"
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="target-dsn">Target PostgreSQL DSN (encrypted at rest)</label>
                <input
                  id="target-dsn"
                  type="password"
                  value={targetDSN}
                  onChange={(e) => setTargetDSN(e.target.value)}
                  placeholder="postgres://user:pass@host:5432/dbname?sslmode=require"
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="storage-endpoint">S3 / R2 Endpoint URL (optional)</label>
                <input
                  id="storage-endpoint"
                  type="text"
                  value={storageEndpoint}
                  onChange={(e) => setStorageEndpoint(e.target.value)}
                  placeholder="https://<account>.r2.cloudflarestorage.com or http://10.0.0.5:4566"
                />
              </div>
              <div className="field">
                <label htmlFor="storage-region">Storage Region</label>
                <input
                  id="storage-region"
                  type="text"
                  value={storageRegion}
                  onChange={(e) => setStorageRegion(e.target.value)}
                  placeholder="us-east-1"
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="storage-bucket">S3 / R2 Bucket</label>
                <input
                  id="storage-bucket"
                  type="text"
                  value={storageBucket}
                  onChange={(e) => setStorageBucket(e.target.value)}
                  placeholder="pgvault-backups"
                  required
                />
              </div>
              <div className="field">
                <label htmlFor="storage-access-key">Access Key ID</label>
                <input
                  id="storage-access-key"
                  type="text"
                  value={storageAccessKey}
                  onChange={(e) => setStorageAccessKey(e.target.value)}
                  placeholder="test"
                />
              </div>
              <div className="field">
                <label htmlFor="storage-secret-key">Secret Access Key (encrypted at rest)</label>
                <input
                  id="storage-secret-key"
                  type="password"
                  value={storageSecretKey}
                  onChange={(e) => setStorageSecretKey(e.target.value)}
                  placeholder="••••••••"
                />
              </div>
              <div className="field">
                <label htmlFor="interval-seconds">Interval (seconds)</label>
                <input
                  id="interval-seconds"
                  type="number"
                  min={60}
                  value={intervalSeconds}
                  onChange={(e) => setIntervalSeconds(Number(e.target.value))}
                />
              </div>
              <div className="field">
                <label htmlFor="retention-keep-last">Retention: Keep Last (0 = off)</label>
                <input
                  id="retention-keep-last"
                  type="number"
                  min={0}
                  value={retentionKeepLast}
                  onChange={(e) => setRetentionKeepLast(Number(e.target.value))}
                />
              </div>
              <div className="field">
                <label htmlFor="retention-max-age-days">Retention: Max Age Days (0 = off)</label>
                <input
                  id="retention-max-age-days"
                  type="number"
                  min={0}
                  value={retentionMaxAgeDays}
                  onChange={(e) => setRetentionMaxAgeDays(Number(e.target.value))}
                />
              </div>
              <div className="field full">
                <label htmlFor="sanity-query">
                  Read-Only Sanity Query (optional, SELECT/WITH only)
                </label>
                <input
                  id="sanity-query"
                  type="text"
                  value={sanityQuery}
                  onChange={(e) => setSanityQuery(e.target.value)}
                  placeholder="SELECT count(*) FROM public.users"
                />
              </div>
              <div className="field full">
                <div className="checkbox-row">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={forcePathStyle}
                      onChange={(e) => setForcePathStyle(e.target.checked)}
                    />
                    Force Path Style (required for LocalStack / MinIO)
                  </label>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={submittingTarget}
                  >
                    {submittingTarget ? "Creating..." : "Create Target"}
                  </button>
                </div>
              </div>
            </form>
          </section>
        </>
      )}

      {/* Jobs & Artifacts Tab */}
      {activeTab === "jobs" && (
        <>
          <section className="card">
            <h2>Backup Jobs</h2>
            {jobs.length === 0 ? (
              <div className="empty-state">
                No backup jobs yet. Trigger a backup from the Targets tab.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Job</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Restore Verification</th>
                      <th>Attempts</th>
                      <th>Created / Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((j) => (
                      <tr key={j.id}>
                        <td className="mono">#{j.id}</td>
                        <td>{targetNameById.get(j.target_id) ?? `Target #${j.target_id}`}</td>
                        <td>
                          <span className={jobStatusBadge(j.status)}>{j.status}</span>
                        </td>
                        <td>
                          {j.artifact ? (
                            j.artifact.verification_passed ? (
                              <span className="badge badge-success">
                                Passed ({j.artifact.restore_duration_ms} ms)
                              </span>
                            ) : (
                              <span className="badge badge-danger">
                                Failed
                                {j.artifact.restore_duration_ms > 0
                                  ? ` (${j.artifact.restore_duration_ms} ms)`
                                  : ""}
                              </span>
                            )
                          ) : (
                            <span className="badge badge-muted">Pending</span>
                          )}
                        </td>
                        <td className="mono">
                          {j.attempts}/{j.max_attempts}
                        </td>
                        <td>
                          <div className="mono" style={{ color: "var(--muted)" }}>
                            {new Date(j.created_at).toLocaleString()}
                          </div>
                          {j.error_message && (
                            <div style={{ color: "#fca5a5", marginTop: 4 }}>
                              {j.error_message}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card">
            <h2>Encrypted Backup Artifacts</h2>
            {artifacts.length === 0 ? (
              <div className="empty-state">No encrypted backup artifacts recorded yet.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Artifact / Object Key</th>
                      <th>PG</th>
                      <th>Size (Plain / Cipher)</th>
                      <th>Tables</th>
                      <th>Verification</th>
                      <th>SHA-256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {artifacts.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <div className="mono">{a.object_key}</div>
                          <div className="mono" style={{ color: "var(--muted)" }}>
                            Job #{a.job_id} ·{" "}
                            {targetNameById.get(a.target_id) ?? `Target #${a.target_id}`}
                          </div>
                        </td>
                        <td className="mono">v{a.pg_major_version}</td>
                        <td className="mono">
                          {formatBytes(a.plaintext_bytes)} / {formatBytes(a.ciphertext_bytes)}
                        </td>
                        <td className="mono">{a.tables.length}</td>
                        <td>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                            {a.verification_passed ? (
                              <span className="badge badge-success">
                                Passed · {a.restore_duration_ms} ms
                              </span>
                            ) : (
                              <span className="badge badge-danger">Failed</span>
                            )}
                            {a.pruned_at && (
                              <span
                                className="badge badge-muted"
                                title={`Pruned at ${new Date(a.pruned_at).toLocaleString()}`}
                              >
                                Pruned
                              </span>
                            )}
                          </div>
                          {!a.verification_passed && a.verification_error && (
                            <div style={{ color: "#fca5a5", marginTop: 4, fontSize: "0.78rem" }}>
                              {a.verification_error}
                            </div>
                          )}
                        </td>
                        <td className="mono" title={a.ciphertext_sha256}>
                          {a.ciphertext_sha256.slice(0, 12)}…
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}

      {/* Telegram Alerts Tab */}
      {activeTab === "alerts" && (
        <>
          <section className="card">
            <h2>Configured Alert Channels</h2>
            {alerts.length === 0 ? (
              <div className="empty-state">No Telegram alert channels configured yet.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Scope</th>
                      <th>Channel</th>
                      <th>Chat ID</th>
                      <th>Triggers</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((ch) => (
                      <tr key={ch.id}>
                        <td>
                          {ch.target_id === null
                            ? "Global (all targets)"
                            : targetNameById.get(ch.target_id) ?? `Target #${ch.target_id}`}
                        </td>
                        <td>
                          <span className="badge badge-info">{ch.channel_type}</span>{" "}
                          <span className="badge badge-success">
                            Token: {ch.has_bot_token ? "Encrypted" : "Missing"}
                          </span>
                        </td>
                        <td className="mono">{ch.chat_id}</td>
                        <td>
                          {ch.notify_on_failure && (
                            <span className="badge badge-danger" style={{ marginRight: 6 }}>
                              On Failure
                            </span>
                          )}
                          {ch.notify_on_success && (
                            <span className="badge badge-success">On Success</span>
                          )}
                        </td>
                        <td>
                          <span
                            className={`badge ${ch.enabled ? "badge-success" : "badge-muted"}`}
                          >
                            {ch.enabled ? "Enabled" : "Disabled"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card">
            <h2>Configure Telegram Alert</h2>
            <form className="form-grid" onSubmit={handleSaveTelegramAlert}>
              <div className="field">
                <label htmlFor="alert-scope">Scope</label>
                <select
                  id="alert-scope"
                  value={alertTargetId}
                  onChange={(e) => setAlertTargetId(e.target.value)}
                >
                  <option value="global">Global (All Targets)</option>
                  {targets.map((t) => (
                    <option key={t.id} value={String(t.id)}>
                      {t.name} (#{t.id})
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="tg-chat-id">Telegram Chat ID</label>
                <input
                  id="tg-chat-id"
                  type="text"
                  value={telegramChatId}
                  onChange={(e) => setTelegramChatId(e.target.value)}
                  placeholder="-1001234567890"
                  required
                />
              </div>
              <div className="field full">
                <label htmlFor="tg-bot-token">
                  Telegram Bot Token (encrypted at rest; leave blank when updating existing channel)
                </label>
                <input
                  id="tg-bot-token"
                  type="password"
                  value={telegramBotToken}
                  onChange={(e) => setTelegramBotToken(e.target.value)}
                  placeholder="123456789:AA..."
                />
              </div>
              <div className="field full">
                <div className="checkbox-row">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={notifyOnFailure}
                      onChange={(e) => setNotifyOnFailure(e.target.checked)}
                    />
                    Notify on Failure
                  </label>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={notifyOnSuccess}
                      onChange={(e) => setNotifyOnSuccess(e.target.checked)}
                    />
                    Notify on Success
                  </label>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={alertEnabled}
                      onChange={(e) => setAlertEnabled(e.target.checked)}
                    />
                    Enabled
                  </label>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={submittingAlert}
                  >
                    {submittingAlert ? "Saving..." : "Save Telegram Alert"}
                  </button>
                </div>
              </div>
            </form>
          </section>
        </>
      )}
    </main>
  );
}
