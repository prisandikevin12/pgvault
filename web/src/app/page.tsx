"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertChannel,
  APIConfig,
  Artifact,
  checkHealthWithLatency,
  createTarget,
  CreateTargetInput,
  deleteTarget,
  formatBytes,
  formatInterval,
  formatRelativeTime,
  formatTimestamp,
  HealthStatus,
  Job,
  listAlerts,
  listArtifacts,
  listJobs,
  listTargets,
  resolveDefaultApiBaseUrl,
  Target,
  triggerBackup,
  updateTarget,
  UpdateTargetInput,
  upsertTelegramAlert,
} from "@/lib/api";
import {
  ActivityIcon,
  ArchiveIcon,
  BellIcon,
  CheckIcon,
  CopyIcon,
  DatabaseIcon,
  MenuIcon,
  PlayIcon,
  PlugIcon,
  PlusIcon,
  RefreshIcon,
  SearchIcon,
  ShieldIcon,
  XIcon,
} from "@/components/Icons";
import { ConnectionPopover } from "@/components/ConnectionPopover";
import { TargetDrawer } from "@/components/TargetDrawer";
import { JobInspectorDrawer } from "@/components/JobInspectorDrawer";

const STORAGE_KEY_URL = "pgvault_api_base_url";
const STORAGE_KEY_API_KEY = "pgvault_api_key";

type NavSection = "overview" | "targets" | "artifacts" | "alerts";
type JobStatusFilter = "all" | "succeeded" | "failed" | "queued";

function renderJobStatusBadge(job: Job) {
  const isStaleRecovered =
    job.error_message?.toLowerCase().includes("lease expired") ?? false;

  switch (job.status) {
    case "succeeded":
      return (
        <span className="badge badge-emerald">
          <span className="status-dot dot-emerald" />
          succeeded
        </span>
      );
    case "failed":
      return (
        <span className="badge badge-rose">
          <span className="status-dot dot-rose" />
          failed
        </span>
      );
    case "running":
    case "verifying":
      return (
        <span className="badge badge-amber">
          <span className="status-dot dot-amber" />
          {job.status}
        </span>
      );
    case "queued":
      return (
        <span className="badge badge-amber">
          <span className="status-dot dot-amber" />
          {isStaleRecovered ? "queued · recovered" : "queued"}
        </span>
      );
    default:
      return <span className="badge badge-neutral">{job.status}</span>;
  }
}

export default function ControlPlanePage() {
  const [defaultUrl, setDefaultUrl] = useState("http://127.0.0.1:8080");
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8080");
  const [apiKey, setApiKey] = useState("");
  const [configLoaded, setConfigLoaded] = useState(false);

  const [section, setSection] = useState<NavSection>("overview");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [connOpen, setConnOpen] = useState(false);

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);

  const [targets, setTargets] = useState<Target[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [alerts, setAlerts] = useState<AlertChannel[]>([]);

  // Job table filters
  const [jobStatusFilter, setJobStatusFilter] = useState<JobStatusFilter>("all");
  const [jobTargetFilter, setJobTargetFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Drawers
  const [targetDrawerOpen, setTargetDrawerOpen] = useState(false);
  const [editingTarget, setEditingTarget] = useState<Target | null>(null);
  const [savingTarget, setSavingTarget] = useState(false);
  const [inspectedJobId, setInspectedJobId] = useState<number | null>(null);

  // Copy feedback for artifact hashes
  const [copiedHashId, setCopiedHashId] = useState<number | null>(null);

  // Telegram Alerts form state
  const [alertTargetId, setAlertTargetId] = useState<string>("global");
  const [telegramBotToken, setTelegramBotToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [notifyOnFailure, setNotifyOnFailure] = useState(true);
  const [notifyOnSuccess, setNotifyOnSuccess] = useState(false);
  const [alertEnabled, setAlertEnabled] = useState(true);
  const [savingAlert, setSavingAlert] = useState(false);

  useEffect(() => {
    const resolvedDefault = resolveDefaultApiBaseUrl();
    setDefaultUrl(resolvedDefault);
    const savedUrl = window.localStorage.getItem(STORAGE_KEY_URL);
    const savedKey = window.localStorage.getItem(STORAGE_KEY_API_KEY);
    setBaseUrl(savedUrl && savedUrl.trim() !== "" ? savedUrl : resolvedDefault);
    if (savedKey) setApiKey(savedKey);
    setConfigLoaded(true);
  }, []);

  const apiCfg: APIConfig = useMemo(
    () => ({ baseUrl: baseUrl.trim() || defaultUrl, apiKey }),
    [baseUrl, apiKey, defaultUrl]
  );

  const refreshAll = useCallback(async (cfg: APIConfig) => {
    setLoading(true);
    setErrorBanner(null);
    try {
      const h = await checkHealthWithLatency(cfg);
      setHealth(h);
      if (!h.ok) {
        setErrorBanner(
          `Unable to reach PGVault API at ${cfg.baseUrl}. Open Connection to verify API Base URL.`
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
      setErrorBanner(err instanceof Error ? err.message : "Failed to load control plane state");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (configLoaded) {
      void refreshAll(apiCfg);
    }
  }, [configLoaded]); // eslint-disable-line react-hooks/exhaustive-deps

  const targetById = useMemo(() => {
    const m = new Map<number, Target>();
    for (const t of targets) {
      m.set(t.id, t);
    }
    return m;
  }, [targets]);

  const inspectedJob = useMemo(
    () => (inspectedJobId === null ? null : jobs.find((j) => j.id === inspectedJobId) ?? null),
    [jobs, inspectedJobId]
  );

  const jobCounts = useMemo(() => {
    let succeeded = 0;
    let failed = 0;
    let queued = 0;
    let active = 0;
    for (const j of jobs) {
      if (j.status === "succeeded") succeeded++;
      else if (j.status === "failed") failed++;
      else if (j.status === "queued") queued++;
      else if (j.status === "running" || j.status === "verifying") active++;
    }
    return { all: jobs.length, succeeded, failed, queued, active };
  }, [jobs]);

  const filteredJobs = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return jobs.filter((j) => {
      if (jobStatusFilter === "succeeded" && j.status !== "succeeded") return false;
      if (jobStatusFilter === "failed" && j.status !== "failed") return false;
      if (
        jobStatusFilter === "queued" &&
        j.status !== "queued" &&
        j.status !== "running" &&
        j.status !== "verifying"
      ) {
        return false;
      }
      if (jobTargetFilter !== "all" && String(j.target_id) !== jobTargetFilter) {
        return false;
      }
      if (q !== "") {
        const tName = (targetById.get(j.target_id)?.name ?? "").toLowerCase();
        const key = (j.artifact?.object_key ?? "").toLowerCase();
        const errTxt = (j.error_message ?? "").toLowerCase();
        const idStr = `#${j.id}`;
        if (
          !tName.includes(q) &&
          !key.includes(q) &&
          !errTxt.includes(q) &&
          !idStr.includes(q) &&
          !String(j.id).includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [jobs, jobStatusFilter, jobTargetFilter, searchQuery, targetById]);

  const filteredArtifacts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return artifacts.filter((a) => {
      if (jobTargetFilter !== "all" && String(a.target_id) !== jobTargetFilter) {
        return false;
      }
      if (q !== "") {
        const tName = (targetById.get(a.target_id)?.name ?? "").toLowerCase();
        if (
          !tName.includes(q) &&
          !a.object_key.toLowerCase().includes(q) &&
          !a.ciphertext_sha256.toLowerCase().includes(q) &&
          !String(a.job_id).includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [artifacts, jobTargetFilter, searchQuery, targetById]);

  const verificationMetrics = useMemo(() => {
    const verified = artifacts.filter((a) => a.verification_passed);
    const activeArtifacts = artifacts.filter((a) => !a.pruned_at);
    const prunedArtifacts = artifacts.length - activeArtifacts.length;
    const avgMs =
      verified.length > 0
        ? Math.round(verified.reduce((acc, a) => acc + a.restore_duration_ms, 0) / verified.length)
        : 0;
    const passRate =
      artifacts.length > 0 ? Math.round((verified.length / artifacts.length) * 100) : 0;
    return { verifiedCount: verified.length, activeCount: activeArtifacts.length, prunedCount: prunedArtifacts, avgMs, passRate };
  }, [artifacts]);

  const handleSaveConnection = (nextUrl: string, nextKey: string) => {
    const nextCfg: APIConfig = { baseUrl: nextUrl, apiKey: nextKey };
    setBaseUrl(nextUrl);
    setApiKey(nextKey);
    window.localStorage.setItem(STORAGE_KEY_URL, nextUrl);
    window.localStorage.setItem(STORAGE_KEY_API_KEY, nextKey);
    setSuccessBanner(`Connected API target updated to ${nextUrl}`);
    void refreshAll(nextCfg);
  };

  const handleResetConnection = () => {
    window.localStorage.removeItem(STORAGE_KEY_URL);
    window.localStorage.removeItem(STORAGE_KEY_API_KEY);
    setBaseUrl(defaultUrl);
    setApiKey("");
    setSuccessBanner(`Reset API connection to default (${defaultUrl})`);
    void refreshAll({ baseUrl: defaultUrl, apiKey: "" });
  };

  const openCreateTargetDrawer = () => {
    setEditingTarget(null);
    setTargetDrawerOpen(true);
  };

  const openEditTargetDrawer = (t: Target) => {
    setEditingTarget(t);
    setTargetDrawerOpen(true);
  };

  const handleCreateTarget = async (input: CreateTargetInput) => {
    setSavingTarget(true);
    setErrorBanner(null);
    setSuccessBanner(null);
    try {
      const created = await createTarget(apiCfg, input);
      setTargetDrawerOpen(false);
      setSuccessBanner(`Target "${created.name}" (#${created.id}) created with encrypted credentials.`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : "Failed to create target");
    } finally {
      setSavingTarget(false);
    }
  };

  const handleUpdateTarget = async (id: number, input: UpdateTargetInput) => {
    setSavingTarget(true);
    setErrorBanner(null);
    setSuccessBanner(null);
    try {
      const updated = await updateTarget(apiCfg, id, input);
      setTargetDrawerOpen(false);
      setEditingTarget(null);
      setSuccessBanner(`Target "${updated.name}" updated.`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : "Failed to update target");
    } finally {
      setSavingTarget(false);
    }
  };

  const handleDeleteTarget = async (t: Target) => {
    if (!window.confirm(`Delete target "${t.name}" and its job/artifact records?`)) {
      return;
    }
    setErrorBanner(null);
    setSuccessBanner(null);
    try {
      await deleteTarget(apiCfg, t.id);
      setSuccessBanner(`Deleted target "${t.name}".`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : "Failed to delete target");
    }
  };

  const handleTriggerBackup = async (t: Target) => {
    setErrorBanner(null);
    setSuccessBanner(null);
    try {
      const job = await triggerBackup(apiCfg, t.id);
      setSuccessBanner(`Enqueued Job #${job.id} for "${t.name}" (${job.status}).`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : "Failed to enqueue backup job");
    }
  };

  const handleSaveAlert = async (e: FormEvent) => {
    e.preventDefault();
    setSavingAlert(true);
    setErrorBanner(null);
    setSuccessBanner(null);
    try {
      const saved = await upsertTelegramAlert(apiCfg, {
        target_id: alertTargetId === "global" ? null : Number(alertTargetId),
        bot_token: telegramBotToken,
        chat_id: telegramChatId,
        notify_on_failure: notifyOnFailure,
        notify_on_success: notifyOnSuccess,
        enabled: alertEnabled,
      });
      setTelegramBotToken("");
      setSuccessBanner(`Saved Telegram alert channel #${saved.id} (Chat ${saved.chat_id}).`);
      await refreshAll(apiCfg);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : "Failed to save Telegram alert");
    } finally {
      setSavingAlert(false);
    }
  };

  const copyHash = async (artifact: Artifact) => {
    try {
      await navigator.clipboard.writeText(artifact.ciphertext_sha256);
      setCopiedHashId(artifact.id);
      setTimeout(() => setCopiedHashId((prev) => (prev === artifact.id ? null : prev)), 1600);
    } catch {
      // Clipboard unavailable
    }
  };

  const sectionTitle: Record<NavSection, string> = {
    overview: "Overview & Jobs",
    targets: "Targets",
    artifacts: "Artifacts",
    alerts: "Telegram Alerts",
  };

  const selectSection = (next: NavSection) => {
    setSection(next);
    setMobileNavOpen(false);
  };

  return (
    <div className="shell">
      {/* Mobile Sidebar Backdrop */}
      {mobileNavOpen && (
        <div
          className="popover-backdrop"
          style={{ background: "rgba(0,0,0,0.5)", zIndex: 25 }}
          onClick={() => setMobileNavOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Sidebar (220px) */}
      <aside className={`sidebar ${mobileNavOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-brand">
          <div className="brand-mark">
            <span className="brand-glyph">
              <ShieldIcon />
            </span>
            <span>pgvault</span>
          </div>
          <span className="brand-tag mono">v1</span>
        </div>

        <nav className="sidebar-nav" aria-label="Primary Navigation">
          <div className="sidebar-section-label">Observability</div>
          <button
            type="button"
            className={`nav-item ${section === "overview" ? "active" : ""}`}
            onClick={() => selectSection("overview")}
          >
            <span className="nav-item-left">
              <ActivityIcon />
              Overview &amp; Jobs
            </span>
            <span className="nav-count">{jobs.length}</span>
          </button>

          <button
            type="button"
            className={`nav-item ${section === "targets" ? "active" : ""}`}
            onClick={() => selectSection("targets")}
          >
            <span className="nav-item-left">
              <DatabaseIcon />
              Targets
            </span>
            <span className="nav-count">{targets.length}</span>
          </button>

          <button
            type="button"
            className={`nav-item ${section === "artifacts" ? "active" : ""}`}
            onClick={() => selectSection("artifacts")}
          >
            <span className="nav-item-left">
              <ArchiveIcon />
              Artifacts
            </span>
            <span className="nav-count">{artifacts.length}</span>
          </button>

          <div className="sidebar-section-label" style={{ marginTop: 8 }}>
            Operations
          </div>
          <button
            type="button"
            className={`nav-item ${section === "alerts" ? "active" : ""}`}
            onClick={() => selectSection("alerts")}
          >
            <span className="nav-item-left">
              <BellIcon />
              Alerts
            </span>
            <span className="nav-count">{alerts.filter((a) => a.enabled).length}</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <span>Control Plane Endpoint</span>
          <span className="sidebar-footer-endpoint mono" title={apiCfg.baseUrl}>
            {apiCfg.baseUrl}
          </span>
        </div>
      </aside>

      {/* Main Column */}
      <div className="main-area">
        {/* Top Utility Bar (48px) */}
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="btn btn-ghost btn-icon mobile-menu-btn"
              onClick={() => setMobileNavOpen((v) => !v)}
              aria-label="Toggle navigation"
            >
              <MenuIcon />
            </button>
            <div className="breadcrumb">
              <span className="breadcrumb-ws mono">pgvault</span>
              <span>/</span>
              <span className="breadcrumb-current">{sectionTitle[section]}</span>
            </div>
          </div>

          <div className="topbar-right">
            <div className="health-pill" title={`API endpoint: ${apiCfg.baseUrl}`}>
              <span
                className={`status-dot ${
                  health === null
                    ? "dot-muted"
                    : health.ok
                    ? "dot-emerald"
                    : "dot-rose"
                }`}
              />
              {health === null && <span>Checking</span>}
              {health?.ok && (
                <span className="mono">
                  Online · {health.latencyMs}ms
                </span>
              )}
              {health && !health.ok && <span style={{ color: "var(--rose)" }}>Offline</span>}
            </div>

            <button
              type="button"
              className="btn"
              onClick={() => setConnOpen((v) => !v)}
            >
              <PlugIcon />
              Connection
            </button>

            <button
              type="button"
              className="btn"
              disabled={loading}
              onClick={() => void refreshAll(apiCfg)}
            >
              <RefreshIcon />
              {loading ? "Syncing" : "Refresh"}
            </button>

            <button
              type="button"
              className="btn btn-primary"
              onClick={openCreateTargetDrawer}
            >
              <PlusIcon />
              New Target
            </button>
          </div>
        </header>

        {/* Main Workspace Content */}
        <main className="content">
          {errorBanner && (
            <div className="notice notice-error" role="alert">
              <span>{errorBanner}</span>
              <button
                type="button"
                className="btn btn-ghost btn-icon"
                onClick={() => setErrorBanner(null)}
                aria-label="Dismiss error"
              >
                <XIcon />
              </button>
            </div>
          )}

          {successBanner && (
            <div className="notice notice-success" role="status">
              <span>{successBanner}</span>
              <button
                type="button"
                className="btn btn-ghost btn-icon"
                onClick={() => setSuccessBanner(null)}
                aria-label="Dismiss notification"
              >
                <XIcon />
              </button>
            </div>
          )}

          {/* OVERVIEW & JOBS */}
          {section === "overview" && (
            <>
              <section className="kpi-strip" aria-label="Key Metrics">
                <div className="kpi-cell">
                  <span className="kpi-label">Targets</span>
                  <div className="kpi-row">
                    <span className="kpi-value">{targets.length}</span>
                    <span className="kpi-sub mono">AES-256-GCM</span>
                  </div>
                </div>
                <div className="kpi-cell">
                  <span className="kpi-label">Backup Jobs</span>
                  <div className="kpi-row">
                    <span className="kpi-value">{jobCounts.all}</span>
                    <span className="kpi-sub mono">
                      <span style={{ color: "var(--emerald)" }}>{jobCounts.succeeded} ok</span>
                      {" · "}
                      <span style={{ color: jobCounts.failed > 0 ? "var(--rose)" : "var(--text-muted)" }}>
                        {jobCounts.failed} err
                      </span>
                    </span>
                  </div>
                </div>
                <div className="kpi-cell">
                  <span className="kpi-label">Restore Verification</span>
                  <div className="kpi-row">
                    <span className="kpi-value">
                      {artifacts.length > 0 ? `${verificationMetrics.passRate}%` : "—"}
                    </span>
                    <span className="kpi-sub mono">
                      {verificationMetrics.avgMs > 0 ? `avg ${verificationMetrics.avgMs}ms` : "no runs"}
                    </span>
                  </div>
                </div>
                <div className="kpi-cell">
                  <span className="kpi-label">S3 Artifacts</span>
                  <div className="kpi-row">
                    <span className="kpi-value">{verificationMetrics.activeCount}</span>
                    <span className="kpi-sub mono">{verificationMetrics.prunedCount} pruned</span>
                  </div>
                </div>
              </section>

              <section className="panel">
                <div className="panel-header">
                  <div className="panel-title-group">
                    <h1 className="panel-title">Backup Executions</h1>
                    <span className="panel-subtitle">Click a row to inspect lease, verification, and error logs</span>
                  </div>

                  <div className="toolbar">
                    <div className="segmented" role="tablist" aria-label="Filter jobs by status">
                      {(
                        [
                          ["all", "All", jobCounts.all],
                          ["succeeded", "Succeeded", jobCounts.succeeded],
                          ["failed", "Failed", jobCounts.failed],
                          ["queued", "Queued", jobCounts.queued + jobCounts.active],
                        ] as const
                      ).map(([key, label, count]) => (
                        <button
                          key={key}
                          type="button"
                          role="tab"
                          aria-selected={jobStatusFilter === key}
                          className={`seg-btn ${jobStatusFilter === key ? "active" : ""}`}
                          onClick={() => setJobStatusFilter(key)}
                        >
                          {label}
                          <span className="seg-count">{count}</span>
                        </button>
                      ))}
                    </div>

                    <select
                      className="select-compact"
                      aria-label="Filter by target"
                      value={jobTargetFilter}
                      onChange={(e) => setJobTargetFilter(e.target.value)}
                    >
                      <option value="all">All targets</option>
                      {targets.map((t) => (
                        <option key={t.id} value={String(t.id)}>
                          {t.name}
                        </option>
                      ))}
                    </select>

                    <div className="search-box">
                      <SearchIcon />
                      <input
                        className="search-input"
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Filter #id, target, key, error..."
                      />
                    </div>
                  </div>
                </div>

                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Job</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Restore Verify</th>
                        <th>Attempts</th>
                        <th>Size</th>
                        <th>Run After / Created</th>
                        <th>Diagnostics</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredJobs.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="empty-cell">
                            {jobs.length === 0
                              ? "No backup executions yet. Add a target and click Backup Now."
                              : "No jobs match the current filter."}
                          </td>
                        </tr>
                      ) : (
                        filteredJobs.map((j) => {
                          const targetName =
                            targetById.get(j.target_id)?.name ?? `target-#${j.target_id}`;
                          return (
                            <tr
                              key={j.id}
                              className={`clickable ${inspectedJobId === j.id ? "selected" : ""}`}
                              onClick={() => setInspectedJobId(j.id)}
                            >
                              <td className="mono">#{j.id}</td>
                              <td>
                                <div className="cell-primary">{targetName}</div>
                                {j.locked_by && (
                                  <div className="cell-secondary mono">{j.locked_by}</div>
                                )}
                              </td>
                              <td>{renderJobStatusBadge(j)}</td>
                              <td>
                                {j.artifact ? (
                                  j.artifact.verification_passed ? (
                                    <span className="badge badge-emerald">
                                      Passed · {j.artifact.restore_duration_ms}ms
                                    </span>
                                  ) : (
                                    <span className="badge badge-rose">Failed</span>
                                  )
                                ) : (
                                  <span className="badge badge-neutral">Pending</span>
                                )}
                              </td>
                              <td className="mono">
                                {j.attempts}/{j.max_attempts}
                              </td>
                              <td className="mono">
                                {j.artifact ? formatBytes(j.artifact.ciphertext_bytes) : "—"}
                              </td>
                              <td>
                                <div className="mono">{formatRelativeTime(j.created_at)}</div>
                                <div className="cell-secondary mono">
                                  {formatTimestamp(j.run_after)}
                                </div>
                              </td>
                              <td>
                                {j.error_message ? (
                                  <div
                                    className="mono truncate"
                                    style={{ color: "var(--rose)", maxWidth: 220 }}
                                    title={j.error_message}
                                  >
                                    {j.error_message}
                                  </div>
                                ) : j.artifact?.object_key ? (
                                  <div
                                    className="mono truncate"
                                    style={{ color: "var(--text-muted)", maxWidth: 220 }}
                                    title={j.artifact.object_key}
                                  >
                                    {j.artifact.object_key}
                                  </div>
                                ) : (
                                  <span style={{ color: "var(--text-muted)" }}>—</span>
                                )}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {/* TARGETS */}
          {section === "targets" && (
            <section className="panel">
              <div className="panel-header">
                <div className="panel-title-group">
                  <h1 className="panel-title">Backup Targets</h1>
                  <span className="panel-subtitle mono">{targets.length} configured</span>
                </div>
                <button
                  type="button"
                  className="btn btn-primary btn-xs"
                  onClick={openCreateTargetDrawer}
                >
                  <PlusIcon />
                  New Target
                </button>
              </div>

              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Storage Destination</th>
                      <th>Schedule</th>
                      <th>Retention Policy</th>
                      <th>Sanity Query</th>
                      <th>Credentials</th>
                      <th style={{ textAlign: "right" }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targets.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="empty-cell">
                          No backup targets configured. Click &ldquo;New Target&rdquo; in the top bar to register a PostgreSQL database.
                        </td>
                      </tr>
                    ) : (
                      targets.map((t) => (
                        <tr key={t.id}>
                          <td>
                            <div className="cell-primary">{t.name}</div>
                            <div className="cell-secondary mono">id:{t.id}</div>
                          </td>
                          <td>
                            <div className="mono">
                              s3://{t.storage_bucket}{" "}
                              <span style={{ color: "var(--text-muted)" }}>({t.storage_region})</span>
                            </div>
                            <div className="cell-secondary mono">
                              {t.storage_endpoint || "AWS S3 default endpoint"}
                            </div>
                          </td>
                          <td>
                            <div className="mono">every {formatInterval(t.interval_seconds)}</div>
                            <div className="cell-secondary mono">
                              last: {formatRelativeTime(t.last_scheduled_at)}
                            </div>
                          </td>
                          <td className="mono">
                            <div>
                              keep_last:{" "}
                              <span style={{ color: t.retention_keep_last > 0 ? "var(--text)" : "var(--text-muted)" }}>
                                {t.retention_keep_last > 0 ? t.retention_keep_last : "off"}
                              </span>
                            </div>
                            <div className="cell-secondary">
                              max_age:{" "}
                              <span style={{ color: t.retention_max_age_days > 0 ? "var(--text-secondary)" : "var(--text-muted)" }}>
                                {t.retention_max_age_days > 0 ? `${t.retention_max_age_days}d` : "off"}
                              </span>
                            </div>
                          </td>
                          <td>
                            {t.sanity_query ? (
                              <div className="mono truncate" style={{ maxWidth: 200 }} title={t.sanity_query}>
                                {t.sanity_query}
                              </div>
                            ) : (
                              <span style={{ color: "var(--text-muted)" }}>—</span>
                            )}
                          </td>
                          <td>
                            <div className="actions-inline">
                              <span className="badge badge-emerald">
                                DSN {t.has_target_dsn ? "enc" : "missing"}
                              </span>
                              <span className="badge badge-neutral">
                                S3 {t.has_storage_secret_key ? "enc" : "IAM"}
                              </span>
                            </div>
                          </td>
                          <td style={{ textAlign: "right" }}>
                            <div className="actions-inline">
                              <button
                                type="button"
                                className="btn btn-primary btn-xs"
                                onClick={() => void handleTriggerBackup(t)}
                              >
                                <PlayIcon />
                                Backup Now
                              </button>
                              <button
                                type="button"
                                className="btn btn-xs"
                                onClick={() => openEditTargetDrawer(t)}
                              >
                                Edit
                              </button>
                              <button
                                type="button"
                                className="btn btn-danger btn-xs"
                                onClick={() => void handleDeleteTarget(t)}
                              >
                                Delete
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* ARTIFACTS */}
          {section === "artifacts" && (
            <section className="panel">
              <div className="panel-header">
                <div className="panel-title-group">
                  <h1 className="panel-title">Encrypted Backup Artifacts</h1>
                  <span className="panel-subtitle mono">
                    {verificationMetrics.activeCount} active · {verificationMetrics.prunedCount} pruned
                  </span>
                </div>

                <div className="toolbar">
                  <select
                    className="select-compact"
                    aria-label="Filter artifacts by target"
                    value={jobTargetFilter}
                    onChange={(e) => setJobTargetFilter(e.target.value)}
                  >
                    <option value="all">All targets</option>
                    {targets.map((t) => (
                      <option key={t.id} value={String(t.id)}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                  <div className="search-box">
                    <SearchIcon />
                    <input
                      className="search-input"
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Filter key, sha256, job..."
                    />
                  </div>
                </div>
              </div>

              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Object Key</th>
                      <th>Target / Job</th>
                      <th>PG</th>
                      <th>Plain / Cipher</th>
                      <th>SHA-256</th>
                      <th>Restore Verification</th>
                      <th>Lifecycle</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredArtifacts.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="empty-cell">
                          No backup artifacts recorded yet.
                        </td>
                      </tr>
                    ) : (
                      filteredArtifacts.map((a) => {
                        const targetName =
                          targetById.get(a.target_id)?.name ?? `target-#${a.target_id}`;
                        return (
                          <tr key={a.id}>
                            <td>
                              <div className="mono truncate" style={{ maxWidth: 260 }} title={a.object_key}>
                                {a.object_key}
                              </div>
                              <div className="cell-secondary mono">
                                {formatTimestamp(a.created_at)}
                              </div>
                            </td>
                            <td>
                              <div className="cell-primary">{targetName}</div>
                              <div className="cell-secondary mono">
                                job #{a.job_id} · {a.tables.length} tables
                              </div>
                            </td>
                            <td className="mono">v{a.pg_major_version}</td>
                            <td className="mono">
                              <div>{formatBytes(a.plaintext_bytes)}</div>
                              <div className="cell-secondary">{formatBytes(a.ciphertext_bytes)}</div>
                            </td>
                            <td>
                              <div className="actions-inline">
                                <span className="mono" title={a.ciphertext_sha256}>
                                  {a.ciphertext_sha256.slice(0, 12)}
                                </span>
                                <button
                                  type="button"
                                  className="btn btn-ghost btn-icon"
                                  style={{ height: 22, width: 22 }}
                                  onClick={() => void copyHash(a)}
                                  title="Copy full SHA-256"
                                  aria-label="Copy SHA-256"
                                >
                                  {copiedHashId === a.id ? <CheckIcon /> : <CopyIcon />}
                                </button>
                              </div>
                            </td>
                            <td>
                              {a.verification_passed ? (
                                <span className="badge badge-emerald">
                                  Passed · {a.restore_duration_ms}ms
                                </span>
                              ) : (
                                <span className="badge badge-rose" title={a.verification_error}>
                                  Failed
                                </span>
                              )}
                            </td>
                            <td>
                              {a.pruned_at ? (
                                <span
                                  className="badge badge-neutral"
                                  title={`Pruned at ${formatTimestamp(a.pruned_at)}`}
                                >
                                  Pruned
                                </span>
                              ) : (
                                <span className="badge badge-emerald">Stored</span>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* ALERTS */}
          {section === "alerts" && (
            <div className="alerts-grid">
              <section className="panel">
                <div className="panel-header">
                  <div className="panel-title-group">
                    <h1 className="panel-title">Alert Channels</h1>
                    <span className="panel-subtitle mono">{alerts.length} configured</span>
                  </div>
                </div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Scope</th>
                        <th>Chat ID</th>
                        <th>Triggers</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="empty-cell">
                            No Telegram alert channels configured.
                          </td>
                        </tr>
                      ) : (
                        alerts.map((ch) => (
                          <tr key={ch.id}>
                            <td>
                              <div className="cell-primary">
                                {ch.target_id === null
                                  ? "Global (all targets)"
                                  : targetById.get(ch.target_id)?.name ?? `target-#${ch.target_id}`}
                              </div>
                              <div className="cell-secondary mono">
                                {ch.channel_type} · token {ch.has_bot_token ? "enc" : "missing"}
                              </div>
                            </td>
                            <td className="mono">{ch.chat_id}</td>
                            <td>
                              <div className="actions-inline">
                                {ch.notify_on_failure && (
                                  <span className="badge badge-rose">failure</span>
                                )}
                                {ch.notify_on_success && (
                                  <span className="badge badge-emerald">success</span>
                                )}
                              </div>
                            </td>
                            <td>
                              <span
                                className={`badge ${
                                  ch.enabled ? "badge-emerald" : "badge-neutral"
                                }`}
                              >
                                {ch.enabled ? "enabled" : "disabled"}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="panel">
                <div className="panel-header">
                  <h2 className="panel-title">Configure Telegram Channel</h2>
                </div>
                <form className="popover-body" onSubmit={(e) => void handleSaveAlert(e)}>
                  <div className="field">
                    <label htmlFor="al-scope">Scope</label>
                    <select
                      id="al-scope"
                      className="select"
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
                    <label htmlFor="al-chat">Telegram Chat ID</label>
                    <input
                      id="al-chat"
                      className="input mono"
                      type="text"
                      value={telegramChatId}
                      onChange={(e) => setTelegramChatId(e.target.value)}
                      placeholder="-1001234567890"
                      required
                    />
                  </div>

                  <div className="field">
                    <label htmlFor="al-token">Bot Token</label>
                    <input
                      id="al-token"
                      className="input mono"
                      type="password"
                      value={telegramBotToken}
                      onChange={(e) => setTelegramBotToken(e.target.value)}
                      placeholder="123456789:AA... (blank keeps existing)"
                    />
                    <span className="field-hint">
                      Stored encrypted with KEK; never returned in API responses.
                    </span>
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <label className="checkbox-line">
                      <input
                        type="checkbox"
                        checked={notifyOnFailure}
                        onChange={(e) => setNotifyOnFailure(e.target.checked)}
                      />
                      Notify on backup or verification failure
                    </label>
                    <label className="checkbox-line">
                      <input
                        type="checkbox"
                        checked={notifyOnSuccess}
                        onChange={(e) => setNotifyOnSuccess(e.target.checked)}
                      />
                      Notify on verified success
                    </label>
                    <label className="checkbox-line">
                      <input
                        type="checkbox"
                        checked={alertEnabled}
                        onChange={(e) => setAlertEnabled(e.target.checked)}
                      />
                      Channel enabled
                    </label>
                  </div>

                  <div style={{ display: "flex", justifyContent: "flex-end", paddingTop: 4 }}>
                    <button type="submit" className="btn btn-primary" disabled={savingAlert}>
                      {savingAlert ? "Saving..." : "Save Telegram Alert"}
                    </button>
                  </div>
                </form>
              </section>
            </div>
          )}
        </main>
      </div>

      {/* Connection Settings Popover */}
      <ConnectionPopover
        open={connOpen}
        baseUrl={apiCfg.baseUrl}
        apiKey={apiKey}
        defaultBaseUrl={defaultUrl}
        onClose={() => setConnOpen(false)}
        onSave={handleSaveConnection}
        onReset={handleResetConnection}
      />

      {/* Target Create/Edit Slide-Over Drawer */}
      <TargetDrawer
        open={targetDrawerOpen}
        editingTarget={editingTarget}
        submitting={savingTarget}
        onClose={() => {
          setTargetDrawerOpen(false);
          setEditingTarget(null);
        }}
        onCreate={handleCreateTarget}
        onUpdate={handleUpdateTarget}
      />

      {/* Execution Detail Inspector Drawer */}
      <JobInspectorDrawer
        job={inspectedJob}
        targetName={
          inspectedJob
            ? targetById.get(inspectedJob.target_id)?.name ?? `target-#${inspectedJob.target_id}`
            : ""
        }
        onClose={() => setInspectedJobId(null)}
      />
    </div>
  );
}
