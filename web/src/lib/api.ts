export interface TableSnapshot {
  Schema: string;
  Name: string;
  EstimatedRows: number;
}

export interface Target {
  id: number;
  name: string;
  has_target_dsn: boolean;
  storage_endpoint: string;
  storage_region: string;
  storage_bucket: string;
  storage_access_key: string;
  has_storage_secret_key: boolean;
  storage_force_path_style: boolean;
  sanity_query: string;
  schedule_cron: string;
  interval_seconds: number;
  retention_keep_last: number;
  retention_max_age_days: number;
  last_scheduled_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateTargetInput {
  name: string;
  target_dsn: string;
  storage_endpoint: string;
  storage_region: string;
  storage_bucket: string;
  storage_access_key: string;
  storage_secret_key: string;
  storage_force_path_style: boolean;
  sanity_query: string;
  interval_seconds: number;
  retention_keep_last: number;
  retention_max_age_days: number;
}

export interface UpdateTargetInput {
  name?: string;
  target_dsn?: string;
  storage_endpoint?: string;
  storage_region?: string;
  storage_bucket?: string;
  storage_access_key?: string;
  storage_secret_key?: string;
  storage_force_path_style?: boolean;
  sanity_query?: string;
  interval_seconds?: number;
  retention_keep_last?: number;
  retention_max_age_days?: number;
}

export interface Artifact {
  id: number;
  job_id: number;
  target_id: number;
  object_key: string;
  wrapped_dek_base64?: string;
  plaintext_bytes: number;
  ciphertext_bytes: number;
  ciphertext_sha256: string;
  pg_major_version: number;
  tables: TableSnapshot[];
  verification_passed: boolean;
  restore_duration_ms: number;
  verification_error: string;
  pruned_at?: string;
  created_at: string;
}

export interface Job {
  id: number;
  target_id: number;
  status: "queued" | "running" | "verifying" | "succeeded" | "failed" | string;
  attempts: number;
  max_attempts: number;
  run_after: string;
  locked_at?: string;
  locked_by?: string;
  lease_expires_at?: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
  created_at: string;
  artifact?: Artifact;
}

export interface AlertChannel {
  id: number;
  target_id: number | null;
  channel_type: string;
  has_bot_token: boolean;
  chat_id: string;
  notify_on_failure: boolean;
  notify_on_success: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface UpsertTelegramAlertInput {
  target_id: number | null;
  bot_token: string;
  chat_id: string;
  notify_on_failure: boolean;
  notify_on_success: boolean;
  enabled: boolean;
}

export interface APIConfig {
  baseUrl: string;
  apiKey: string;
}

export interface HealthStatus {
  ok: boolean;
  latencyMs: number;
}

export interface TestConnectionResult {
  ok: boolean;
  latency_ms?: number;
  server_version?: string;
  error?: string;
}

export function resolveDefaultApiBaseUrl(): string {
  const envUrl = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (envUrl) {
    return envUrl.replace(/\/+$/, "");
  }
  if (typeof window !== "undefined") {
    const { hostname, origin } = window.location;
    if (hostname && hostname !== "localhost" && hostname !== "127.0.0.1") {
      return origin.replace(/\/+$/, "");
    }
  }
  return "http://127.0.0.1:8080";
}

export class APIError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "APIError";
    this.status = status;
  }
}

export function resolveDefaultApiKey(): string {
  return (process.env.NEXT_PUBLIC_API_KEY ?? "").trim();
}

async function request<T>(
  cfg: APIConfig,
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (cfg.apiKey.trim() !== "") {
    headers.set("Authorization", `Bearer ${cfg.apiKey.trim()}`);
  }

  const res = await fetch(`${base}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });

  if (res.status === 204) {
    return undefined as T;
  }

  const text = await res.text();
  let parsed: Record<string, unknown> | undefined;
  if (text) {
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      parsed = undefined;
    }
  }

  if (!res.ok) {
    const errMsg =
      (parsed && typeof parsed.error === "string" && parsed.error) ||
      `HTTP ${res.status} ${res.statusText}`;
    throw new APIError(res.status, errMsg);
  }

  return parsed as T;
}

export async function checkHealth(cfg: APIConfig): Promise<boolean> {
  const res = await checkHealthWithLatency(cfg);
  return res.ok;
}

export async function checkHealthWithLatency(cfg: APIConfig): Promise<HealthStatus> {
  const start = typeof performance !== "undefined" ? performance.now() : Date.now();
  try {
    const res = await request<{ status: string }>(cfg, "/healthz");
    const elapsed = Math.max(
      1,
      Math.round((typeof performance !== "undefined" ? performance.now() : Date.now()) - start)
    );
    return { ok: res.status === "ok", latencyMs: elapsed };
  } catch {
    return { ok: false, latencyMs: 0 };
  }
}

export async function listTargets(cfg: APIConfig): Promise<Target[]> {
  const res = await request<{ targets: Target[] }>(cfg, "/api/v1/targets");
  return res.targets ?? [];
}

export async function createTarget(
  cfg: APIConfig,
  input: CreateTargetInput
): Promise<Target> {
  return request<Target>(cfg, "/api/v1/targets", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function updateTarget(
  cfg: APIConfig,
  id: number,
  input: UpdateTargetInput
): Promise<Target> {
  return request<Target>(cfg, `/api/v1/targets/${id}`, {
    method: "PATCH",
    body: JSON.stringify(input),
  });
}

export async function deleteTarget(cfg: APIConfig, id: number): Promise<void> {
  await request<void>(cfg, `/api/v1/targets/${id}`, { method: "DELETE" });
}

export async function triggerBackup(cfg: APIConfig, targetId: number): Promise<Job> {
  return request<Job>(cfg, `/api/v1/targets/${targetId}/backups`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function testTargetConnection(
  cfg: APIConfig,
  input: { dsn?: string; target_id?: number }
): Promise<TestConnectionResult> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const headers = new Headers({ "Content-Type": "application/json" });
  if (cfg.apiKey.trim() !== "") {
    headers.set("Authorization", `Bearer ${cfg.apiKey.trim()}`);
  }
  const res = await fetch(`${base}/api/v1/targets/test-connection`, {
    method: "POST",
    headers,
    body: JSON.stringify(input),
    cache: "no-store",
  });
  const text = await res.text();
  let parsed: TestConnectionResult = { ok: false };
  try {
    parsed = JSON.parse(text) as TestConnectionResult;
  } catch {
    parsed = { ok: false, error: `HTTP ${res.status} ${res.statusText}` };
  }
  if (!res.ok) {
    return {
      ok: false,
      error: parsed.error || `HTTP ${res.status} ${res.statusText}`,
    };
  }
  return parsed;
}

export async function downloadArtifact(
  cfg: APIConfig,
  artifactId: number,
  decrypted: boolean
): Promise<void> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const headers = new Headers();
  if (cfg.apiKey.trim() !== "") {
    headers.set("Authorization", `Bearer ${cfg.apiKey.trim()}`);
  }
  const endpoint = decrypted
    ? `${base}/api/v1/artifacts/${artifactId}/decrypt`
    : `${base}/api/v1/artifacts/${artifactId}/download`;

  const res = await fetch(endpoint, { method: "GET", headers, cache: "no-store" });
  if (!res.ok) {
    const text = await res.text();
    let msg = `HTTP ${res.status} ${res.statusText}`;
    try {
      const parsed = JSON.parse(text) as { error?: string };
      if (parsed.error) msg = parsed.error;
    } catch {
      // ignore non-JSON body
    }
    throw new APIError(res.status, msg);
  }

  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="?([^"]+)"?/i);
  const filename =
    (match && match[1]) ||
    `pgvault-artifact-${artifactId}.${decrypted ? "dump" : "pgv"}`;

  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function listJobs(cfg: APIConfig): Promise<Job[]> {
  const res = await request<{ jobs: Job[] }>(cfg, "/api/v1/jobs?limit=100");
  return res.jobs ?? [];
}

export async function listArtifacts(cfg: APIConfig): Promise<Artifact[]> {
  const res = await request<{ artifacts: Artifact[] }>(
    cfg,
    "/api/v1/artifacts?limit=100"
  );
  return res.artifacts ?? [];
}

export async function listAlerts(cfg: APIConfig): Promise<AlertChannel[]> {
  const res = await request<{ alerts: AlertChannel[] }>(cfg, "/api/v1/alerts");
  return res.alerts ?? [];
}

export async function upsertTelegramAlert(
  cfg: APIConfig,
  input: UpsertTelegramAlertInput
): Promise<AlertChannel> {
  return request<AlertChannel>(cfg, "/api/v1/alerts/telegram", {
    method: "PUT",
    body: JSON.stringify(input),
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx++;
  }
  return `${value.toFixed(1)} ${units[idx]}`;
}

export function formatInterval(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600 && seconds % 60 === 0) return `${seconds / 60}m`;
  if (seconds < 86400 && seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  return `${seconds}s`;
}

export function formatTimestamp(ts?: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

export function formatRelativeTime(ts?: string): string {
  if (!ts) return "never";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const diffSec = Math.round((Date.now() - d.getTime()) / 1000);
  if (Math.abs(diffSec) < 5) return "just now";
  const abs = Math.abs(diffSec);
  const suffix = diffSec >= 0 ? "ago" : "from now";
  if (abs < 60) return `${abs}s ${suffix}`;
  if (abs < 3600) return `${Math.floor(abs / 60)}m ${suffix}`;
  if (abs < 86400) return `${Math.floor(abs / 3600)}h ${suffix}`;
  return `${Math.floor(abs / 86400)}d ${suffix}`;
}
