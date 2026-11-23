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
}

export interface Artifact {
  id: number;
  job_id: number;
  target_id: number;
  object_key: string;
  plaintext_bytes: number;
  ciphertext_bytes: number;
  ciphertext_sha256: string;
  pg_major_version: number;
  tables: TableSnapshot[];
  verification_passed: boolean;
  restore_duration_ms: number;
  verification_error: string;
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
    throw new Error(errMsg);
  }

  return parsed as T;
}

export async function checkHealth(cfg: APIConfig): Promise<boolean> {
  try {
    const res = await request<{ status: string }>(cfg, "/healthz");
    return res.status === "ok";
  } catch {
    return false;
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

export async function deleteTarget(cfg: APIConfig, id: number): Promise<void> {
  await request<void>(cfg, `/api/v1/targets/${id}`, { method: "DELETE" });
}

export async function triggerBackup(cfg: APIConfig, targetId: number): Promise<Job> {
  return request<Job>(cfg, `/api/v1/targets/${targetId}/backups`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function listJobs(cfg: APIConfig): Promise<Job[]> {
  const res = await request<{ jobs: Job[] }>(cfg, "/api/v1/jobs?limit=50");
  return res.jobs ?? [];
}

export async function listArtifacts(cfg: APIConfig): Promise<Artifact[]> {
  const res = await request<{ artifacts: Artifact[] }>(
    cfg,
    "/api/v1/artifacts?limit=50"
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
