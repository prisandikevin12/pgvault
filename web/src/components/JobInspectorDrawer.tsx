"use client";

import { useEffect, useState } from "react";
import { formatBytes, formatTimestamp, Job } from "@/lib/api";
import { CheckIcon, CopyIcon, XIcon } from "@/components/Icons";

interface JobInspectorDrawerProps {
  job: Job | null;
  targetName: string;
  onClose: () => void;
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case "succeeded":
      return "badge badge-emerald";
    case "failed":
      return "badge badge-rose";
    case "queued":
    case "running":
    case "verifying":
      return "badge badge-amber";
    default:
      return "badge badge-neutral";
  }
}

export function JobInspectorDrawer({ job, targetName, onClose }: JobInspectorDrawerProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (!job) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [job, onClose]);

  if (!job) return null;

  const copyText = async (label: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(label);
      setTimeout(() => setCopiedKey((prev) => (prev === label ? null : prev)), 1800);
    } catch {
      // Clipboard API unavailable in non-secure context
    }
  };

  const errorBlockParts: string[] = [];
  if (job.error_message) {
    errorBlockParts.push(`[job.error_message]\n${job.error_message}`);
  }
  if (job.artifact?.verification_error) {
    errorBlockParts.push(`[artifact.verification_error]\n${job.artifact.verification_error}`);
  }
  const combinedLog = errorBlockParts.join("\n\n");

  const isStaleRecovered =
    job.error_message?.toLowerCase().includes("lease expired") ?? false;

  return (
    <div
      className="drawer-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <aside className="drawer" role="dialog" aria-label={`Execution Details for Job #${job.id}`}>
        <div className="drawer-header">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <h2 className="drawer-title mono">Job #{job.id}</h2>
              <span className={statusBadgeClass(job.status)}>{job.status}</span>
              {isStaleRecovered && <span className="badge badge-amber">stale recovered</span>}
            </div>
            <div className="drawer-subtitle">{targetName}</div>
          </div>
          <button type="button" className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close">
            <XIcon />
          </button>
        </div>

        <div className="drawer-body">
          {/* Execution Metadata */}
          <div className="form-section">
            <div className="form-section-title">Execution State</div>
            <div className="kv-grid">
              <div className="kv-item">
                <div className="kv-label">Attempts</div>
                <div className="kv-value mono">
                  {job.attempts} / {job.max_attempts}
                </div>
              </div>
              <div className="kv-item">
                <div className="kv-label">Locked By</div>
                <div className="kv-value mono">{job.locked_by || "—"}</div>
              </div>
              <div className="kv-item">
                <div className="kv-label">Run After</div>
                <div className="kv-value mono">{formatTimestamp(job.run_after)}</div>
              </div>
              <div className="kv-item">
                <div className="kv-label">Lease Expires At</div>
                <div className="kv-value mono">{formatTimestamp(job.lease_expires_at)}</div>
              </div>
              <div className="kv-item">
                <div className="kv-label">Started At</div>
                <div className="kv-value mono">{formatTimestamp(job.started_at)}</div>
              </div>
              <div className="kv-item">
                <div className="kv-label">Finished At</div>
                <div className="kv-value mono">{formatTimestamp(job.finished_at)}</div>
              </div>
              <div className="kv-item full">
                <div className="kv-label">Created At</div>
                <div className="kv-value mono">{formatTimestamp(job.created_at)}</div>
              </div>
            </div>
          </div>

          {/* Restore Verification & Artifact */}
          <div className="form-section">
            <div className="form-section-title">Restore Verification &amp; Artifact</div>
            {job.artifact ? (
              <div className="kv-grid">
                <div className="kv-item">
                  <div className="kv-label">Verification</div>
                  <div className="kv-value" style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {job.artifact.verification_passed ? (
                      <span className="badge badge-emerald">
                        Passed · {job.artifact.restore_duration_ms} ms
                      </span>
                    ) : (
                      <span className="badge badge-rose">Failed</span>
                    )}
                    {job.artifact.pruned_at && <span className="badge badge-neutral">Pruned</span>}
                  </div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">PostgreSQL / Tables</div>
                  <div className="kv-value mono">
                    PG v{job.artifact.pg_major_version} · {job.artifact.tables.length} tables
                  </div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Plaintext Size</div>
                  <div className="kv-value mono">{formatBytes(job.artifact.plaintext_bytes)}</div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Ciphertext Size</div>
                  <div className="kv-value mono">{formatBytes(job.artifact.ciphertext_bytes)}</div>
                </div>
                <div className="kv-item full">
                  <div className="kv-label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span>S3 Object Key</span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-xs"
                      onClick={() => void copyText("object_key", job.artifact!.object_key)}
                    >
                      {copiedKey === "object_key" ? <CheckIcon /> : <CopyIcon />}
                      {copiedKey === "object_key" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <div className="kv-value mono">{job.artifact.object_key}</div>
                </div>
                <div className="kv-item full">
                  <div className="kv-label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span>Ciphertext SHA-256</span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-xs"
                      onClick={() => void copyText("sha256", job.artifact!.ciphertext_sha256)}
                    >
                      {copiedKey === "sha256" ? <CheckIcon /> : <CopyIcon />}
                      {copiedKey === "sha256" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <div className="kv-value mono">{job.artifact.ciphertext_sha256}</div>
                </div>
                {job.artifact.pruned_at && (
                  <div className="kv-item full">
                    <div className="kv-label">Pruned At</div>
                    <div className="kv-value mono">{formatTimestamp(job.artifact.pruned_at)}</div>
                  </div>
                )}
              </div>
            ) : (
              <div className="kv-grid">
                <div className="kv-item full">
                  <div className="kv-value" style={{ color: "var(--text-muted)" }}>
                    No artifact recorded yet for this job execution.
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Error / Diagnostic Log Block */}
          <div className="form-section">
            <div className="form-section-title">Diagnostics &amp; Errors</div>
            <div className="log-box">
              <div className="log-box-header">
                <span className="mono">execution.log</span>
                <button
                  type="button"
                  className="btn btn-xs"
                  disabled={!combinedLog}
                  onClick={() => void copyText("log", combinedLog)}
                >
                  {copiedKey === "log" ? <CheckIcon /> : <CopyIcon />}
                  {copiedKey === "log" ? "Copied" : "Copy"}
                </button>
              </div>
              {combinedLog ? (
                <pre>{combinedLog}</pre>
              ) : (
                <pre className="log-clean">No errors reported for Job #{job.id}.</pre>
              )}
            </div>
          </div>
        </div>

        <div className="drawer-footer">
          <button type="button" className="btn" onClick={onClose}>
            Close
          </button>
        </div>
      </aside>
    </div>
  );
}
