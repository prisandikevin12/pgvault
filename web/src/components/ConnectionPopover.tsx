"use client";

import { FormEvent, useEffect, useState } from "react";
import { XIcon } from "@/components/Icons";

interface ConnectionPopoverProps {
  open: boolean;
  baseUrl: string;
  apiKey: string;
  defaultBaseUrl: string;
  onClose: () => void;
  onSave: (baseUrl: string, apiKey: string) => void;
  onReset: () => void;
}

export function ConnectionPopover({
  open,
  baseUrl,
  apiKey,
  defaultBaseUrl,
  onClose,
  onSave,
  onReset,
}: ConnectionPopoverProps) {
  const [draftUrl, setDraftUrl] = useState(baseUrl);
  const [draftKey, setDraftKey] = useState(apiKey);

  useEffect(() => {
    if (open) {
      setDraftUrl(baseUrl);
      setDraftKey(apiKey);
    }
  }, [open, baseUrl, apiKey]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    onSave(draftUrl.trim() || defaultBaseUrl, draftKey);
    onClose();
  };

  return (
    <>
      <div className="popover-backdrop" onClick={onClose} aria-hidden="true" />
      <div className="popover" role="dialog" aria-label="API Connection Settings">
        <div className="popover-header">
          <span>API Connection</span>
          <button type="button" className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close">
            <XIcon />
          </button>
        </div>
        <form className="popover-body" onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="conn-base-url">API Base URL</label>
            <input
              id="conn-base-url"
              className="input mono"
              type="text"
              value={draftUrl}
              onChange={(e) => setDraftUrl(e.target.value)}
              placeholder={defaultBaseUrl}
              required
            />
            <span className="field-hint">
              Stored in browser localStorage. Default: <span className="mono">{defaultBaseUrl}</span>
            </span>
          </div>

          <div className="field">
            <label htmlFor="conn-api-key">API Key (Bearer / X-API-Key)</label>
            <input
              id="conn-api-key"
              className="input mono"
              type="password"
              value={draftKey}
              onChange={(e) => setDraftKey(e.target.value)}
              placeholder="Optional when PGVAULT_API_KEY is unset"
            />
          </div>

          <div className="popover-footer">
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => {
                onReset();
                onClose();
              }}
            >
              Reset Default
            </button>
            <div className="actions-inline">
              <button type="button" className="btn btn-xs" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary btn-xs">
                Save &amp; Connect
              </button>
            </div>
          </div>
        </form>
      </div>
    </>
  );
}
