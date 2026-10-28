import { useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { AddDeviceResponse, PlatformType } from "../types";

interface AddSwitchModalProps {
  onClose: () => void;
  onAdded: (result: AddDeviceResponse) => void;
}

const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const IPV6_RE = /^[0-9a-f:]+$/i;
const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;

function validateTarget(value: string): string | null {
  const cleaned = value.trim();
  if (!cleaned) return "Enter a switch IP address or DNS hostname.";
  if (IPV4_RE.test(cleaned) || (cleaned.includes(":") && IPV6_RE.test(cleaned))) {
    return null;
  }
  if (HOSTNAME_RE.test(cleaned)) return null;
  return "Use a valid IPv4/IPv6 address or DNS hostname.";
}

export function AddSwitchModal({ onClose, onAdded }: AddSwitchModalProps) {
  const [target, setTarget] = useState("");
  const [platform, setPlatform] = useState<PlatformType>("cisco_ios");
  const [site, setSite] = useState("");
  const [role, setRole] = useState("");
  const [inventoryHostname, setInventoryHostname] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const validationError = validateTarget(target);
    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const result = await api.addDevice({
        target: target.trim(),
        platform,
        site: site.trim() || null,
        role: role.trim() || null,
        inventory_hostname: inventoryHostname.trim() || null,
      });
      onAdded(result);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Failed to add switch";
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="noc-panel w-full max-w-lg p-5">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-white">Add Switch</h3>
            <p className="mt-1 text-sm text-noc-muted">
              Registers a switch for monitoring after a read-only SSH check using your
              login credentials. No passwords are stored in inventory.
            </p>
          </div>
          <button type="button" className="noc-btn-ghost shrink-0" onClick={onClose} disabled={submitting}>
            Close
          </button>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div>
            <label htmlFor="add-switch-target" className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">
              Switch hostname / IP
            </label>
            <input
              id="add-switch-target"
              className="noc-input font-mono"
              placeholder="10.168.2.79 or core-sw1.example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoFocus
              required
              disabled={submitting}
            />
          </div>

          <div>
            <label htmlFor="add-switch-platform" className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">
              Platform profile
            </label>
            <select
              id="add-switch-platform"
              className="noc-input"
              value={platform}
              onChange={(e) => setPlatform(e.target.value as PlatformType)}
              disabled={submitting}
            >
              <option value="cisco_ios">Cisco IOS / IOS-XE</option>
              <option value="cisco_nxos">Cisco NX-OS</option>
            </select>
            <p className="mt-1 text-xs text-slate-500">
              Auto-corrected from read-only <span className="font-mono">show version</span> when needed.
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="add-switch-site" className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">
                Site (optional)
              </label>
              <input
                id="add-switch-site"
                className="noc-input"
                placeholder="Building / campus"
                value={site}
                onChange={(e) => setSite(e.target.value)}
                disabled={submitting}
              />
            </div>
            <div>
              <label htmlFor="add-switch-role" className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">
                Role (optional)
              </label>
              <input
                id="add-switch-role"
                className="noc-input"
                placeholder="access / core / …"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                disabled={submitting}
              />
            </div>
          </div>

          <div>
            <label htmlFor="add-switch-id" className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500">
              Inventory ID (optional)
            </label>
            <input
              id="add-switch-id"
              className="noc-input font-mono"
              placeholder="Defaults from IP or DNS short name"
              value={inventoryHostname}
              onChange={(e) => setInventoryHostname(e.target.value)}
              disabled={submitting}
            />
          </div>

          {error && (
            <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
              {error}
            </div>
          )}

          <div className="flex flex-wrap justify-end gap-2 pt-1">
            <button type="button" className="noc-btn-ghost" onClick={onClose} disabled={submitting}>
              Cancel
            </button>
            <button type="submit" className="noc-btn" disabled={submitting}>
              {submitting ? "Checking & adding…" : "Add Switch"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
