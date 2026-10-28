import { useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { AddSwitchResponse, PlatformType } from "../types";

interface AddSwitchModalProps {
  onClose: () => void;
  onAdded: (result: AddSwitchResponse) => void;
}

const IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const HOST_OR_DNS = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252})$/;
const INVENTORY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function validateAddress(value: string): string | null {
  const cleaned = value.trim();
  if (!cleaned) return "Enter a management IP or DNS name.";
  if (/\s/.test(cleaned)) return "Address must not contain spaces.";
  if (IPV4.test(cleaned) || HOST_OR_DNS.test(cleaned)) return null;
  return "Enter a valid IPv4 address or DNS hostname.";
}

export function AddSwitchModal({ onClose, onAdded }: AddSwitchModalProps) {
  const [address, setAddress] = useState("");
  const [hostname, setHostname] = useState("");
  const [site, setSite] = useState("");
  const [role, setRole] = useState("");
  const [platform, setPlatform] = useState<"" | PlatformType>("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const addressError = validateAddress(address);
    if (addressError) {
      setError(addressError);
      return;
    }
    const inventoryId = hostname.trim();
    if (inventoryId && !INVENTORY_ID.test(inventoryId)) {
      setError("Inventory name must be letters, digits, dot, underscore, or hyphen.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await api.addSwitch({
        address: address.trim(),
        hostname: inventoryId || undefined,
        site: site.trim() || undefined,
        role: role.trim() || undefined,
        platform: platform || undefined,
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
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="noc-panel w-full max-w-lg p-5 shadow-xl">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Add Switch</h2>
            <p className="mt-1 text-sm text-noc-muted">
              Enter the management IP or DNS name. The app runs a read-only SSH check
              with your login credentials, then adds the switch to inventory for polling
              and global search.
            </p>
          </div>
          <button type="button" className="noc-btn-ghost shrink-0" onClick={onClose} disabled={loading}>
            Close
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <label className="block text-sm text-slate-300">
            Switch IP / DNS
            <input
              className="noc-input mt-1 font-mono"
              placeholder="10.168.2.90 or eyok2-000a-swa-02"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              autoFocus
              required
              disabled={loading}
            />
          </label>

          <label className="block text-sm text-slate-300">
            Inventory name <span className="text-noc-muted">(optional)</span>
            <input
              className="noc-input mt-1 font-mono"
              placeholder="Defaults to sw-&lt;ip&gt; or DNS name"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              disabled={loading}
            />
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block text-sm text-slate-300">
              Site <span className="text-noc-muted">(optional)</span>
              <input
                className="noc-input mt-1"
                value={site}
                onChange={(e) => setSite(e.target.value)}
                disabled={loading}
              />
            </label>
            <label className="block text-sm text-slate-300">
              Role <span className="text-noc-muted">(optional)</span>
              <input
                className="noc-input mt-1"
                placeholder="access / core"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                disabled={loading}
              />
            </label>
          </div>

          <label className="block text-sm text-slate-300">
            Platform hint <span className="text-noc-muted">(optional — auto-detected)</span>
            <select
              className="noc-input mt-1"
              value={platform}
              onChange={(e) => setPlatform(e.target.value as "" | PlatformType)}
              disabled={loading}
            >
              <option value="">Auto-detect from show version</option>
              <option value="cisco_ios">cisco_ios</option>
              <option value="cisco_nxos">cisco_nxos</option>
              <option value="cisco_xe">cisco_xe</option>
            </select>
          </label>

          <p className="rounded-lg border border-noc-border/70 bg-slate-950/50 px-3 py-2 text-xs text-noc-muted">
            Passwords are never saved. SSH uses your current UI login session only.
            Only read-only <span className="font-mono text-slate-300">show</span> commands
            are run on the switch.
          </p>

          {error && (
            <p className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button type="button" className="noc-btn-ghost" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="noc-btn" disabled={loading}>
              {loading ? "Testing SSH & adding…" : "Add Switch"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
