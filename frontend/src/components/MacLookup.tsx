import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api/client";
import type { MacLookupResponse } from "../types";

export function MacLookup() {
  const [mac, setMac] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<MacLookupResponse | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const data = await api.macLookup(mac.trim());
      setResult(data);
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Lookup failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="noc-panel p-5">
        <h2 className="text-lg font-semibold text-white">Global MAC Lookup</h2>
        <p className="mt-1 text-sm text-noc-muted">
          Search a MAC across all inventory switches. Accepts colon, dash, or Cisco dotted format.
        </p>
        <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3 sm:flex-row">
          <input
            className="noc-input font-mono"
            placeholder="aa:bb:cc:dd:ee:ff"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
            required
          />
          <button type="submit" className="noc-btn shrink-0" disabled={loading}>
            {loading ? "Searching…" : "Search"}
          </button>
        </form>
        {error && (
          <p className="mt-3 text-sm text-red-300">{error}</p>
        )}
      </div>

      {result && (
        <div className="noc-panel overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-noc-border px-5 py-3 text-sm">
            <span className="font-mono text-cyan-300">{result.normalized_mac}</span>
            <span className="text-noc-muted">
              {result.hits.length} hit(s) · {result.devices_queried} queried ·{" "}
              {result.devices_failed} failed
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-400">
                <tr>
                  <th className="px-4 py-3">Switch</th>
                  <th className="px-4 py-3">Port</th>
                  <th className="px-4 py-3">VLAN</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">MAC</th>
                </tr>
              </thead>
              <tbody>
                {result.hits.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-noc-muted">
                      No matching MAC entries found.
                    </td>
                  </tr>
                ) : (
                  result.hits.map((hit, index) => (
                    <tr key={`${hit.hostname}-${hit.port}-${index}`} className="border-t border-noc-border/80">
                      <td className="px-4 py-3">
                        <div className="font-medium text-white">{hit.hostname}</div>
                        <div className="font-mono text-xs text-slate-500">{hit.ip}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-cyan-200">{hit.port || "—"}</td>
                      <td className="px-4 py-3">{hit.vlan || "—"}</td>
                      <td className="px-4 py-3">{hit.port_type || "—"}</td>
                      <td className="px-4 py-3 font-mono">{hit.mac}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {result.errors.length > 0 && (
            <div className="border-t border-noc-border px-5 py-3 text-xs text-amber-300">
              {result.errors.map((msg) => (
                <div key={msg}>{msg}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
