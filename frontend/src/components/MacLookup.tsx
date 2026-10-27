import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api/client";
import type { MacLookupResponse } from "../types";
import { SearchCoverageBanner } from "./SearchCoverageBanner";

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
          Access ports (Gi/Fa) are listed first — uplink/SVI hits are marked so you can ignore flood
          paths. Uses cached MAC/ARP first; live SSH only on switches not already marked unreachable.
          Run Live collect so offline switches still have searchable cache.
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
              {result.hits.length} hit(s) · {result.devices_queried} queried
              {result.devices_failed > 0 ? ` · ${result.devices_failed} unreachable` : ""}
              {(result.devices_from_cache ?? 0) > 0
                ? ` · ${result.devices_from_cache} from cache`
                : ""}
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-400">
                <tr>
                  <th className="px-4 py-3">Switch</th>
                  <th className="px-4 py-3">Port</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">VLAN</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">MAC</th>
                  <th className="px-4 py-3">Source</th>
                </tr>
              </thead>
              <tbody>
                {result.hits.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-noc-muted">
                      No matching MAC entries found.
                    </td>
                  </tr>
                ) : (
                  result.hits.map((hit, index) => {
                    const role = hit.port_role ?? "unknown";
                    const roleLabel =
                      role === "edge"
                        ? "access"
                        : role === "uplink"
                          ? "uplink"
                          : role === "svi"
                            ? "SVI/ARP"
                            : "—";
                    const roleClass =
                      role === "edge"
                        ? "text-emerald-300"
                        : role === "uplink"
                          ? "text-amber-300"
                          : role === "svi"
                            ? "text-slate-400"
                            : "text-noc-muted";
                    return (
                      <tr
                        key={`${hit.hostname}-${hit.port}-${index}`}
                        className="border-t border-noc-border/80"
                      >
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">
                            {hit.device_hostname || hit.hostname}
                          </div>
                          {hit.device_hostname ? (
                            <div className="text-xs text-slate-500">{hit.hostname}</div>
                          ) : null}
                          <div className="font-mono text-xs text-slate-500">{hit.ip}</div>
                        </td>
                        <td
                          className={`px-4 py-3 font-mono ${
                            role === "edge" ? "text-cyan-200" : "text-slate-400"
                          }`}
                        >
                          {hit.port || "—"}
                        </td>
                        <td className={`px-4 py-3 text-xs uppercase tracking-wide ${roleClass}`}>
                          {roleLabel}
                        </td>
                        <td className="px-4 py-3">{hit.vlan || "—"}</td>
                        <td className="px-4 py-3">{hit.port_type || "—"}</td>
                        <td className="px-4 py-3 font-mono">{hit.mac}</td>
                        <td className="px-4 py-3 text-xs uppercase text-noc-muted">
                          {hit.from_cache ? "cache" : "live"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <SearchCoverageBanner
            warning={result.warning}
            devicesFailed={result.devices_failed}
            devicesFromCache={result.devices_from_cache}
            unreachableHosts={result.unreachable_hosts}
            errors={result.errors}
          />
        </div>
      )}
    </div>
  );
}
