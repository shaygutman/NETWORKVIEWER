import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { BaselineDiffResponse, DeviceSummary } from "../types";

interface ConfigDiffProps {
  devices: DeviceSummary[];
  selectedHostname?: string | null;
}

export function ConfigDiff({ devices, selectedHostname }: ConfigDiffProps) {
  const [hostname, setHostname] = useState(selectedHostname || devices[0]?.hostname || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [diff, setDiff] = useState<BaselineDiffResponse | null>(null);

  useEffect(() => {
    if (selectedHostname) {
      setHostname(selectedHostname);
    }
  }, [selectedHostname]);

  async function runDiff(target?: string) {
    const host = target || hostname;
    if (!host) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.baselineDiff(host);
      setDiff(data);
      if (data.error) setError(data.error);
    } catch (err) {
      setDiff(null);
      setError(err instanceof Error ? err.message : "Baseline compare failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="noc-panel p-5">
        <h2 className="text-lg font-semibold text-white">Baseline Configuration Drift</h2>
        <p className="mt-1 text-sm text-noc-muted">
          Compare live running-config against the approved golden baseline.
        </p>
        <div className="mt-4 flex flex-col gap-3 sm:flex-row">
          <select
            className="noc-input"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
          >
            {devices.map((device) => (
              <option key={device.hostname} value={device.hostname}>
                {device.hostname} ({device.ip})
              </option>
            ))}
          </select>
          <button className="noc-btn shrink-0" onClick={() => runDiff()} disabled={loading || !hostname}>
            {loading ? "Comparing…" : "Compare"}
          </button>
        </div>
        {error && <p className="mt-3 text-sm text-amber-300">{error}</p>}
      </div>

      {diff && (
        <div className="noc-panel overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-noc-border px-5 py-3 text-sm">
            <div>
              <span className="font-semibold text-white">{diff.hostname}</span>
              <span className="ml-2 text-noc-muted">vs {diff.baseline_file}</span>
            </div>
            <div className="flex gap-3 text-xs">
              <span className={diff.has_drift ? "text-amber-300" : "text-noc-good"}>
                {diff.has_drift ? "Drift detected" : "In sync"}
              </span>
              <span className="text-noc-good">+{diff.added_lines}</span>
              <span className="text-noc-bad">-{diff.removed_lines}</span>
            </div>
          </div>
          <div className="max-h-[28rem] overflow-auto font-mono text-xs leading-5">
            {diff.diff_lines.length === 0 ? (
              <p className="p-5 text-noc-muted">No comparable lines.</p>
            ) : (
              diff.diff_lines.map((line) => {
                const bg =
                  line.tag === "insert"
                    ? "bg-emerald-500/10 text-emerald-300"
                    : line.tag === "delete"
                      ? "bg-rose-500/10 text-rose-300"
                      : "text-slate-400";
                const prefix = line.tag === "insert" ? "+" : line.tag === "delete" ? "-" : " ";
                const content = line.running_line ?? line.baseline_line ?? "";
                return (
                  <div key={`${line.line_no}-${line.tag}-${content}`} className={`flex gap-3 px-4 py-0.5 ${bg}`}>
                    <span className="w-10 shrink-0 select-none text-slate-600">{line.line_no}</span>
                    <span className="w-3 shrink-0 select-none">{prefix}</span>
                    <span className="whitespace-pre-wrap break-all">{content}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
