import { useEffect, useMemo, useState } from "react";
import type { NeighborDeviceType, PortDetail } from "../types";

interface PortTableProps {
  interfaces: PortDetail[];
  onPortSelect?: (port: string) => void;
  highlightPort?: string | null;
  staleDaysThreshold?: number;
}

function StatusBadge({ status, reason }: { status: PortDetail["status"]; reason?: string | null }) {
  const styles: Record<PortDetail["status"], string> = {
    up: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
    down: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
    "admin-down": "bg-slate-500/20 text-slate-300 ring-slate-500/30",
    "err-disabled": "bg-rose-600/30 text-rose-100 ring-rose-400/60",
    unknown: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  };
  const title =
    status === "err-disabled"
      ? `Err-disabled${reason ? `: ${reason}` : ""}`
      : status;
  return (
    <span
      title={title}
      className={`inline-flex rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ${styles[status]}`}
    >
      {status}
    </span>
  );
}

function DeviceIcon({ type }: { type?: NeighborDeviceType | null }) {
  const label: Record<NeighborDeviceType, string> = {
    switch: "SW",
    phone: "PH",
    ap: "AP",
    server: "SRV",
    host: "PC",
    unknown: "?",
  };
  const colors: Record<NeighborDeviceType, string> = {
    switch: "bg-indigo-500/20 text-indigo-200 ring-indigo-400/40",
    phone: "bg-violet-500/20 text-violet-200 ring-violet-400/40",
    ap: "bg-sky-500/20 text-sky-200 ring-sky-400/40",
    server: "bg-orange-500/20 text-orange-200 ring-orange-400/40",
    host: "bg-slate-500/20 text-slate-200 ring-slate-400/40",
    unknown: "bg-slate-700/40 text-slate-300 ring-slate-500/40",
  };
  if (!type) return null;
  return (
    <span
      title={type}
      className={`mr-1 inline-flex h-5 min-w-[1.75rem] items-center justify-center rounded px-1 text-[10px] font-bold uppercase ring-1 ${colors[type]}`}
    >
      {label[type]}
    </span>
  );
}

function HealthBadges({ iface }: { iface: PortDetail }) {
  const badges: { key: string; label: string; title: string; className: string }[] = [];
  if (iface.err_disabled) {
    badges.push({
      key: "err",
      label: "ERR-DIS",
      title: iface.err_disabled_reason || "err-disabled",
      className: "bg-rose-600/30 text-rose-100 ring-rose-400/50",
    });
  }
  if (iface.duplex_mismatch) {
    badges.push({
      key: "duplex",
      label: "HALF",
      title: "Half-duplex on an up link — possible duplex mismatch",
      className: "bg-amber-500/20 text-amber-200 ring-amber-400/40",
    });
  }
  if (iface.high_errors) {
    const title = [
      iface.crc_errors != null ? `CRC ${iface.crc_errors}` : null,
      iface.input_errors != null ? `In ${iface.input_errors}` : null,
      iface.output_errors != null ? `Out ${iface.output_errors}` : null,
    ]
      .filter(Boolean)
      .join(" · ");
    badges.push({
      key: "crc",
      label: "CRC/ERR",
      title: title || "Elevated interface errors",
      className: "bg-amber-500/20 text-amber-100 ring-amber-400/40",
    });
  }
  if (iface.poe_high_draw) {
    badges.push({
      key: "poe",
      label: "PoE↑",
      title: "High PoE draw vs port max",
      className: "bg-orange-500/20 text-orange-100 ring-orange-400/40",
    });
  }
  if (iface.is_stale) {
    badges.push({
      key: "stale",
      label: `IDLE ${iface.stale_days ?? "?"}d`,
      title: `Continuously down for ${iface.stale_days ?? "?"} day(s)`,
      className: "bg-slate-600/40 text-slate-200 ring-slate-400/40",
    });
  }
  if (badges.length === 0) return <span className="text-noc-muted">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {badges.map((b) => (
        <span
          key={b.key}
          title={b.title}
          className={`inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ${b.className}`}
        >
          {b.label}
        </span>
      ))}
    </div>
  );
}

function neighborLabel(iface: PortDetail): string {
  if (iface.connected_device) return iface.connected_device;
  if (iface.neighbor_hostname) {
    const bits = [iface.neighbor_hostname];
    if (iface.neighbor_platform) bits.push(iface.neighbor_platform);
    if (iface.neighbor_ip) bits.push(iface.neighbor_ip);
    if (iface.neighbor_protocol) bits.push(`via ${iface.neighbor_protocol.toUpperCase()}`);
    return bits.join(" · ");
  }
  return "—";
}

function poeLabel(iface: PortDetail): string {
  if (iface.poe_watts == null && !iface.poe_status) return "—";
  const watts = iface.poe_watts != null ? `${iface.poe_watts}W` : "";
  const cls = iface.poe_class ? `C${iface.poe_class}` : "";
  const st = iface.poe_status || "";
  return [watts, cls, st].filter(Boolean).join(" · ");
}

function macLabel(iface: PortDetail): { text: string; title: string } {
  const macs = iface.mac_addresses ?? [];
  if (macs.length === 0) return { text: "—", title: "" };
  if (macs.length <= 2) {
    const text = macs.join(", ");
    return { text, title: text };
  }
  return {
    text: `${macs.slice(0, 2).join(", ")} +${macs.length - 2}`,
    title: macs.join("\n"),
  };
}

export function PortTable({
  interfaces,
  onPortSelect,
  highlightPort,
  staleDaysThreshold = 30,
}: PortTableProps) {
  const [vlanFilter, setVlanFilter] = useState("");
  const [viewMode, setViewMode] = useState<"all" | "issues" | "unused">("all");

  useEffect(() => {
    if (!highlightPort) return;
    const id = `port-row-${highlightPort}`;
    const el = document.getElementById(id);
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [highlightPort, interfaces]);

  const vlanOptions = useMemo(() => {
    const values = new Set<string>();
    for (const iface of interfaces) {
      if (iface.vlan) values.add(iface.vlan);
    }
    return Array.from(values).sort((a, b) => {
      const an = Number(a);
      const bn = Number(b);
      if (!Number.isNaN(an) && !Number.isNaN(bn)) return an - bn;
      return a.localeCompare(b, undefined, { sensitivity: "base" });
    });
  }, [interfaces]);

  const filtered = useMemo(() => {
    const needle = vlanFilter.trim().toLowerCase();
    return interfaces.filter((iface) => {
      if (viewMode === "issues") {
        const hasIssue =
          iface.err_disabled ||
          iface.duplex_mismatch ||
          iface.high_errors ||
          iface.poe_high_draw ||
          (iface.health_flags && iface.health_flags.length > 0);
        if (!hasIssue) return false;
      }
      if (viewMode === "unused") {
        const days = iface.stale_days ?? 0;
        if (!iface.is_stale && days < staleDaysThreshold) return false;
      }
      if (!needle) return true;
      const vlan = (iface.vlan || "").toLowerCase();
      return vlan === needle || vlan.includes(needle);
    });
  }, [interfaces, vlanFilter, viewMode, staleDaysThreshold]);

  if (interfaces.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-noc-border px-4 py-8 text-center text-sm text-noc-muted">
        No interface data available for this switch.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1 rounded-lg border border-noc-border p-0.5">
          {(
            [
              ["all", "All ports"],
              ["issues", "Health issues"],
              ["unused", `Unused (≥${staleDaysThreshold}d)`],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={`rounded-md px-2.5 py-1 text-xs ${
                viewMode === id ? "bg-cyan-500/15 text-cyan-300" : "text-slate-400 hover:text-slate-200"
              }`}
              onClick={() => setViewMode(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="text-xs uppercase tracking-wide text-slate-400" htmlFor="vlan-filter">
          VLAN
        </label>
        <input
          id="vlan-filter"
          className="noc-input max-w-[10rem] font-mono text-sm"
          list="vlan-filter-options"
          placeholder="e.g. 10 or trunk"
          value={vlanFilter}
          onChange={(e) => setVlanFilter(e.target.value)}
        />
        <datalist id="vlan-filter-options">
          {vlanOptions.map((vlan) => (
            <option key={vlan} value={vlan} />
          ))}
        </datalist>
        {vlanFilter && (
          <button type="button" className="noc-btn-ghost text-xs" onClick={() => setVlanFilter("")}>
            Clear
          </button>
        )}
        <span className="text-xs text-noc-muted">
          Showing {filtered.length} of {interfaces.length} ports
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-dashed border-noc-border px-4 py-8 text-center text-sm text-noc-muted">
          No ports match the current filters.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-noc-border">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/70 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-3 py-2">Port</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">VLAN</th>
                <th className="px-3 py-2">MAC Address</th>
                <th className="px-3 py-2">Health</th>
                <th className="px-3 py-2">Connected Device / Neighbor</th>
                <th className="px-3 py-2">PoE</th>
                <th className="px-3 py-2">Speed</th>
                <th className="px-3 py-2">Duplex</th>
                <th className="px-3 py-2">Description</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((iface) => {
                const highlighted =
                  highlightPort &&
                  iface.port.toLowerCase() === highlightPort.toLowerCase();
                const macs = macLabel(iface);
                return (
                  <tr
                    key={iface.port}
                    id={`port-row-${iface.port}`}
                    className={`cursor-pointer border-t border-noc-border/70 hover:bg-cyan-500/5 ${
                      highlighted ? "bg-cyan-500/10 ring-1 ring-inset ring-cyan-400/40" : ""
                    } ${iface.err_disabled ? "bg-rose-500/5" : ""}`}
                    onClick={() => onPortSelect?.(iface.port)}
                  >
                    <td className="px-3 py-2 font-mono text-cyan-200">{iface.port}</td>
                    <td className="px-3 py-2">
                      <StatusBadge status={iface.status} reason={iface.err_disabled_reason} />
                    </td>
                    <td className="px-3 py-2 font-mono">{iface.vlan || "—"}</td>
                    <td
                      className="max-w-[12rem] px-3 py-2 font-mono text-xs text-slate-200"
                      title={macs.title || undefined}
                    >
                      <span className="line-clamp-2">{macs.text}</span>
                    </td>
                    <td className="px-3 py-2">
                      <HealthBadges iface={iface} />
                    </td>
                    <td className="max-w-xs px-3 py-2 text-slate-300" title={neighborLabel(iface)}>
                      <span className="inline-flex items-start">
                        <DeviceIcon type={iface.neighbor_device_type} />
                        <span className="line-clamp-2">{neighborLabel(iface)}</span>
                      </span>
                    </td>
                    <td
                      className={`px-3 py-2 font-mono text-xs ${
                        iface.poe_high_draw ? "text-orange-300" : "text-slate-300"
                      }`}
                      title={
                        iface.poe_max_watts != null
                          ? `Max ${iface.poe_max_watts}W`
                          : undefined
                      }
                    >
                      {poeLabel(iface)}
                    </td>
                    <td className="px-3 py-2 font-mono">{iface.speed || "—"}</td>
                    <td
                      className={`px-3 py-2 font-mono ${
                        iface.duplex_mismatch ? "text-amber-300" : ""
                      }`}
                    >
                      {iface.duplex || "—"}
                    </td>
                    <td className="px-3 py-2 text-slate-300">{iface.description || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
