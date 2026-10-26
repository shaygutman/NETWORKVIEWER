import type { PortDetail } from "../types";

interface PortTableProps {
  interfaces: PortDetail[];
  onPortSelect?: (port: string) => void;
}

function StatusBadge({ status }: { status: PortDetail["status"] }) {
  const styles: Record<PortDetail["status"], string> = {
    up: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
    down: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
    "admin-down": "bg-slate-500/20 text-slate-300 ring-slate-500/30",
    unknown: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  };
  return (
    <span className={`inline-flex rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ${styles[status]}`}>
      {status}
    </span>
  );
}

export function PortTable({ interfaces, onPortSelect }: PortTableProps) {
  if (interfaces.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-noc-border px-4 py-8 text-center text-sm text-noc-muted">
        No interface data available for this switch.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-noc-border">
      <table className="min-w-full text-left text-sm">
        <thead className="bg-slate-950/70 text-xs uppercase tracking-wide text-slate-400">
          <tr>
            <th className="px-3 py-2">Port</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">VLAN</th>
            <th className="px-3 py-2">Speed</th>
            <th className="px-3 py-2">Duplex</th>
            <th className="px-3 py-2">Trust</th>
            <th className="px-3 py-2">Description</th>
          </tr>
        </thead>
        <tbody>
          {interfaces.map((iface) => (
            <tr
              key={iface.port}
              className="cursor-pointer border-t border-noc-border/70 hover:bg-cyan-500/5"
              onClick={() => onPortSelect?.(iface.port)}
            >
              <td className="px-3 py-2 font-mono text-cyan-200">{iface.port}</td>
              <td className="px-3 py-2">
                <StatusBadge status={iface.status} />
              </td>
              <td className="px-3 py-2">{iface.vlan || "—"}</td>
              <td className="px-3 py-2 font-mono">{iface.speed || "—"}</td>
              <td className="px-3 py-2 font-mono">{iface.duplex || "—"}</td>
              <td className="px-3 py-2">{iface.trust_level || "—"}</td>
              <td className="px-3 py-2 text-slate-300">{iface.description || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
