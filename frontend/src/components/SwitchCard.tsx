import type { SwitchOverview } from "../types";

interface SwitchCardProps {
  switchData: SwitchOverview;
  selected: boolean;
  onSelect: () => void;
}

function BoolPill({ label, value }: { label: string; value: boolean | null | undefined }) {
  if (value === null || value === undefined) {
    return (
      <span className="rounded-md bg-slate-800 px-2 py-0.5 text-[11px] text-slate-400">
        {label}: n/a
      </span>
    );
  }
  return (
    <span
      className={`rounded-md px-2 py-0.5 text-[11px] ${
        value ? "bg-emerald-500/15 text-emerald-300" : "bg-slate-800 text-slate-400"
      }`}
    >
      {label}: {value ? "on" : "off"}
    </span>
  );
}

export function SwitchCard({ switchData, selected, onSelect }: SwitchCardProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`noc-panel w-full p-4 text-left transition hover:border-cyan-500/40 ${
        selected ? "border-cyan-400/50 ring-1 ring-cyan-400/30" : ""
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                switchData.reachable ? "bg-noc-good shadow-[0_0_8px_rgba(34,197,94,0.7)]" : "bg-noc-bad"
              }`}
            />
            <h3 className="font-semibold text-white">{switchData.hostname}</h3>
          </div>
          <p className="mt-1 font-mono text-xs text-slate-400">{switchData.ip}</p>
        </div>
        <span className="rounded-md bg-slate-900 px-2 py-1 text-[10px] uppercase tracking-wide text-slate-400">
          {switchData.platform.replace("cisco_", "")}
        </span>
      </div>

      {switchData.error ? (
        <p className="mt-3 text-xs text-rose-300">{switchData.error}</p>
      ) : (
        <>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-300">
            <div>
              <div className="text-slate-500">Model</div>
              <div className="truncate">{switchData.model || "—"}</div>
            </div>
            <div>
              <div className="text-slate-500">Firmware</div>
              <div className="truncate">{switchData.firmware || "—"}</div>
            </div>
            <div>
              <div className="text-slate-500">Uptime</div>
              <div className="truncate">{switchData.uptime || "—"}</div>
            </div>
            <div>
              <div className="text-slate-500">CPU</div>
              <div>{switchData.cpu_percent != null ? `${switchData.cpu_percent}%` : "—"}</div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            <BoolPill label="DHCP Snoop" value={switchData.dhcp_snooping} />
            <BoolPill label="IGMP" value={switchData.igmp_snooping} />
            <BoolPill label="Jumbo" value={switchData.jumbo_frames} />
          </div>
          <div className="mt-3 flex gap-3 text-xs">
            <span className="text-noc-good">{switchData.interfaces_up} up</span>
            <span className="text-noc-bad">{switchData.interfaces_down} down</span>
            <span className="text-slate-500">{switchData.interface_count} ports</span>
          </div>
        </>
      )}
    </button>
  );
}
