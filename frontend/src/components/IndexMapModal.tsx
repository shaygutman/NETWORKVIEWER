export interface IndexMapEntry {
  hostName: string;
  description: string;
  ipAddress: string;
}

/** Documentation index (page 4) — display-only reference; never used for SSH or config. */
export const INDEX_MAP_ENTRIES: IndexMapEntry[] = [
  { hostName: "eyok2-02sr-swc-01", description: "Cisco 4500 Switch", ipAddress: "10.247.231.130" },
  { hostName: "eyok2-02sr-swc-02", description: "Cisco 4500 Switch", ipAddress: "10.247.231.331" },
  { hostName: "nuyokn-her-fl0-sw1", description: "Switch / Core Device", ipAddress: "10.247.58.10" },
  { hostName: "nuyokn-her-fl0-sw2", description: "Switch / Core Device", ipAddress: "10.247.58.8" },
  { hostName: "nuyokn-rim-fl1-sw1", description: "Switch / Core Device", ipAddress: "10.247.58.11" },
  { hostName: "nuyokn-her-fl2-sw1", description: "Switch / Core Device", ipAddress: "10.247.58.1" },
  { hostName: "nuyokn-her-fl2-sw2", description: "Switch / Core Device", ipAddress: "10.247.58.2" },
  { hostName: "nuyokn-her-fl3-sw1", description: "Switch / Core Device", ipAddress: "10.247.58.3" },
  { hostName: "nuyokn-her-fl3-sw2", description: "Switch / Core Device", ipAddress: "10.247.58.7" },
  { hostName: "nuyokn-tav-fl2-sw1", description: "Access Tavor Switch", ipAddress: "10.247.58.12" },
  { hostName: "nuyokn-her-fl6-sw1", description: "Switch / Core Device", ipAddress: "10.247.58.5" },
  { hostName: "nuyokn-her-fl6-sw2", description: "Switch / Core Device", ipAddress: "10.247.58.6" },
  { hostName: "NewN9k-pri", description: "New Nexus Switch (Primary)", ipAddress: "10.247.58.52" },
  { hostName: "NewN9k-sec", description: "New Nexus Switch (Secondary)", ipAddress: "10.247.58.53" },
  { hostName: "n9k-pri", description: "Nexus Switch (Primary, boxed area)", ipAddress: "10.247.58.50" },
  { hostName: "n9k-sec", description: "Nexus Switch (Secondary, boxed area)", ipAddress: "10.247.58.51" },
  { hostName: "FEX100", description: "Fabric Extender (FEX)", ipAddress: "Connected via Eth1/1 - Eth1/2" },
  { hostName: "FEX101", description: "Fabric Extender (FEX)", ipAddress: "Connected via Eth1/3 - Eth1/4" },
];

interface IndexMapModalProps {
  onClose: () => void;
}

export function IndexMapModal({ onClose }: IndexMapModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="noc-panel flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden p-5">
        <div className="mb-4 flex shrink-0 items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-white">Index Map</h3>
            <p className="mt-1 text-sm text-noc-muted">
              Network device index from documentation (page 4). Reference only — no
              switch access or configuration changes.
            </p>
          </div>
          <button type="button" className="noc-btn-ghost shrink-0" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-auto rounded-xl border border-noc-border/80">
          <table className="w-full min-w-[640px] border-collapse text-left text-sm">
            <thead className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur">
              <tr className="border-b border-noc-border text-xs uppercase tracking-wide text-slate-400">
                <th className="w-12 px-3 py-3 font-medium">#</th>
                <th className="px-3 py-3 font-medium">Host Name</th>
                <th className="px-3 py-3 font-medium">Description / Model</th>
                <th className="px-3 py-3 font-medium">IP Address</th>
              </tr>
            </thead>
            <tbody>
              {INDEX_MAP_ENTRIES.map((entry, index) => (
                <tr
                  key={`${entry.hostName}-${index}`}
                  className="border-b border-slate-800/80 transition hover:bg-cyan-500/5"
                >
                  <td className="px-3 py-2.5 tabular-nums text-slate-500">{index + 1}</td>
                  <td className="px-3 py-2.5 font-mono text-cyan-200">{entry.hostName}</td>
                  <td className="px-3 py-2.5 text-slate-200">{entry.description}</td>
                  <td className="px-3 py-2.5 font-mono text-slate-300">{entry.ipAddress}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="mt-3 shrink-0 text-xs text-slate-500">
          {INDEX_MAP_ENTRIES.length} devices listed · documentation reference
        </p>
      </div>
    </div>
  );
}
