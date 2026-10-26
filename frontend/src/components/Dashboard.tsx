import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api, clearSession } from "../api/client";
import type {
  ConnectivityProbeResult,
  DashboardTab,
  DeviceSummary,
  MacLookupResponse,
  SwitchDetail,
  SwitchOverview,
  UserInfo,
} from "../types";
import { CliCommandsModal } from "./CliCommandsModal";
import { ConfigDiff } from "./ConfigDiff";
import { MacLookup } from "./MacLookup";
import { PortTable } from "./PortTable";
import { SwitchCard } from "./SwitchCard";

interface DashboardProps {
  user: UserInfo;
  onLogout: () => void;
}

export function Dashboard({ user, onLogout }: DashboardProps) {
  const [tab, setTab] = useState<DashboardTab>("switches");
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const [overviews, setOverviews] = useState<SwitchOverview[]>([]);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [detail, setDetail] = useState<SwitchDetail | null>(null);
  const [loadingFleet, setLoadingFleet] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastSync, setLastSync] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [headerMac, setHeaderMac] = useState("");
  const [macQuickResult, setMacQuickResult] = useState<MacLookupResponse | null>(null);
  const [commandsModal, setCommandsModal] = useState<{ title: string; commands: string[] } | null>(null);
  const [probeResult, setProbeResult] = useState<ConnectivityProbeResult | null>(null);
  const [probing, setProbing] = useState(false);

  const reachableCount = useMemo(
    () => overviews.filter((item) => item.reachable).length,
    [overviews],
  );

  /** force=true bypasses backend TTL cache (manual Refresh / auto-refresh). */
  const refreshFleet = useCallback(async (force = false) => {
    setLoadingFleet(true);
    setError(null);
    try {
      const [deviceList, overviewList] = await Promise.all([
        api.listDevices(),
        api.overview(force),
      ]);
      setDevices(deviceList);
      setOverviews(overviewList);
      setLastSync(new Date());
      if (overviewList.length > 0) {
        setSelectedHost((prev) => prev ?? overviewList[0].hostname);
      }
      // After a forced fleet collect, detail cache is warm — reload selected host from cache.
      if (force && selectedHost) {
        try {
          const data = await api.deviceDetail(selectedHost, false);
          setDetail(data);
        } catch {
          /* detail panel will show prior error state if needed */
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to refresh fleet");
    } finally {
      setLoadingFleet(false);
    }
  }, [selectedHost]);

  /** Cached by default; pass force=true only when explicitly re-collecting. */
  const loadDetail = useCallback(async (hostname: string, force = false) => {
    setLoadingDetail(true);
    setProbeResult(null);
    try {
      const data = await api.deviceDetail(hostname, force);
      setDetail(data);
    } catch (err) {
      setDetail(null);
      setError(err instanceof Error ? err.message : "Failed to load switch detail");
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  const runSessionProbe = useCallback(async (hostname: string) => {
    setProbing(true);
    setError(null);
    try {
      const result = await api.probeDevice(hostname);
      setProbeResult(result);
      // Probe already did a live collect and refreshed the cache — serve cache.
      await loadDetail(hostname, false);
      // Keep fleet card in sync with probe outcome.
      setOverviews((prev) =>
        prev.map((item) =>
          item.hostname === hostname
            ? {
                ...item,
                reachable: result.reachable,
                model: result.model ?? item.model,
                firmware: result.firmware ?? item.firmware,
                interface_count: result.interface_count,
                interfaces_up: result.interfaces_up,
                interfaces_down: result.interfaces_down,
                error: result.error ?? null,
                last_collected_at: result.collected_at ?? item.last_collected_at,
              }
            : item,
        ),
      );
    } catch (err) {
      setProbeResult(null);
      setError(err instanceof Error ? err.message : "SSH probe failed");
    } finally {
      setProbing(false);
    }
  }, [loadDetail]);

  useEffect(() => {
    // First paint: prefer cache; live SSH only on cold miss.
    void refreshFleet(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mount-only initial load
  }, []);

  useEffect(() => {
    if (selectedHost) {
      void loadDetail(selectedHost, false);
    }
  }, [selectedHost, loadDetail]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      void refreshFleet(true);
    }, 60000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, refreshFleet]);

  async function handleHeaderMac(event: FormEvent) {
    event.preventDefault();
    setTab("mac");
    try {
      const result = await api.macLookup(headerMac.trim());
      setMacQuickResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "MAC lookup failed");
    }
  }

  async function openCommands(port?: string) {
    if (!selectedHost) return;
    try {
      const commands = await api.recommendedCommands(selectedHost, port);
      setCommandsModal({
        title: port ? `${selectedHost} · ${port}` : selectedHost,
        commands,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load commands");
    }
  }

  async function handleLogout() {
    try {
      await api.logout();
    } catch {
      clearSession();
    }
    onLogout();
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-noc-border/80 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.8)]" />
              <h1 className="text-lg font-bold text-white">Network Operations Assistant</h1>
            </div>
            <p className="mt-1 text-xs text-noc-muted">
              {reachableCount}/{overviews.length || devices.length} switches reachable
              {lastSync ? ` · Last sync ${lastSync.toLocaleTimeString()}` : ""}
            </p>
          </div>

          <form onSubmit={handleHeaderMac} className="flex w-full max-w-md gap-2">
            <input
              className="noc-input font-mono"
              placeholder="MAC lookup…"
              value={headerMac}
              onChange={(e) => setHeaderMac(e.target.value)}
            />
            <button type="submit" className="noc-btn-ghost shrink-0">
              Find
            </button>
          </form>

          <div className="flex flex-wrap items-center gap-2">
            <label className="noc-btn-ghost cursor-pointer">
              <input
                type="checkbox"
                className="mr-2 accent-cyan-400"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              Auto-refresh
            </label>
            <button
              className="noc-btn-ghost"
              onClick={() => void refreshFleet(true)}
              disabled={loadingFleet}
              title="Force live SSH collection (bypasses cache)"
            >
              {loadingFleet ? "Refreshing…" : "Refresh"}
            </button>
            <span className="rounded-lg border border-noc-border px-3 py-2 text-xs text-slate-300">
              {user.display_name || user.username}
            </span>
            <button className="noc-btn-ghost" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>

        <div className="mx-auto flex max-w-7xl gap-1 px-4 pb-3">
          {(
            [
              ["switches", "Switches"],
              ["mac", "MAC Lookup"],
              ["baseline", "Baseline Diff"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              className={`rounded-lg px-3 py-1.5 text-sm ${
                tab === id
                  ? "bg-cyan-500/15 text-cyan-300"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              }`}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-5">
        {error && (
          <div className="mb-4 rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        {tab === "switches" && (
          <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
            <section className="space-y-3">
              {overviews.length === 0 && !loadingFleet ? (
                <div className="noc-panel p-4 text-sm text-noc-muted">
                  No switches in inventory yet. Update inventory.yaml and refresh.
                </div>
              ) : (
                overviews.map((item) => (
                  <SwitchCard
                    key={item.hostname}
                    switchData={item}
                    selected={selectedHost === item.hostname}
                    onSelect={() => setSelectedHost(item.hostname)}
                  />
                ))
              )}
            </section>

            <section className="noc-panel p-5">
              {!selectedHost ? (
                <p className="text-sm text-noc-muted">Select a switch to inspect ports.</p>
              ) : loadingDetail ? (
                <p className="text-sm text-noc-muted">Collecting interface data from {selectedHost}…</p>
              ) : detail ? (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 className="text-xl font-semibold text-white">{detail.hostname}</h2>
                      <p className="mt-1 text-sm text-noc-muted">
                        {detail.model || "Unknown model"} · {detail.firmware || "Unknown firmware"}
                        {detail.system_mac ? ` · MAC ${detail.system_mac}` : ""}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <button
                        className="noc-btn-ghost"
                        disabled={probing}
                        onClick={() => selectedHost && void runSessionProbe(selectedHost)}
                        title="Uses your login session credentials only"
                      >
                        {probing ? "Testing SSH…" : "Test SSH"}
                      </button>
                      <button className="noc-btn-ghost" onClick={() => void openCommands()}>
                        CLI Tips
                      </button>
                      <button
                        className="noc-btn-ghost"
                        onClick={() => {
                          setTab("baseline");
                        }}
                      >
                        Baseline
                      </button>
                    </div>
                  </div>
                  {probeResult && (
                    <div className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-noc-muted">
                      Session probe as <span className="font-mono text-cyan-300">{probeResult.ssh_username}</span>
                      {" · "}source={probeResult.credentials_source}
                      {" · "}handshake={probeResult.handshake_ok ? "ok" : "fail"}
                      {" · "}auth={probeResult.authenticated ? "ok" : "fail"}
                      {" · "}model={probeResult.model || "—"}
                      {" · "}fw={probeResult.firmware || "—"}
                      {" · "}ports={probeResult.interface_count}
                      {probeResult.error ? ` · error: ${probeResult.error}` : ""}
                    </div>
                  )}
                  <PortTable
                    interfaces={detail.interfaces}
                    onPortSelect={(port) => void openCommands(port)}
                  />
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-sm text-noc-muted">Unable to load detail for {selectedHost}.</p>
                  <button
                    className="noc-btn-ghost"
                    disabled={probing}
                    onClick={() => void runSessionProbe(selectedHost)}
                  >
                    {probing ? "Testing SSH…" : "Test SSH (session credentials)"}
                  </button>
                  {probeResult && (
                    <div className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-noc-muted">
                      handshake={probeResult.handshake_ok ? "ok" : "fail"}
                      {" · "}auth={probeResult.authenticated ? "ok" : "fail"}
                      {probeResult.error ? ` · ${probeResult.error}` : ""}
                    </div>
                  )}
                </div>
              )}
            </section>
          </div>
        )}

        {tab === "mac" && (
          <div className="space-y-4">
            <MacLookup />
            {macQuickResult && (
              <div className="noc-panel p-4 text-sm text-noc-muted">
                Header search returned {macQuickResult.hits.length} hit(s) for{" "}
                <span className="font-mono text-cyan-300">{macQuickResult.normalized_mac}</span>.
              </div>
            )}
          </div>
        )}

        {tab === "baseline" && (
          <ConfigDiff devices={devices} selectedHostname={selectedHost} />
        )}
      </main>

      {commandsModal && (
        <CliCommandsModal
          title={commandsModal.title}
          commands={commandsModal.commands}
          onClose={() => setCommandsModal(null)}
        />
      )}
    </div>
  );
}
