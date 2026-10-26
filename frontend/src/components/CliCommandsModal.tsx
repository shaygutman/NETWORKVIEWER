import { useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "../api/client";

interface CliCommandsModalProps {
  title: string;
  hostname: string;
  commands: string[];
  onClose: () => void;
}

function isShowCommand(command: string): boolean {
  return command.trim().toLowerCase().startsWith("show ");
}

export function CliCommandsModal({ title, hostname, commands, onClose }: CliCommandsModalProps) {
  const [customCommand, setCustomCommand] = useState("");
  const [activeCommand, setActiveCommand] = useState<string | null>(null);
  const [output, setOutput] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  async function runCommand(command: string) {
    const trimmed = command.trim();
    if (!trimmed) return;

    if (!isShowCommand(trimmed)) {
      setError("Only read-only commands that begin with \"show \" are allowed.");
      setOutput(null);
      setActiveCommand(trimmed);
      return;
    }

    setLoading(true);
    setError(null);
    setCopied(false);
    setActiveCommand(trimmed);
    setOutput(null);

    try {
      const result = await api.execCommand(hostname, trimmed);
      if (!result.success) {
        setError(result.error || "Command failed on the switch.");
        setOutput(result.output || null);
      } else {
        setOutput(result.output);
      }
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Failed to execute command";
      setError(message);
      setOutput(null);
    } finally {
      setLoading(false);
    }
  }

  function handleCustomSubmit(event: FormEvent) {
    event.preventDefault();
    void runCommand(customCommand);
  }

  async function copyOutput() {
    if (!output) return;
    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Could not copy output to clipboard.");
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="noc-panel flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden p-5">
        <div className="mb-4 flex shrink-0 items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-white">CLI Recommendations</h3>
            <p className="text-sm text-noc-muted">{title}</p>
          </div>
          <button type="button" className="noc-btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
              Recommended show commands — click to run
            </p>
            <ul className="space-y-2">
              {commands.map((command) => {
                const isActive = activeCommand === command;
                return (
                  <li key={command}>
                    <button
                      type="button"
                      className={`w-full rounded-lg border px-3 py-2 text-left font-mono text-sm transition disabled:cursor-wait disabled:opacity-60 ${
                        isActive
                          ? "border-cyan-500/60 bg-cyan-950/40 text-cyan-100"
                          : "border-noc-border bg-slate-950/70 text-cyan-200 hover:border-cyan-500/40 hover:bg-slate-900"
                      }`}
                      onClick={() => void runCommand(command)}
                      disabled={loading}
                      title={`Run on ${hostname}`}
                    >
                      {command}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>

          <form onSubmit={handleCustomSubmit} className="space-y-2">
            <label htmlFor="cli-custom-command" className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Custom show command
            </label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                id="cli-custom-command"
                className="noc-input font-mono"
                placeholder="show interfaces status"
                value={customCommand}
                onChange={(e) => setCustomCommand(e.target.value)}
                disabled={loading}
                autoComplete="off"
                spellCheck={false}
              />
              <button type="submit" className="noc-btn shrink-0" disabled={loading || !customCommand.trim()}>
                Run
              </button>
            </div>
          </form>

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                Output / console
                {activeCommand ? (
                  <span className="ml-2 normal-case tracking-normal text-slate-400">
                    · {activeCommand}
                  </span>
                ) : null}
              </p>
              <button
                type="button"
                className="noc-btn-ghost text-xs"
                onClick={() => void copyOutput()}
                disabled={!output || loading}
              >
                {copied ? "Copied" : "Copy Output"}
              </button>
            </div>

            <div className="min-h-[12rem] rounded-lg border border-noc-border bg-slate-950/90 p-3">
              {loading ? (
                <div className="flex h-48 flex-col items-center justify-center gap-3 text-sm text-slate-400">
                  <span
                    className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-cyan-500/30 border-t-cyan-400"
                    aria-hidden
                  />
                  <span>Running on {hostname} via SSH…</span>
                </div>
              ) : error && !output ? (
                <p className="text-sm text-rose-300">{error}</p>
              ) : output ? (
                <div className="space-y-2">
                  {error ? <p className="text-sm text-rose-300">{error}</p> : null}
                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-emerald-200/90">
                    {output}
                  </pre>
                </div>
              ) : (
                <p className="flex h-48 items-center justify-center text-sm text-slate-500">
                  Click a recommended command or run a custom show command to see output here.
                </p>
              )}
            </div>
          </div>
        </div>

        <p className="mt-4 shrink-0 text-xs text-slate-500">
          Read-only show commands only. The assistant never pushes configuration changes.
        </p>
      </div>
    </div>
  );
}
