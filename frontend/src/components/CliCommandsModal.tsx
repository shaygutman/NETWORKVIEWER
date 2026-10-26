interface CliCommandsModalProps {
  title: string;
  commands: string[];
  onClose: () => void;
}

export function CliCommandsModal({ title, commands, onClose }: CliCommandsModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="noc-panel w-full max-w-lg p-5">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-white">CLI Recommendations</h3>
            <p className="text-sm text-noc-muted">{title}</p>
          </div>
          <button className="noc-btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>
        <ul className="space-y-2">
          {commands.map((command) => (
            <li
              key={command}
              className="rounded-lg border border-noc-border bg-slate-950/70 px-3 py-2 font-mono text-sm text-cyan-200"
            >
              {command}
            </li>
          ))}
        </ul>
        <p className="mt-4 text-xs text-slate-500">
          Read-only show commands only. The assistant never pushes configuration changes.
        </p>
      </div>
    </div>
  );
}
