import { useState } from "react";

interface SearchCoverageBannerProps {
  warning?: string | null;
  devicesFailed: number;
  devicesFromCache?: number;
  unreachableHosts?: string[];
  errors?: string[];
}

/**
 * Collapsible aggregate warning for unreachable switches during fleet search.
 * Keeps raw per-switch errors tucked away instead of dumping them in the panel.
 */
export function SearchCoverageBanner({
  warning,
  devicesFailed,
  devicesFromCache = 0,
  unreachableHosts = [],
  errors = [],
}: SearchCoverageBannerProps) {
  const [expanded, setExpanded] = useState(false);

  if (devicesFailed <= 0 && !warning) {
    return null;
  }

  const summary =
    warning ||
    (devicesFromCache > 0
      ? `${devicesFailed} switch(es) unreachable — showing results from cache`
      : `${devicesFailed} switch(es) unreachable`);

  const hostList =
    unreachableHosts.length > 0
      ? unreachableHosts
      : errors.map((line) => line.split(":")[0]?.trim()).filter(Boolean);

  return (
    <div className="border-t border-amber-500/30 bg-amber-500/10 px-5 py-3 text-sm text-amber-100">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p>{summary}</p>
        {(hostList.length > 0 || errors.length > 0) && (
          <button
            type="button"
            className="shrink-0 text-xs text-amber-200/90 underline-offset-2 hover:underline"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Hide details" : "Show details"}
          </button>
        )}
      </div>
      {expanded && (
        <div className="mt-2 space-y-1 font-mono text-xs text-amber-200/80">
          {hostList.length > 0 && (
            <p>
              Unreachable: {hostList.join(", ")}
              {devicesFromCache > 0 ? ` · cache used for ${devicesFromCache}` : ""}
            </p>
          )}
          {errors.map((msg) => (
            <div key={msg}>{msg}</div>
          ))}
        </div>
      )}
    </div>
  );
}
