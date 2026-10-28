import type {
  AddDeviceRequest,
  AddDeviceResponse,
  AuthToken,
  BaselineDiffResponse,
  ConnectivityProbeResult,
  DeviceSummary,
  ExecCommandResponse,
  MacLookupResponse,
  SwitchDetail,
  SwitchOverview,
  TrackerSearchResponse,
  UserInfo,
} from "../types";

const TOKEN_KEY = "noa_token";
const USER_KEY = "noa_user";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): UserInfo | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserInfo;
  } catch {
    return null;
  }
}

export function storeSession(auth: AuthToken): void {
  localStorage.setItem(TOKEN_KEY, auth.access_token);
  localStorage.setItem(USER_KEY, JSON.stringify(auth.user));
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  const token = getStoredToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) {
    clearSession();
    throw new ApiError("Session expired. Please sign in again.", 401);
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    const raw = await response.text();
    try {
      const body = JSON.parse(raw) as { detail?: string | unknown };
      if (typeof body.detail === "string" && body.detail) {
        detail = body.detail;
      }
    } catch {
      if (/Request Header Or Cookie Too Large/i.test(raw)) {
        detail =
          "Session token too large for the web proxy. Sign out, then sign in again after the server update.";
      }
    }
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  login(username: string, password: string) {
    return request<AuthToken>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  },
  async logout() {
    const token = getStoredToken();
    try {
      if (token) {
        await fetch("/api/auth/logout", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
      }
    } finally {
      clearSession();
    }
  },
  me() {
    return request<UserInfo>("/api/auth/me");
  },
  listDevices() {
    return request<DeviceSummary[]>("/api/devices");
  },
  /** Register a switch after a read-only SSH check (session credentials only). */
  addDevice(body: AddDeviceRequest) {
    return request<AddDeviceResponse>("/api/devices", {
      method: "POST",
      body: JSON.stringify(body),
    });
  },
  /** Fleet overview. Default = local cache only (no SSH). refresh=true = on-demand live collect. */
  overview(refresh = false) {
    const qs = refresh ? "?refresh=true" : "";
    return request<SwitchOverview[]>(`/api/devices/overview${qs}`);
  },
  /** Switch detail. Default = local cache only (no SSH). refresh=true = on-demand live collect. */
  deviceDetail(hostname: string, refresh = false) {
    const qs = refresh ? "?refresh=true" : "";
    return request<SwitchDetail>(
      `/api/devices/${encodeURIComponent(hostname)}${qs}`,
    );
  },
  /** Live Test SSH — always live collect + cache update. Uses Bearer session credentials. */
  probeDevice(hostname: string) {
    return request<ConnectivityProbeResult>(
      `/api/devices/${encodeURIComponent(hostname)}/probe`,
    );
  },
  recommendedCommands(hostname: string, port?: string) {
    const qs = port ? `?port=${encodeURIComponent(port)}` : "";
    return request<string[]>(`/api/devices/${encodeURIComponent(hostname)}/commands${qs}`);
  },
  /** Run one read-only show command on a switch (backend enforces show-only safety gate). */
  execCommand(hostname: string, command: string) {
    return request<ExecCommandResponse>(
      `/api/devices/${encodeURIComponent(hostname)}/exec-command`,
      {
        method: "POST",
        body: JSON.stringify({ command }),
      },
    );
  },
  macLookup(mac: string, hostname?: string) {
    return request<MacLookupResponse>("/api/mac/lookup", {
      method: "POST",
      body: JSON.stringify({ mac, hostname: hostname || null }),
    });
  },
  /** Global IP / MAC / hostname tracker (read-only fleet search). */
  trackerSearch(query: string, hostname?: string) {
    return request<TrackerSearchResponse>("/api/tracker/search", {
      method: "POST",
      body: JSON.stringify({ query, hostname: hostname || null }),
    });
  },
  baselineDiff(hostname: string) {
    return request<BaselineDiffResponse>(`/api/baseline/${encodeURIComponent(hostname)}`);
  },
};
