import type {
  AuthToken,
  BaselineDiffResponse,
  ConnectivityProbeResult,
  DeviceSummary,
  MacLookupResponse,
  SwitchDetail,
  SwitchOverview,
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
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* ignore parse errors */
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
  /** Fleet overview. Pass refresh=true for manual Refresh / auto-refresh (bypass TTL cache). */
  overview(refresh = false) {
    const qs = refresh ? "?refresh=true" : "";
    return request<SwitchOverview[]>(`/api/devices/overview${qs}`);
  },
  /** Switch detail. Cached by default; refresh=true forces a live SSH collect. */
  deviceDetail(hostname: string, refresh = false) {
    const qs = refresh ? "?refresh=true" : "";
    return request<SwitchDetail>(
      `/api/devices/${encodeURIComponent(hostname)}${qs}`,
    );
  },
  /** Live Test SSH — always bypasses cache. Uses Bearer session credentials. */
  probeDevice(hostname: string) {
    return request<ConnectivityProbeResult>(
      `/api/devices/${encodeURIComponent(hostname)}/probe`,
    );
  },
  recommendedCommands(hostname: string, port?: string) {
    const qs = port ? `?port=${encodeURIComponent(port)}` : "";
    return request<string[]>(`/api/devices/${encodeURIComponent(hostname)}/commands${qs}`);
  },
  macLookup(mac: string, hostname?: string) {
    return request<MacLookupResponse>("/api/mac/lookup", {
      method: "POST",
      body: JSON.stringify({ mac, hostname: hostname || null }),
    });
  },
  baselineDiff(hostname: string) {
    return request<BaselineDiffResponse>(`/api/baseline/${encodeURIComponent(hostname)}`);
  },
};
