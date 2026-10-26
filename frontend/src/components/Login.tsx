import { useState } from "react";
import type { FormEvent } from "react";
import { api, storeSession } from "../api/client";
import type { UserInfo } from "../types";

interface LoginProps {
  onSuccess: (user: UserInfo) => void;
}

export function Login({ onSuccess }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const auth = await api.login(username.trim(), password);
      // Browser keeps only the JWT + user profile — never persist the password
      storeSession(auth);
      setPassword("");
      onSuccess(auth.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="noc-panel w-full max-w-md p-8">
        <div className="mb-8 text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            ent.core.medtronic.com
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">Network Operations Assistant</h1>
          <p className="mt-2 text-sm text-noc-muted">
            Sign in with your Medtronic ENT account. Credentials stay in server memory only for
            this session and are used for read-only switch SSH — never written to disk.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" autoComplete="on">
          <label className="block space-y-1.5">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
              ENT Username
            </span>
            <input
              className="noc-input"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username@ent.core.medtronic.com"
              required
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
              Password
            </span>
            <input
              className="noc-input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>

          {error && (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          <button type="submit" className="noc-btn w-full" disabled={loading}>
            {loading ? "Signing in to ENT…" : "Sign in with ENT"}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-slate-500">
          Passwords are held encrypted in server memory for this session only, then wiped on logout
          or expiry.
        </p>
      </div>
    </div>
  );
}
