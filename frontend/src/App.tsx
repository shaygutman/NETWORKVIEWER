import { useEffect, useState } from "react";
import { clearSession, getStoredToken, getStoredUser } from "./api/client";
import { Dashboard } from "./components/Dashboard";
import { Login } from "./components/Login";
import type { UserInfo } from "./types";

export default function App() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    const token = getStoredToken();
    const stored = getStoredUser();
    if (token && stored) {
      setUser(stored);
    } else {
      clearSession();
    }
    setBooting(false);
  }, []);

  if (booting) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-noc-muted">
        Loading…
      </div>
    );
  }

  if (!user) {
    return <Login onSuccess={setUser} />;
  }

  return <Dashboard user={user} onLogout={() => setUser(null)} />;
}
