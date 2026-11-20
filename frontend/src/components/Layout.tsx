import { Activity, History, Radar } from "lucide-react";
import { NavLink, Outlet, Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { cx, GITHUB_URL, GithubIcon, Logo } from "./ui";

export function Background() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden>
      <div className="absolute inset-0 bg-grid" />
      <div className="absolute -top-40 left-1/2 h-[520px] w-[900px] -translate-x-1/2 rounded-full bg-neon/20 blur-[140px]" />
      <div className="absolute top-[40%] -right-40 h-[420px] w-[520px] rounded-full bg-neon-2/15 blur-[140px]" />
      <div className="absolute bottom-0 -left-40 h-[360px] w-[480px] rounded-full bg-cyan-500/10 blur-[120px]" />
    </div>
  );
}

function ApiStatus() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    const ping = () =>
      api.health().then(() => alive && setOk(true)).catch(() => alive && setOk(false));
    ping();
    const t = setInterval(ping, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  const color = ok === null ? "#94a3b8" : ok ? "#4ade80" : "#ff3b6b";
  return (
    <span className="hidden items-center gap-2 rounded-full border border-line px-3 py-1 font-mono text-[11px] text-slate-400 md:inline-flex">
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping rounded-full opacity-60" style={{ background: color }} />
        <span className="relative inline-flex size-2 rounded-full" style={{ background: color }} />
      </span>
      {ok === null ? "connecting" : ok ? "engine online" : "engine offline"}
    </span>
  );
}

export default function Layout() {
  const link = ({ isActive }: { isActive: boolean }) =>
    cx(
      "flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition",
      isActive ? "bg-white/[0.06] text-white" : "text-slate-400 hover:text-white",
    );
  return (
    <div className="noise min-h-screen">
      <Background />
      <header className="no-print sticky top-0 z-40 border-b border-line bg-ink-950/70 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
          <Link to="/" className="group flex items-center gap-2.5">
            <Logo className="size-8 transition group-hover:drop-shadow-[0_0_10px_#22d3ee]" />
            <span className="text-lg font-bold tracking-tight">
              Vuln<span className="text-gradient">Sight</span>
            </span>
          </Link>
          <nav className="flex items-center gap-1">
            <NavLink to="/" end className={link}>
              <Radar className="size-4" /> <span className="hidden sm:inline">Scanner</span>
            </NavLink>
            <NavLink to="/history" className={link}>
              <History className="size-4" /> <span className="hidden sm:inline">History</span>
            </NavLink>
            <ApiStatus />
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              className="ml-1 rounded-lg p-2 text-slate-400 transition hover:bg-white/[0.06] hover:text-white"
              aria-label="Source on GitHub"
            >
              <GithubIcon className="size-5" />
            </a>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 pb-24 sm:px-6">
        <Outlet />
      </main>
      <footer className="no-print border-t border-line py-8 text-center font-mono text-xs text-slate-500">
        <Activity className="mr-1.5 inline size-3.5 text-neon" />
        VulnSight · non-intrusive web security assessment · only scan systems you own or are authorised to test
      </footer>
    </div>
  );
}
