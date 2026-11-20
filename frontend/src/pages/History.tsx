import { motion } from "framer-motion";
import { ArrowRight, Loader2, Radar as RadarIcon, Search, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, SEVERITIES, type ScanSummary } from "../lib/api";
import { Card, GradeBadge, SEV_COLOR, timeAgo } from "../components/ui";

export default function History() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [q, setQ] = useState("");

  const load = () => api.listScans().then(setScans).catch(() => setScans([]));
  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(
    () => (scans ?? []).filter((s) => (s.host || s.target).toLowerCase().includes(q.toLowerCase())),
    [scans, q],
  );

  const remove = async (id: string) => {
    if (!confirm("Delete this scan from history?")) return;
    await api.deleteScan(id).catch((e) => alert(e.message));
    load();
  };

  return (
    <div className="pt-12">
      <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="font-mono text-xs uppercase tracking-[0.25em] text-neon">// history</div>
          <h1 className="mt-2 text-4xl font-bold">Scan history</h1>
          <p className="mt-2 text-slate-400">Every assessment is stored locally in SQLite. Open one to see its full report.</p>
        </div>
        <label className="glass flex items-center gap-2 rounded-xl px-3">
          <Search className="size-4 text-slate-500" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter by host…"
            className="h-10 w-56 bg-transparent text-sm focus:outline-none"
          />
        </label>
      </div>

      {scans === null ? (
        <div className="grid place-items-center py-20">
          <Loader2 className="size-8 animate-spin text-neon" />
        </div>
      ) : filtered.length === 0 ? (
        <Card className="p-14 text-center">
          <RadarIcon className="mx-auto mb-4 size-10 text-neon" />
          <h2 className="text-xl font-semibold">No scans yet</h2>
          <p className="mt-2 text-slate-400">Run your first assessment to populate the history.</p>
          <Link to="/" className="mt-6 inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-neon to-neon-2 px-4 py-2 font-semibold text-ink-950">
            Start scanning <ArrowRight className="size-4" />
          </Link>
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="hidden grid-cols-[56px_1.6fr_1fr_1.4fr_110px_40px] gap-4 border-b border-line px-5 py-3 font-mono text-[10px] uppercase tracking-widest text-slate-500 md:grid">
            <span>Grade</span>
            <span>Target</span>
            <span>Score</span>
            <span>Findings</span>
            <span>When</span>
            <span />
          </div>
          {filtered.map((s, i) => (
            <motion.div
              key={s.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              className="group grid grid-cols-[48px_1fr_40px] items-center gap-4 border-b border-line/60 px-5 py-3.5 transition last:border-0 hover:bg-white/[0.02] md:grid-cols-[56px_1.6fr_1fr_1.4fr_110px_40px]"
            >
              <GradeBadge grade={s.status === "completed" ? s.grade : s.status === "failed" ? "!" : "…"} size="sm" />
              <Link to={`/scan/${s.id}`} className="min-w-0">
                <div className="truncate font-mono text-sm text-slate-100 group-hover:text-neon">{s.host || s.target}</div>
                <div className="font-mono text-[11px] text-slate-500 md:hidden">
                  {s.status === "completed" ? `${s.score}/100` : s.status} · {timeAgo(s.created_at)}
                </div>
              </Link>
              <div className="hidden md:block">
                {s.status === "completed" ? (
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-20 overflow-hidden rounded-full bg-white/[0.06]">
                      <div className="h-full rounded-full bg-gradient-to-r from-neon to-neon-2" style={{ width: `${s.score}%` }} />
                    </div>
                    <span className="font-mono text-sm tabular-nums">{s.score}</span>
                  </div>
                ) : (
                  <span className="font-mono text-xs text-slate-500">{s.status}</span>
                )}
              </div>
              <div className="hidden gap-1.5 md:flex">
                {s.counts &&
                  SEVERITIES.filter((k) => k !== "info").map((k) => (
                    <span
                      key={k}
                      title={k}
                      className="rounded px-1.5 py-0.5 font-mono text-[11px] font-bold"
                      style={{ color: s.counts![k] ? SEV_COLOR[k] : "#334155", background: s.counts![k] ? `${SEV_COLOR[k]}14` : "transparent" }}
                    >
                      {k[0].toUpperCase()}
                      {s.counts![k]}
                    </span>
                  ))}
              </div>
              <span className="hidden font-mono text-xs text-slate-500 md:block">{timeAgo(s.created_at)}</span>
              <button
                onClick={() => remove(s.id)}
                disabled={s.status === "running" || s.status === "queued"}
                className="rounded-md p-2 text-slate-600 transition hover:bg-sev-critical/10 hover:text-sev-critical disabled:opacity-30"
                aria-label="Delete scan"
              >
                <Trash2 className="size-4" />
              </button>
            </motion.div>
          ))}
        </Card>
      )}
    </div>
  );
}
