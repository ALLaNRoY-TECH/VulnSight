import { motion } from "framer-motion";
import {
  ArrowRight, Bug, FileText, Globe, Lock, Mail, Network, ScanLine, ShieldCheck, Sparkles, Zap,
} from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, MODULES, type ModuleId, type ScanSummary, type Stats } from "../lib/api";
import { Radar } from "../components/Visuals";
import { Card, GradeBadge, SEV_COLOR, cx, timeAgo } from "../components/ui";

const MODULE_ICON: Record<ModuleId, typeof Lock> = {
  headers: FileText,
  tls: Lock,
  ports: Network,
  exposure: Bug,
  dns: Mail,
};

const DEMOS = [
  { t: "github.com", note: "hardened" },
  { t: "expired.badssl.com", note: "expired cert" },
  { t: "wrong.host.badssl.com", note: "name mismatch" },
  { t: "scanme.nmap.org", note: "open ports" },
];

const TYPED = ["misconfigurations.", "weak TLS.", "exposed services.", "leaky headers.", "spoofable email."];

function Typewriter() {
  const [i, setI] = useState(0);
  const [n, setN] = useState(0);
  const [del, setDel] = useState(false);
  useEffect(() => {
    const word = TYPED[i];
    const t = setTimeout(
      () => {
        if (!del && n < word.length) setN(n + 1);
        else if (!del) setDel(true);
        else if (n > 0) setN(n - 1);
        else {
          setDel(false);
          setI((i + 1) % TYPED.length);
        }
      },
      !del && n === word.length ? 1400 : del ? 35 : 70,
    );
    return () => clearTimeout(t);
  }, [i, n, del]);
  return <span className="caret text-gradient">{TYPED[i].slice(0, n)}</span>;
}

export default function Home() {
  const nav = useNavigate();
  const [target, setTarget] = useState("");
  const [mods, setMods] = useState<ModuleId[]>(MODULES.map((m) => m.id));
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<ScanSummary[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    api.listScans().then((s) => setRecent(s.slice(0, 6))).catch(() => {});
    api.stats().then(setStats).catch(() => {});
  }, []);

  const toggle = (id: ModuleId) =>
    setMods((m) => (m.includes(id) ? (m.length > 1 ? m.filter((x) => x !== id) : m) : [...m, id]));

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setError(null);
    if (!target.trim()) return setError("Enter a domain or URL to scan.");
    if (!authorized) return setError("Please confirm you own or are authorised to test this target.");
    setBusy(true);
    try {
      const { id } = await api.startScan(target.trim(), mods, authorized);
      nav(`/scan/${id}`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div>
      {/* ------------------------------------------------------------ Hero */}
      <section className="grid items-center gap-12 pt-14 pb-16 lg:grid-cols-[1.15fr_0.85fr] lg:pt-20">
        <div>
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 inline-flex items-center gap-2 rounded-full border border-neon/30 bg-neon/[0.06] px-3 py-1 font-mono text-[11px] uppercase tracking-[0.2em] text-neon"
          >
            <Sparkles className="size-3.5" /> Web Security Assessment Platform
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="text-4xl font-bold leading-[1.05] tracking-tight sm:text-6xl"
          >
            See your attack surface
            <br />
            before attackers do.
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.12 }}
            className="mt-5 max-w-xl text-lg text-slate-400"
          >
            VulnSight runs 40+ automated checks in seconds and hunts for <Typewriter />
          </motion.p>

          {/* -------------------------------------------------------- Scan form */}
          <motion.form
            onSubmit={submit}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="glass glow-border mt-8 rounded-2xl p-3"
          >
            <div className="flex flex-col gap-2 sm:flex-row">
              <label className="flex flex-1 items-center gap-3 rounded-xl bg-black/30 px-4">
                <Globe className="size-5 shrink-0 text-neon" />
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="example.com or https://app.example.com"
                  className="h-14 w-full bg-transparent font-mono text-[15px] text-white placeholder:text-slate-600 focus:outline-none"
                  autoFocus
                  spellCheck={false}
                  autoCapitalize="off"
                  aria-label="Target domain or URL"
                />
              </label>
              <button
                type="submit"
                disabled={busy}
                className="group relative flex h-14 items-center justify-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-neon to-neon-2 px-7 font-semibold text-ink-950 shadow-[0_0_30px_rgba(34,211,238,0.35)] transition hover:shadow-[0_0_45px_rgba(34,211,238,0.6)] disabled:opacity-60"
              >
                <span className="shimmer absolute inset-0" />
                <ScanLine className="relative size-5" />
                <span className="relative">{busy ? "Launching…" : "Run scan"}</span>
                <ArrowRight className="relative size-4 transition group-hover:translate-x-1" />
              </button>
            </div>

            <div className="mt-3 flex flex-wrap gap-2 px-1">
              {MODULES.map((m) => {
                const Icon = MODULE_ICON[m.id];
                const on = mods.includes(m.id);
                return (
                  <button
                    type="button"
                    key={m.id}
                    onClick={() => toggle(m.id)}
                    className={cx(
                      "flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition",
                      on
                        ? "border-neon/40 bg-neon/10 text-cyan-100"
                        : "border-line text-slate-500 hover:text-slate-300",
                    )}
                    aria-pressed={on}
                  >
                    <Icon className="size-3.5" /> {m.short}
                  </button>
                );
              })}
            </div>

            <label className="mt-3 flex cursor-pointer items-start gap-2.5 px-1 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 size-4 accent-cyan-400"
              />
              I own this target or have explicit permission to test it. Scans are non-intrusive (no exploitation).
            </label>
            {error && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-red-200">
                {error}
              </motion.div>
            )}
          </motion.form>

          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="font-mono">try:</span>
            {DEMOS.map((d) => (
              <button
                key={d.t}
                onClick={() => setTarget(d.t)}
                className="rounded-md border border-line px-2 py-1 font-mono text-slate-400 transition hover:border-neon/50 hover:text-neon"
                title={d.note}
              >
                {d.t}
              </button>
            ))}
          </div>
        </div>

        <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.15, duration: 0.8 }} className="relative hidden lg:block">
          <Radar size={420} label="PASSIVE RECON · ACTIVE CHECKS" />
          {[
            { t: "TLS 1.3 · AES-256-GCM", c: "#4ade80", x: "-left-6 top-10" },
            { t: "CSP missing", c: SEV_COLOR.medium, x: "-right-4 top-24" },
            { t: "6379/tcp redis", c: SEV_COLOR.critical, x: "-left-2 bottom-24" },
            { t: "DMARC p=reject", c: "#4ade80", x: "right-0 bottom-10" },
          ].map((b, i) => (
            <motion.div
              key={b.t}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: [0, -6, 0] }}
              transition={{ delay: 0.6 + i * 0.2, y: { repeat: Infinity, duration: 4 + i, ease: "easeInOut" } }}
              className={cx("glass absolute rounded-lg px-3 py-1.5 font-mono text-[11px]", b.x)}
              style={{ color: b.c, boxShadow: `0 0 20px ${b.c}22` }}
            >
              ● {b.t}
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ------------------------------------------------------------ Stats strip */}
      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          { k: "Scans run", v: stats?.total_scans ?? 0, icon: ScanLine },
          { k: "Avg. score", v: stats?.avg_score ?? "—", icon: ShieldCheck },
          { k: "Critical / High found", v: stats ? stats.issues.critical + stats.issues.high : 0, icon: Bug },
          { k: "Checks per scan", v: "40+", icon: Zap },
        ].map(({ k, v, icon: Icon }) => (
          <Card key={k} className="p-5">
            <Icon className="mb-3 size-5 text-neon" />
            <div className="text-3xl font-bold tabular-nums">{v}</div>
            <div className="mt-1 text-xs uppercase tracking-wider text-slate-500">{k}</div>
          </Card>
        ))}
      </section>

      {/* ------------------------------------------------------------ Modules */}
      <section className="mt-24">
        <div className="mb-10 max-w-2xl">
          <div className="font-mono text-xs uppercase tracking-[0.25em] text-neon">// scan modules</div>
          <h2 className="mt-3 text-3xl font-bold sm:text-4xl">Five engines. One report.</h2>
          <p className="mt-3 text-slate-400">
            Every module runs concurrently, so a full assessment usually finishes in under 20 seconds — with
            evidence and a concrete fix for every issue.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {MODULES.map((m, i) => {
            const Icon = MODULE_ICON[m.id];
            return (
              <motion.div
                key={m.id}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.07 }}
                whileHover={{ y: -4 }}
                className="glass group relative overflow-hidden rounded-2xl p-6"
              >
                <div className="absolute -right-10 -top-10 size-32 rounded-full bg-neon/10 blur-2xl transition group-hover:bg-neon/25" />
                <div className="mb-4 inline-grid size-11 place-items-center rounded-xl border border-neon/30 bg-neon/10">
                  <Icon className="size-5 text-neon" />
                </div>
                <h3 className="text-lg font-semibold">{m.label}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">{m.blurb}</p>
              </motion.div>
            );
          })}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.35 }}
            className="relative overflow-hidden rounded-2xl border border-neon-2/30 bg-gradient-to-br from-neon-2/15 to-neon/10 p-6"
          >
            <FileText className="mb-4 size-6 text-neon-2" />
            <h3 className="text-lg font-semibold">Actionable reports</h3>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">
              Weighted 0–100 security score, A+→F grade, severity breakdown and export to Markdown, JSON or PDF.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ------------------------------------------------------------ How it works */}
      <section className="mt-24">
        <div className="font-mono text-xs uppercase tracking-[0.25em] text-neon">// pipeline</div>
        <h2 className="mt-3 text-3xl font-bold sm:text-4xl">How a scan works</h2>
        <div className="mt-10 grid gap-4 md:grid-cols-4">
          {[
            ["01", "Scope & resolve", "Target is normalised, resolved and checked against private/internal ranges (SSRF guard)."],
            ["02", "Fingerprint", "Landing page is fetched, redirects followed, server and response metadata recorded."],
            ["03", "Parallel checks", "Headers, TLS, ports, exposure and DNS modules run concurrently with live progress."],
            ["04", "Score & remediate", "Findings are ranked by severity, scored, and paired with copy-paste fixes."],
          ].map(([n, t, d], i) => (
            <motion.div
              key={n}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08 }}
              className="relative"
            >
              <div className="font-mono text-5xl font-bold text-white/[0.06]">{n}</div>
              <div className="-mt-4 h-px bg-gradient-to-r from-neon/60 to-transparent" />
              <h3 className="mt-4 font-semibold">{t}</h3>
              <p className="mt-2 text-sm text-slate-400">{d}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------------ Recent */}
      {recent.length > 0 && (
        <section className="mt-24">
          <div className="mb-6 flex items-end justify-between">
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.25em] text-neon">// recent</div>
              <h2 className="mt-3 text-3xl font-bold">Latest assessments</h2>
            </div>
            <Link to="/history" className="flex items-center gap-1 text-sm text-slate-400 hover:text-neon">
              View all <ArrowRight className="size-4" />
            </Link>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {recent.map((s) => (
              <Link key={s.id} to={`/scan/${s.id}`} className="glass flex items-center gap-4 rounded-xl p-4 transition hover:border-neon/40">
                <GradeBadge grade={s.status === "failed" ? "!" : s.grade} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-sm">{s.host || s.target}</div>
                  <div className="text-xs text-slate-500">
                    {s.status === "completed" ? `${s.score}/100` : s.status} · {timeAgo(s.created_at)}
                  </div>
                </div>
                <ArrowRight className="size-4 text-slate-600" />
              </Link>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
