import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle, CheckCircle2, Clock, Download, FileJson, Loader2, Printer, RefreshCw, ShieldAlert, XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import FindingCard from "../components/FindingCard";
import { DnsPanel, HeadersPanel, PortsPanel, SitePanel, TlsPanel } from "../components/Panels";
import { Radar, ScoreRing, SeverityBars, Terminal } from "../components/Visuals";
import { Card, SEV_COLOR, SectionTitle, cx } from "../components/ui";
import { api, MODULES, SEVERITIES, type ModuleId, type Scan, type Severity } from "../lib/api";

function useScan(id: string) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const s = await api.getScan(id);
        if (!alive) return;
        setScan(s);
        if (s.status === "queued" || s.status === "running") timer = setTimeout(tick, 700);
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [id]);
  return { scan, error };
}

const STATE_ICON = {
  pending: <Clock className="size-4 text-slate-500" />,
  running: <Loader2 className="size-4 animate-spin text-neon" />,
  done: <CheckCircle2 className="size-4 text-acid" />,
  error: <XCircle className="size-4 text-sev-critical" />,
};

function LiveView({ scan }: { scan: Scan }) {
  return (
    <div className="grid grid-cols-1 gap-6 pt-10 lg:grid-cols-[0.9fr_1.1fr]">
      <Card className="relative overflow-hidden p-8">
        <Radar size={300} label={`SCANNING ${scan.host ?? scan.target}`.toUpperCase()} />
        <div className="mt-14">
          <div className="mb-2 flex justify-between font-mono text-xs text-slate-400">
            <span>progress</span>
            <span className="text-neon">{scan.progress}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
            <motion.div
              className="relative h-full rounded-full bg-gradient-to-r from-neon to-neon-2 shadow-[0_0_16px_#22d3ee]"
              animate={{ width: `${scan.progress}%` }}
              transition={{ ease: "easeOut" }}
            >
              <span className="shimmer absolute inset-0" />
            </motion.div>
          </div>
        </div>
      </Card>
      <div className="min-w-0 space-y-4">
        <Card className="p-5">
          <SectionTitle>Modules</SectionTitle>
          <div className="grid gap-2 sm:grid-cols-2">
            {MODULES.filter((m) => scan.modules[m.id]).map((m) => {
              const st = scan.modules[m.id]!;
              return (
                <div
                  key={m.id}
                  className={cx(
                    "flex items-center gap-3 rounded-lg border px-3 py-2.5 text-sm transition",
                    st === "running" ? "border-neon/40 bg-neon/[0.06]" : "border-line",
                  )}
                >
                  {STATE_ICON[st]}
                  <span className={st === "pending" ? "text-slate-500" : "text-slate-200"}>{m.label}</span>
                </div>
              );
            })}
          </div>
        </Card>
        <Terminal lines={scan.log} live />
      </div>
    </div>
  );
}

function Report({ scan }: { scan: Scan }) {
  const nav = useNavigate();
  const [mod, setMod] = useState<ModuleId | "all">("all");
  const [sev, setSev] = useState<Severity | "all">("all");
  const [tab, setTab] = useState<"issues" | "passed">("issues");
  const [rescanning, setRescanning] = useState(false);

  const issues = scan.findings.filter((f) => f.status === "fail" || f.status === "warn");
  const informational = scan.findings.filter((f) => f.status === "info");
  const passed = scan.findings.filter((f) => f.status === "pass");
  const list = useMemo(() => {
    const base = tab === "issues" ? [...issues, ...informational] : passed;
    return base.filter((f) => (mod === "all" || f.module === mod) && (sev === "all" || f.severity === sev || tab === "passed"));
  }, [scan, mod, sev, tab]); // eslint-disable-line react-hooks/exhaustive-deps

  const counts = scan.counts!;
  const worst = SEVERITIES.find((s) => counts[s] > 0 && s !== "info");
  const rescan = async () => {
    setRescanning(true);
    try {
      const mods = Object.keys(scan.modules) as ModuleId[];
      const { id } = await api.startScan(scan.target, mods, true);
      nav(`/scan/${id}`);
    } catch (e) {
      alert((e as Error).message);
      setRescanning(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="pt-10">
      {/* --------------------------------------------------------- Header */}
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="font-mono text-xs uppercase tracking-[0.25em] text-neon">// security report</div>
          <h1 className="mt-2 break-all text-3xl font-bold sm:text-4xl">{scan.host}</h1>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-slate-500">
            <span>id {scan.id}</span>
            <span>{new Date(scan.created_at).toLocaleString()}</span>
            <span>{((scan.duration_ms ?? 0) / 1000).toFixed(1)}s</span>
            <span>{scan.findings.length} checks</span>
          </div>
        </div>
        <div className="no-print flex flex-wrap gap-2">
          <button onClick={rescan} disabled={rescanning} className="btn-ghost flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm text-slate-300 transition hover:border-neon/50 hover:text-white">
            <RefreshCw className={cx("size-4", rescanning && "animate-spin")} /> Rescan
          </button>
          <a href={`/api/scans/${scan.id}/report.md`} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm text-slate-300 transition hover:border-neon/50 hover:text-white">
            <Download className="size-4" /> Markdown
          </a>
          <a href={`/api/scans/${scan.id}/report.json`} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm text-slate-300 transition hover:border-neon/50 hover:text-white">
            <FileJson className="size-4" /> JSON
          </a>
          <button onClick={() => window.print()} className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-neon to-neon-2 px-3 py-2 text-sm font-semibold text-ink-950">
            <Printer className="size-4" /> PDF
          </button>
        </div>
      </div>

      {/* --------------------------------------------------------- Score row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[auto_1fr_1fr]">
        <Card className="glow-border flex items-center justify-center p-6">
          <ScoreRing score={scan.score ?? 0} grade={scan.grade} />
        </Card>
        <Card className="p-6">
          <SectionTitle icon={<ShieldAlert className="size-4" />}>Risk breakdown</SectionTitle>
          <SeverityBars counts={counts} />
          <p className="mt-5 text-sm text-slate-400">
            {worst ? (
              <>
                <span className="font-semibold" style={{ color: SEV_COLOR[worst] }}>
                  {issues.length} issue{issues.length === 1 ? "" : "s"}
                </span>{" "}
                found — fix <span style={{ color: SEV_COLOR[worst] }}>{worst}</span> severity items first.
              </>
            ) : (
              <span className="text-acid">No security issues detected. Excellent hygiene.</span>
            )}
          </p>
        </Card>
        <SitePanel scan={scan} />
      </div>

      {/* --------------------------------------------------------- Module score tiles */}
      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        {MODULES.filter((m) => scan.modules[m.id]).map((m) => {
          const fs = scan.findings.filter((f) => f.module === m.id);
          const bad = fs.filter((f) => f.status === "fail" || f.status === "warn");
          const ok = fs.filter((f) => f.status === "pass").length;
          const errored = scan.modules[m.id] === "error";
          const top = SEVERITIES.find((s) => bad.some((b) => b.severity === s));
          const color = errored ? "#64748b" : top ? SEV_COLOR[top] : "#4ade80";
          return (
            <button
              key={m.id}
              onClick={() => {
                setMod(mod === m.id ? "all" : m.id);
                setTab("issues");
              }}
              className={cx("glass rounded-xl p-4 text-left transition hover:-translate-y-0.5", mod === m.id && "ring-1 ring-neon")}
            >
              <div className="text-xs text-slate-400">{m.short}</div>
              <div className="mt-1 text-2xl font-bold" style={{ color }}>
                {errored ? "—" : bad.length}
              </div>
              <div className="font-mono text-[11px] text-slate-500">{errored ? "module error" : `issues · ${ok} passed`}</div>
            </button>
          );
        })}
      </div>

      {/* --------------------------------------------------------- Findings + side panels */}
      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[1.35fr_1fr]">
        <div className="min-w-0">
          <div className="no-print mb-4 flex flex-wrap items-center gap-2">
            <div className="flex rounded-lg border border-line p-1">
              {(["issues", "passed"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={cx("rounded-md px-3 py-1.5 text-sm capitalize transition", tab === t ? "bg-white/10 text-white" : "text-slate-400")}
                >
                  {t === "issues" ? <AlertTriangle className="mr-1.5 inline size-3.5" /> : <CheckCircle2 className="mr-1.5 inline size-3.5" />}
                  {t} <span className="font-mono text-xs text-slate-500">{t === "issues" ? issues.length : passed.length}</span>
                </button>
              ))}
            </div>
            {tab === "issues" && (
              <div className="flex flex-wrap gap-1">
                {(["all", ...SEVERITIES] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSev(s)}
                    className={cx(
                      "rounded-md border px-2 py-1 font-mono text-[11px] uppercase transition",
                      sev === s ? "border-white/30 bg-white/10 text-white" : "border-line text-slate-500 hover:text-slate-300",
                    )}
                    style={s !== "all" && sev === s ? { color: SEV_COLOR[s], borderColor: `${SEV_COLOR[s]}66` } : undefined}
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
            {mod !== "all" && (
              <button onClick={() => setMod("all")} className="rounded-md border border-neon/40 px-2 py-1 font-mono text-[11px] text-neon">
                {mod} ✕
              </button>
            )}
          </div>
          <div className="space-y-2.5">
            <AnimatePresence mode="popLayout">
              {list.map((f, i) => (
                <FindingCard key={`${tab}-${f.module}-${f.id}`} f={f} index={i} defaultOpen={i === 0 && tab === "issues"} />
              ))}
            </AnimatePresence>
            {list.length === 0 && (
              <Card className="p-10 text-center text-slate-400">
                <CheckCircle2 className="mx-auto mb-3 size-8 text-acid" />
                Nothing matches this filter.
              </Card>
            )}
          </div>
        </div>
        <div className="min-w-0 space-y-4">
          <TlsPanel scan={scan} />
          <PortsPanel scan={scan} />
          <DnsPanel scan={scan} />
          <HeadersPanel scan={scan} />
          <div className="no-print">
            <Terminal lines={scan.log} />
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export default function ScanPage() {
  const { id = "" } = useParams();
  const { scan, error } = useScan(id);

  if (error)
    return (
      <div className="pt-24 text-center">
        <XCircle className="mx-auto mb-4 size-12 text-sev-critical" />
        <h1 className="text-2xl font-bold">Scan not found</h1>
        <p className="mt-2 text-slate-400">{error}</p>
        <Link to="/" className="mt-6 inline-block text-neon hover:underline">← Start a new scan</Link>
      </div>
    );
  if (!scan)
    return (
      <div className="grid place-items-center pt-32">
        <Loader2 className="size-8 animate-spin text-neon" />
      </div>
    );
  if (scan.status === "failed")
    return (
      <div className="mx-auto max-w-2xl pt-20">
        <Card className="p-8 text-center">
          <XCircle className="mx-auto mb-4 size-12 text-sev-critical" />
          <h1 className="text-2xl font-bold">Scan could not be completed</h1>
          <p className="mt-3 text-slate-300">{scan.error}</p>
          <Link to="/" className="mt-6 inline-block rounded-lg bg-gradient-to-r from-neon to-neon-2 px-4 py-2 font-semibold text-ink-950">
            Try another target
          </Link>
        </Card>
        <Terminal lines={scan.log} className="mt-6" />
      </div>
    );
  if (scan.status !== "completed") return <LiveView scan={scan} />;
  return <Report scan={scan} />;
}
