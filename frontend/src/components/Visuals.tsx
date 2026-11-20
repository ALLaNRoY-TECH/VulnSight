import { motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import type { Counts, LogLine } from "../lib/api";
import { SEVERITIES } from "../lib/api";
import { GRADE_COLOR, SEV_COLOR, cx } from "./ui";

/* ---------------------------------------------------------------- Radar */
const BLIPS = [
  { x: 28, y: 32, d: 0 },
  { x: 68, y: 26, d: 0.8 },
  { x: 74, y: 66, d: 1.6 },
  { x: 36, y: 72, d: 2.1 },
  { x: 52, y: 44, d: 1.1 },
];

export function Radar({ size = 320, active = true, label }: { size?: number; active?: boolean; label?: string }) {
  return (
    <div className="relative mx-auto aspect-square w-full" style={{ maxWidth: size }}>
      <div className="absolute inset-0 rounded-full border border-neon/25 bg-[radial-gradient(circle,rgba(34,211,238,0.10),transparent_70%)]" />
      {[0.25, 0.5, 0.75].map((r) => (
        <div
          key={r}
          className="absolute rounded-full border border-neon/15"
          style={{ inset: `${r * 50}%` }}
        />
      ))}
      <div className="absolute left-1/2 top-0 h-full w-px bg-neon/15" />
      <div className="absolute left-0 top-1/2 h-px w-full bg-neon/15" />
      {active && <div className="radar-sweep absolute inset-0 rounded-full" />}
      {active &&
        BLIPS.map((b, i) => (
          <span key={i} className="absolute" style={{ left: `${b.x}%`, top: `${b.y}%` }}>
            <span className="blip absolute -left-1.5 -top-1.5 size-3 rounded-full border border-neon" style={{ animationDelay: `${b.d}s` }} />
            <span className="absolute -left-1 -top-1 size-2 rounded-full bg-neon shadow-[0_0_12px_#22d3ee]" />
          </span>
        ))}
      <div className="absolute inset-[44%] rounded-full bg-neon/30 blur-md" />
      <div className="absolute inset-[47%] rounded-full bg-neon shadow-[0_0_24px_#22d3ee]" />
      {label && (
        <div className="absolute inset-x-0 -bottom-8 text-center font-mono text-xs tracking-widest text-neon/80">
          {label}
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------------- Count-up */
export function CountUp({ value, duration = 1.4 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let raf = 0;
    const t0 = performance.now();
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / (duration * 1000));
      const eased = 1 - Math.pow(1 - p, 4);
      setDisplay(Math.round(value * eased));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    // Guarantee the final value even if rAF is throttled (background tab, print, headless).
    const done = setTimeout(() => setDisplay(value), duration * 1000 + 100);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(done);
    };
  }, [value, duration]);
  return <>{display}</>;
}

/* ---------------------------------------------------------------- Score ring */
export function ScoreRing({ score, grade, size = 220 }: { score: number; grade: string | null; size?: number }) {
  const r = 88;
  const c = 2 * Math.PI * r;
  const color = GRADE_COLOR(grade);
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg viewBox="0 0 200 200" className="size-full -rotate-90">
        <defs>
          <linearGradient id="ring" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor={color} />
            <stop offset="1" stopColor="#a855f7" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <circle cx="100" cy="100" r={r} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth="12" />
        <circle cx="100" cy="100" r={r + 12} fill="none" stroke="rgba(148,163,184,0.08)" strokeWidth="1" strokeDasharray="2 6" />
        <motion.circle
          cx="100"
          cy="100"
          r={r}
          fill="none"
          stroke="url(#ring)"
          strokeWidth="12"
          strokeLinecap="round"
          filter="url(#glow)"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c - (c * score) / 100 }}
          transition={{ duration: 1.6, ease: [0.16, 1, 0.3, 1] }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-6xl font-bold tabular-nums" style={{ color, textShadow: `0 0 30px ${color}66` }}>
            <CountUp value={score} />
          </div>
          <div className="mt-1 font-mono text-[11px] uppercase tracking-[0.3em] text-slate-400">
            grade <span className="font-bold" style={{ color }}>{grade}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- Severity bars */
export function SeverityBars({ counts }: { counts: Counts }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] ?? 0));
  return (
    <div className="space-y-3">
      {SEVERITIES.filter((s) => s !== "info").map((s, i) => (
        <div key={s} className="grid grid-cols-[72px_1fr_28px] items-center gap-3">
          <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400">{s}</span>
          <div className="h-2.5 overflow-hidden rounded-full bg-white/[0.05]">
            <motion.div
              className="h-full rounded-full"
              style={{ background: `linear-gradient(90deg, ${SEV_COLOR[s]}aa, ${SEV_COLOR[s]})`, boxShadow: `0 0 12px ${SEV_COLOR[s]}88` }}
              initial={{ width: 0 }}
              animate={{ width: `${((counts[s] ?? 0) / max) * 100}%` }}
              transition={{ delay: 0.2 + i * 0.1, duration: 0.9, ease: "easeOut" }}
            />
          </div>
          <span className="text-right font-mono text-sm font-bold tabular-nums" style={{ color: counts[s] ? SEV_COLOR[s] : "#475569" }}>
            {counts[s] ?? 0}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------- Terminal */
const LEVEL_COLOR: Record<LogLine["level"], string> = {
  info: "text-slate-300",
  ok: "text-acid",
  warn: "text-sev-medium",
  error: "text-sev-critical",
};
const LEVEL_TAG: Record<LogLine["level"], string> = { info: "INF", ok: " OK", warn: "WRN", error: "ERR" };

export function Terminal({ lines, live, className }: { lines: LogLine[]; live?: boolean; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [lines.length]);
  return (
    <div className={cx("glass overflow-hidden rounded-2xl", className)}>
      <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
        <span className="size-3 rounded-full bg-[#ff5f57]" />
        <span className="size-3 rounded-full bg-[#febc2e]" />
        <span className="size-3 rounded-full bg-[#28c840]" />
        <span className="ml-3 font-mono text-xs text-slate-500">vulnsight@engine:~$ scan --live</span>
      </div>
      <div ref={ref} className="relative h-72 overflow-y-auto p-4 font-mono text-[12.5px] leading-relaxed">
        {live && <div className="scanline pointer-events-none absolute inset-x-0 top-0 h-24" />}
        {lines.map((l, i) => (
          <motion.div key={i} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="flex gap-3">
            <span className="shrink-0 text-slate-600">{new Date(l.t).toLocaleTimeString([], { hour12: false })}</span>
            <span className={cx("shrink-0 font-bold", LEVEL_COLOR[l.level])}>{LEVEL_TAG[l.level]}</span>
            <span className={cx("break-all", LEVEL_COLOR[l.level])}>{l.msg}</span>
          </motion.div>
        ))}
        {live && <div className="caret mt-1 text-slate-500">&gt;</div>}
      </div>
    </div>
  );
}
