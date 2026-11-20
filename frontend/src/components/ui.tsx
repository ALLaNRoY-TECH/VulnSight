import type { ReactNode } from "react";
import type { Severity, Status } from "../lib/api";

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff3b6b",
  high: "#ff8a3d",
  medium: "#fbbf24",
  low: "#38bdf8",
  info: "#94a3b8",
};

export const GRADE_COLOR = (grade: string | null | undefined) => {
  if (!grade) return "#64748b";
  if (grade.startsWith("A")) return "#4ade80";
  if (grade === "B") return "#a3e635";
  if (grade === "C") return "#fbbf24";
  if (grade === "D") return "#ff8a3d";
  return "#ff3b6b";
};

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

export function SeverityBadge({ severity, status }: { severity: Severity; status?: Status }) {
  const label = status === "pass" ? "pass" : severity;
  const color = status === "pass" ? "#4ade80" : SEV_COLOR[severity];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider"
      style={{ color, background: `${color}1a`, boxShadow: `inset 0 0 0 1px ${color}40` }}
    >
      <span className="size-1.5 rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
      {label}
    </span>
  );
}

export function GradeBadge({ grade, size = "md" }: { grade: string | null; size?: "sm" | "md" }) {
  const color = GRADE_COLOR(grade);
  return (
    <span
      className={cx(
        "inline-grid place-items-center rounded-lg font-bold",
        size === "sm" ? "size-8 text-sm" : "size-11 text-lg",
      )}
      style={{ color, background: `${color}14`, boxShadow: `inset 0 0 0 1px ${color}55, 0 0 18px ${color}22` }}
    >
      {grade ?? "–"}
    </span>
  );
}

export function Logo({ className = "size-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden>
      <defs>
        <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#a855f7" />
        </linearGradient>
      </defs>
      <path d="M32 6 54 15v15c0 14-9.3 24.4-22 28C19.3 54.4 10 44 10 30V15Z" fill="none" stroke="url(#lg)" strokeWidth="4" />
      <circle cx="32" cy="31" r="8" fill="none" stroke="url(#lg)" strokeWidth="4" />
      <circle cx="32" cy="31" r="3" fill="#22d3ee" />
    </svg>
  );
}

export function GithubIcon({ className = "size-4" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden>
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.39-5.26 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={cx("glass rounded-2xl print-break", className)}>{children}</div>;
}

export function SectionTitle({ icon, children, right }: { icon?: ReactNode; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">
        {icon && <span className="text-neon">{icon}</span>}
        {children}
      </h3>
      {right}
    </div>
  );
}

export function timeAgo(iso: string) {
  const s = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export const GITHUB_URL = "https://github.com/ALLaNRoY-TECH/VulnSight";
