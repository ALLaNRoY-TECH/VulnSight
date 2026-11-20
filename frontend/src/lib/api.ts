export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "fail" | "warn" | "pass" | "info";
export type ModuleId = "headers" | "tls" | "ports" | "exposure" | "dns";
export type ModuleState = "pending" | "running" | "done" | "error";

export interface Finding {
  id: string;
  module: ModuleId;
  title: string;
  status: Status;
  severity: Severity;
  description: string;
  evidence: string | null;
  remediation: string | null;
  references: string[];
}

export type Counts = Record<Severity, number>;

export interface LogLine {
  t: string;
  level: "info" | "ok" | "warn" | "error";
  msg: string;
}

export interface Scan {
  id: string;
  target: string;
  host: string | null;
  status: "queued" | "running" | "completed" | "failed";
  created_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  modules: Partial<Record<ModuleId, ModuleState>>;
  log: LogLine[];
  progress: number;
  score: number | null;
  grade: string | null;
  counts: Counts | null;
  findings: Finding[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: Record<string, any>;
  site: {
    requested_url: string;
    final_url: string;
    status_code: number;
    http_version: string;
    response_ms: number;
    redirects: string[];
    server: string | null;
    content_type: string | null;
    title: string;
    headers: Record<string, string>;
  } | null;
  error: string | null;
}

export type ScanSummary = Pick<
  Scan,
  "id" | "target" | "host" | "status" | "created_at" | "finished_at" | "score" | "grade" | "counts"
>;

export interface Stats {
  total_scans: number;
  completed: number;
  avg_score: number | null;
  issues: Counts;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) msg = typeof body.detail === "string" ? body.detail : body.detail[0]?.msg ?? msg;
    } catch {
      /* not json */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export const api = {
  startScan: (target: string, modules: ModuleId[], authorized: boolean) =>
    request<{ id: string }>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ target, modules, authorized }),
    }),
  getScan: (id: string) => request<Scan>(`/api/scans/${id}`),
  listScans: () => request<ScanSummary[]>("/api/scans"),
  deleteScan: (id: string) => request<{ deleted: string }>(`/api/scans/${id}`, { method: "DELETE" }),
  stats: () => request<Stats>("/api/stats"),
  health: () => request<{ status: string; version: string }>("/api/health"),
};

export const MODULES: { id: ModuleId; label: string; short: string; blurb: string }[] = [
  { id: "headers", label: "HTTP Security Headers", short: "Headers", blurb: "CSP, HSTS, framing, MIME sniffing, referrer & permissions policies, version leaks." },
  { id: "tls", label: "SSL / TLS", short: "SSL/TLS", blurb: "Certificate trust, expiry, key strength, protocol versions TLS 1.0 → 1.3 and cipher suites." },
  { id: "ports", label: "Ports & Services", short: "Ports", blurb: "Concurrent TCP scan of 30 high-risk ports with banner grabbing — databases, RDP, SMB, Redis…" },
  { id: "exposure", label: "Misconfiguration & Exposure", short: "Exposure", blurb: "Exposed .git / .env / backups, CORS reflection, cookie flags, HTTPS redirects, directory listing." },
  { id: "dns", label: "DNS & Email Security", short: "DNS", blurb: "SPF, DMARC and CAA records that stop domain spoofing and rogue certificate issuance." },
];

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
