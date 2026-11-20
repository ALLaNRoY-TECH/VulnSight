import { Globe, KeyRound, Lock, Mail, Network, Server } from "lucide-react";
import { useState } from "react";
import type { Scan } from "../lib/api";
import { Card, SEV_COLOR, SectionTitle, cx } from "./ui";

function Row({ k, v, mono = true }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3 border-b border-line/60 py-2 text-sm last:border-0">
      <span className="text-slate-500">{k}</span>
      <span className={cx("whitespace-pre-line break-all text-slate-200", mono && "font-mono text-[12.5px]")}>{v ?? "—"}</span>
    </div>
  );
}

export function SitePanel({ scan }: { scan: Scan }) {
  const s = scan.site;
  const t = scan.data.target;
  return (
    <Card className="p-5">
      <SectionTitle icon={<Globe className="size-4" />}>Target</SectionTitle>
      <Row k="Host" v={scan.host} />
      <Row k="IP addresses" v={t?.addresses?.join(", ")} />
      {s ? (
        <>
          <Row k="Final URL" v={s.final_url} />
          <Row k="Status" v={`${s.status_code} · ${s.http_version}`} />
          <Row k="Response" v={`${s.response_ms} ms`} />
          <Row k="Server" v={s.server} />
          {s.title && <Row k="Page title" v={s.title} mono={false} />}
          {s.redirects.length > 0 && <Row k="Redirects" v={s.redirects.length} />}
        </>
      ) : (
        <Row k="HTTP" v="no response" />
      )}
    </Card>
  );
}

export function TlsPanel({ scan }: { scan: Scan }) {
  const d = scan.data.tls;
  if (!d) return null;
  const c = d.certificate;
  const protos: Record<string, boolean | null> = d.protocols || {};
  return (
    <Card className="p-5">
      <SectionTitle icon={<Lock className="size-4" />}>Certificate & protocols</SectionTitle>
      {!d.available ? (
        <p className="text-sm text-slate-400">{d.available === false ? "No TLS service on port " + d.port : "TLS handshake timed out."}</p>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-4 gap-2">
            {["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"].map((p) => {
              const on = protos[p];
              const legacy = p === "TLSv1.0" || p === "TLSv1.1";
              const color = on == null ? "#475569" : on ? (legacy ? SEV_COLOR.high : "#4ade80") : legacy ? "#4ade80" : "#64748b";
              return (
                <div key={p} className="rounded-lg border p-2 text-center" style={{ borderColor: `${color}55`, background: `${color}10` }}>
                  <div className="font-mono text-[11px] text-slate-400">{p.replace("TLSv", "TLS ")}</div>
                  <div className="mt-0.5 text-xs font-bold" style={{ color }}>
                    {on == null ? "n/a" : on ? "ON" : "OFF"}
                  </div>
                </div>
              );
            })}
          </div>
          {c && (
            <>
              <Row k="Subject" v={c.subject} />
              <Row k="Issuer" v={c.issuer} />
              <Row
                k="Expires"
                v={
                  <span style={{ color: c.days_left < 0 ? SEV_COLOR.critical : c.days_left < 30 ? SEV_COLOR.medium : undefined }}>
                    {new Date(c.not_after).toLocaleDateString()} ({c.days_left} days)
                  </span>
                }
              />
              <Row k="Key" v={`${c.key_type} ${c.key_size} bits`} />
              <Row k="Signature" v={c.signature_hash?.toUpperCase()} />
              <Row k="Cipher" v={`${d.negotiated?.version} · ${d.negotiated?.cipher}`} />
              <Row k="SANs" v={`${c.san_count} name(s)${c.sans?.length ? ": " + c.sans.slice(0, 4).join(", ") + (c.san_count > 4 ? "…" : "") : ""}`} />
              <Row
                k="Trusted"
                v={
                  <span className="inline-flex items-center gap-1.5" style={{ color: d.trusted ? "#4ade80" : d.trusted === false ? SEV_COLOR.critical : "#94a3b8" }}>
                    <KeyRound className="size-3.5" /> {d.trusted ? "yes" : d.trusted === false ? "no" : "unknown"}
                  </span>
                }
              />
            </>
          )}
        </>
      )}
    </Card>
  );
}

export function PortsPanel({ scan }: { scan: Scan }) {
  const d = scan.data.ports;
  if (!d) return null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const open: any[] = d.open || [];
  return (
    <Card className="p-5">
      <SectionTitle icon={<Network className="size-4" />} right={<span className="font-mono text-xs text-slate-500">{open.length}/{d.probed} open</span>}>
        Open ports
      </SectionTitle>
      {open.length === 0 ? (
        <p className="text-sm text-slate-400">No common ports answered on {d.ip}.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left font-mono text-[10px] uppercase tracking-widest text-slate-500">
                <th className="pb-2">Port</th>
                <th className="pb-2">Service</th>
                <th className="pb-2">Risk</th>
                <th className="pb-2 text-right">RTT</th>
              </tr>
            </thead>
            <tbody>
              {open.map((p) => (
                <tr key={p.port} className="border-t border-line/60">
                  <td className="py-2 font-mono text-cyan-200">{p.port}/tcp</td>
                  <td className="py-2">
                    {p.service}
                    {p.banner && <div className="max-w-[220px] truncate font-mono text-[11px] text-slate-500">{p.banner}</div>}
                    {p.confirmed === false && <div className="font-mono text-[11px] text-slate-500">unconfirmed · no banner</div>}
                  </td>
                  <td className="py-2">
                    <span className="font-mono text-[11px] font-bold uppercase" style={{ color: SEV_COLOR[p.risk as keyof typeof SEV_COLOR] }}>
                      {p.risk}
                    </span>
                  </td>
                  <td className="py-2 text-right font-mono text-xs text-slate-400">{p.latency_ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export function DnsPanel({ scan }: { scan: Scan }) {
  const d = scan.data.dns;
  if (!d || !d.apex) return null;
  const rec = (label: string, vals: string[] | undefined) => (
    <Row k={label} v={vals && vals.length ? vals.slice(0, 4).join("\n") : <span className="text-slate-600">none</span>} />
  );
  return (
    <Card className="p-5">
      <SectionTitle icon={<Mail className="size-4" />}>DNS records · {d.apex}</SectionTitle>
      {rec("A", d.a)}
      {rec("AAAA", d.aaaa)}
      {rec("MX", d.mx)}
      {rec("NS", d.ns)}
      {rec("SPF", d.spf)}
      {rec("DMARC", d.dmarc)}
      {rec("CAA", d.caa)}
    </Card>
  );
}

export function HeadersPanel({ scan }: { scan: Scan }) {
  const [open, setOpen] = useState(false);
  const h = scan.site?.headers;
  if (!h) return null;
  const entries = Object.entries(h);
  return (
    <Card className="p-5">
      <SectionTitle
        icon={<Server className="size-4" />}
        right={
          <button onClick={() => setOpen((o) => !o)} className="no-print font-mono text-xs text-neon hover:underline">
            {open ? "collapse" : `show all ${entries.length}`}
          </button>
        }
      >
        Raw response headers
      </SectionTitle>
      <pre className="max-h-[420px] overflow-auto rounded-lg border border-line bg-black/40 p-3 font-mono text-[11.5px] leading-relaxed">
        {(open ? entries : entries.slice(0, 8)).map(([k, v]) => (
          <div key={k} className="break-all">
            <span className="text-neon">{k}</span>
            <span className="text-slate-500">: </span>
            <span className="text-slate-300">{v}</span>
          </div>
        ))}
      </pre>
    </Card>
  );
}
