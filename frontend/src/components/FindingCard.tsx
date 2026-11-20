import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown, Copy, ExternalLink, Wrench } from "lucide-react";
import { useState } from "react";
import type { Finding } from "../lib/api";
import { MODULES } from "../lib/api";
import { SEV_COLOR, SeverityBadge, cx } from "./ui";

export default function FindingCard({ f, index, defaultOpen = false }: { f: Finding; index: number; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);
  const color = f.status === "pass" ? "#4ade80" : SEV_COLOR[f.severity];
  const mod = MODULES.find((m) => m.id === f.module);

  const copy = async () => {
    if (!f.remediation) return;
    try {
      await navigator.clipboard.writeText(f.remediation.replace(/`/g, ""));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.035, 0.5) }}
      className="glass print-break group relative overflow-hidden rounded-xl"
    >
      <span className="absolute inset-y-0 left-0 w-1" style={{ background: color, boxShadow: `0 0 16px ${color}` }} />
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 py-3.5 pl-5 pr-4 text-left transition hover:bg-white/[0.02]"
        aria-expanded={open}
      >
        <SeverityBadge severity={f.severity} status={f.status} />
        <span className="flex-1 font-medium text-slate-100">{f.title}</span>
        <span className="hidden font-mono text-[11px] text-slate-500 sm:inline">{mod?.short}</span>
        <ChevronDown className={cx("size-4 shrink-0 text-slate-500 transition", open && "rotate-180")} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden"
          >
            <div className="space-y-4 border-t border-line py-4 pl-5 pr-4 text-sm">
              {f.description && <p className="leading-relaxed text-slate-300">{f.description}</p>}
              {f.evidence && (
                <div>
                  <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">Evidence</div>
                  <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-black/40 p-3 font-mono text-xs text-cyan-200/90">
                    {f.evidence}
                  </pre>
                </div>
              )}
              {f.remediation && (
                <div className="rounded-lg border border-acid/20 bg-acid/[0.05] p-3">
                  <div className="mb-1.5 flex items-center justify-between">
                    <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-acid">
                      <Wrench className="size-3" /> Remediation
                    </span>
                    <button onClick={copy} className="no-print flex items-center gap-1 text-xs text-slate-400 hover:text-white">
                      {copied ? <Check className="size-3.5 text-acid" /> : <Copy className="size-3.5" />}
                      {copied ? "copied" : "copy"}
                    </button>
                  </div>
                  <p className="leading-relaxed text-slate-200">
                    {f.remediation.split(/(`[^`]+`)/g).map((part, i) =>
                      part.startsWith("`") ? (
                        <code key={i} className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[12px] text-acid">
                          {part.slice(1, -1)}
                        </code>
                      ) : (
                        <span key={i}>{part}</span>
                      ),
                    )}
                  </p>
                </div>
              )}
              {f.references.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {f.references.map((r) => (
                    <a
                      key={r}
                      href={r}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 font-mono text-[11px] text-slate-400 transition hover:border-neon/50 hover:text-neon"
                    >
                      <ExternalLink className="size-3" />
                      {new URL(r).hostname.replace("www.", "")}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
