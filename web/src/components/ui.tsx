"use client";

import clsx from "clsx";
import { ReactNode, useState } from "react";
import { ChevronRight } from "lucide-react";
import type { Trace } from "@/lib/api";

type Tone = "neutral" | "bad" | "warn" | "good" | "accent" | "violet";

const TONES: Record<Tone, string> = {
  neutral: "text-muted border-line-strong bg-surface-2",
  bad: "text-bad border-bad/40 bg-bad/10",
  warn: "text-warn border-warn/40 bg-warn/10",
  good: "text-good border-good/40 bg-good/10",
  accent: "text-accent border-accent/40 bg-accent/10",
  violet: "text-violet border-violet/40 bg-violet/10",
};

export function Pill({ tone = "neutral", children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-none tracking-wide",
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function PriorityBadge({ p }: { p: string | null }) {
  if (!p) return null;
  const tone: Tone = p === "P0" ? "bad" : p === "P1" ? "warn" : p === "P2" ? "neutral" : "neutral";
  return <Pill tone={tone} className="mono font-semibold">{p}</Pill>;
}

export function SevBadge({ s }: { s: string }) {
  const tone: Tone = s === "CRITICAL" ? "bad" : s === "HIGH" ? "warn" : s === "UNKNOWN" ? "neutral" : "violet";
  return <Pill tone={tone}>{s}</Pill>;
}

export function VerdictBadge({ v }: { v: string }) {
  const map: Record<string, [Tone, string]> = {
    AFFECTED: ["bad", "AFFECTED"],
    NOT_AFFECTED: ["good", "NOT AFFECTED"],
    NEEDS_HUMAN: ["warn", "NEEDS HUMAN"],
  };
  const [tone, label] = map[v] ?? ["neutral", v];
  return <Pill tone={tone} className="px-2 py-1 text-xs font-semibold">{label}</Pill>;
}

export function Label({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between">
      <h3 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-faint">{children}</h3>
      {right}
    </div>
  );
}

const TOKEN =
  /(\b(?:MATCH|WHERE|RETURN|WITH|OPTIONAL|UNION|ORDER BY|LIMIT|CALL|YIELD|DISTINCT|AS|AND|OR|NOT|IN|CONTAINS|IS NULL|IS NOT NULL|UNWIND|MERGE|CREATE|SET)\b|\b(?:shortestPath|length|nodes|collect|coalesce|min|count|toLower|any)(?=\()|\$\w+|'[^']*')/g;

const FUNCS = new Set(["shortestPath", "length", "nodes", "collect", "coalesce", "min", "count", "toLower", "any"]);

export function Cypher({ trace, defaultOpen = false }: { trace: Trace; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const parts = trace.cypher.split(TOKEN);
  return (
    <div className="rounded-lg border border-line bg-bg/70">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-[11px] text-muted hover:text-fg"
        aria-expanded={open}
      >
        <ChevronRight className={clsx("h-3 w-3 transition-transform", open && "rotate-90")} />
        <span className="mono truncate">{trace.cypher.slice(0, 64)}…</span>
        <span className="mono ml-auto shrink-0 text-accent">{trace.ms}ms</span>
        <span className="mono shrink-0 text-faint">{trace.rows} rows</span>
      </button>
      {open && (
        <pre className="mono scroll max-h-52 overflow-auto whitespace-pre-wrap break-words border-t border-line px-3 py-2 text-[11px] leading-5 text-[#b8c4dc]">
          {parts.map((p, i) => {
            if (!p) return null;
            if (p.startsWith("$")) return <span key={i} className="text-warn">{p}</span>;
            if (p.startsWith("'")) return <span key={i} className="str">{p}</span>;
            if (FUNCS.has(p)) return <span key={i} className="fn">{p}</span>;
            if (i % 2 === 1) return <span key={i} className="kw">{p}</span>;
            return <span key={i}>{p}</span>;
          })}
        </pre>
      )}
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded-xl border border-dashed border-line-strong px-4 py-8 text-center">
      <div className="text-sm font-medium text-fg">{title}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={clsx("inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent/30 border-t-accent", className)}
      aria-label="Loading"
    />
  );
}

export function timeAgo(ts: number) {
  const s = Math.max(1, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}
