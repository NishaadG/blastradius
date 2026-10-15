"use client";

import clsx from "clsx";
import { ReactNode, useState } from "react";
import type { Trace } from "@/lib/api";

export function Label({ children, right, className }: { children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <div className={clsx("mb-2 flex items-baseline justify-between", className)}>
      <h3 className="label">{children}</h3>
      {right}
    </div>
  );
}

/** Priority as a small square-cornered stamp, not a pill. */
export function Priority({ p }: { p: string | null }) {
  if (!p) return null;
  const hot = p === "P0";
  return (
    <span
      className={clsx(
        "mono inline-block min-w-[28px] border px-1 py-[3px] text-center text-[10.5px] font-semibold leading-none",
        hot ? "border-red bg-red text-paper" : p === "P1" ? "border-ink text-ink" : "border-rule-strong text-faint",
      )}
    >
      {p}
    </span>
  );
}

export function Severity({ s }: { s: string }) {
  const c = s === "CRITICAL" ? "text-red" : s === "HIGH" ? "text-amber" : "text-faint";
  return <span className={clsx("label !text-[10px]", c)}>{s.toLowerCase()}</span>;
}

export const VERDICT: Record<string, { word: string; color: string }> = {
  AFFECTED: { word: "Affected", color: "text-red" },
  NOT_AFFECTED: { word: "Not affected", color: "text-green" },
  NEEDS_HUMAN: { word: "Needs a human", color: "text-amber" },
};

const TOKEN =
  /(\b(?:MATCH|WHERE|RETURN|WITH|OPTIONAL|UNION|ORDER BY|LIMIT|CALL|YIELD|DISTINCT|AS|AND|OR|NOT|IN|CONTAINS|IS NULL|IS NOT NULL|UNWIND|MERGE|CREATE|SET)\b|\b(?:shortestPath|length|nodes|collect|coalesce|min|count|toLower|any)(?=\()|\$\w+|'[^']*')/g;
const FUNCS = new Set(["shortestPath", "length", "nodes", "collect", "coalesce", "min", "count", "toLower", "any"]);

export function Cypher({ trace }: { trace: Trace }) {
  const [open, setOpen] = useState(false);
  const parts = trace.cypher.split(TOKEN);
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="mono flex w-full items-baseline gap-2 py-0.5 text-left text-[11px] text-faint hover:text-ink"
      >
        <span className="w-2 shrink-0">{open ? "−" : "+"}</span>
        <span className="truncate">{trace.cypher.slice(0, 70)}…</span>
        <span className="num ml-auto shrink-0 text-ink-2">{trace.ms} ms</span>
        <span className="num shrink-0">{trace.rows}r</span>
      </button>
      {open && (
        <pre className="mono scroll my-1 max-h-48 overflow-auto whitespace-pre-wrap break-words border-l-2 border-rule-strong bg-sunk px-3 py-2 text-[11px] leading-[1.6] text-ink-2">
          {parts.map((p, i) => {
            if (!p) return null;
            if (p.startsWith("$")) return <span key={i} className="text-amber">{p}</span>;
            if (p.startsWith("'")) return <span key={i} className="text-green">{p}</span>;
            if (FUNCS.has(p)) return <span key={i} className="text-blue">{p}</span>;
            if (i % 2 === 1) return <span key={i} className="font-semibold text-ink">{p}</span>;
            return <span key={i}>{p}</span>;
          })}
        </pre>
      )}
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="border-y border-dashed border-rule-strong py-6">
      <div className="serif text-[17px]">{title}</div>
      {hint && <div className="mt-1 max-w-[34ch] text-[13px] text-ink-2">{hint}</div>}
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="mono py-6 text-[11px] text-faint">{what}…</div>;
}

export function timeAgo(ts: number) {
  const s = Math.max(1, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}
