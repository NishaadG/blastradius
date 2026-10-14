"use client";

import clsx from "clsx";
import { motion } from "framer-motion";
import { Bot, BookMarked, ExternalLink, GitCommit, History, RotateCcw, User } from "lucide-react";
import { useEffect, useState } from "react";
import { api, Brain, GraphData, Risk, ServiceCard } from "@/lib/api";
import { Cypher, Empty, Label, Pill, PriorityBadge, SevBadge, Spinner, timeAgo } from "./ui";

/* ------------------------------------------------------------------ risk board */
export function RiskBoard({ risk, activeId, onPick }: { risk: Risk | null; activeId?: string; onPick: (id: string) => void }) {
  if (!risk) return <div className="flex justify-center py-10"><Spinner /></div>;
  const total = risk.advisories.length || 1;
  const bar: [string, string, string][] = [
    ["P0", "bg-bad", "critical + internet-reachable"],
    ["P1", "bg-warn", "critical, or high + reachable"],
    ["P2", "bg-faint", "everything else"],
  ];
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-3 grid grid-cols-3 gap-2">
        {bar.map(([p, c, hint]) => (
          <div key={p} className="rounded-xl border border-line bg-surface-2/60 p-2.5" title={hint}>
            <div className="flex items-baseline justify-between">
              <span className="mono text-[11px] text-muted">{p}</span>
              <span className="text-lg font-semibold tabular-nums">{risk.summary[p] ?? 0}</span>
            </div>
            <div className="mt-1.5 h-1 rounded-full bg-line">
              <div className={clsx("h-1 rounded-full", c)} style={{ width: `${((risk.summary[p] ?? 0) / total) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
      <Label>Ranked by severity × exposure</Label>
      <ul className="scroll -mr-2 flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto pr-2">
        {risk.advisories.map((a) => (
          <li key={a.id}>
            <button
              onClick={() => onPick(a.cve ?? a.id)}
              className={clsx(
                "w-full rounded-xl border p-2.5 text-left transition",
                activeId === a.id ? "border-accent/60 bg-accent/5" : "border-line bg-surface-2/40 hover:border-line-strong hover:bg-surface-2",
              )}
            >
              <div className="flex items-center gap-1.5">
                <PriorityBadge p={a.priority} />
                <SevBadge s={a.severity} />
                <span className="mono ml-auto truncate text-[11px] text-muted">{a.cve ?? a.id}</span>
              </div>
              <div className="mt-1.5 line-clamp-2 text-xs leading-snug text-[#c3cce0]">{a.summary}</div>
              <div className="mono mt-1 truncate text-[10.5px] text-faint">
                {a.packages[0]} → {a.services.join(", ")}
              </div>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------------ memory */
export function MemoryView({ brain, onReset }: { brain: Brain | null; onReset: () => void }) {
  if (!brain) return <div className="flex justify-center py-10"><Spinner /></div>;
  const reused = brain.cases.reduce((a, c) => a + c.reused, 0);
  const stats: [string, number][] = [
    ["triage runs", brain.runs],
    ["cases remembered", brain.cases.length],
    ["precedents reused", reused],
  ];
  return (
    <div className="scroll -mr-2 flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto pr-2">
      <div className="grid grid-cols-3 gap-2">
        {stats.map(([k, v]) => (
          <motion.div key={k} layout className="rounded-xl border border-line bg-surface-2/60 p-2.5">
            <div className="text-xl font-semibold tabular-nums">{v}</div>
            <div className="text-[10.5px] leading-tight text-muted">{k}</div>
          </motion.div>
        ))}
      </div>
      <section>
        <Label>Episodic · cases</Label>
        {brain.cases.length === 0 ? (
          <Empty title="Memory is empty" hint="Triage a CVE and approve a decision. The next related advisory will cite it." />
        ) : (
          <ol className="relative ml-1.5 border-l border-line-strong pl-4">
            {[...brain.cases].reverse().map((c) => (
              <li key={c.id} className="relative pb-3">
                <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-violet bg-bg" />
                <div className="flex items-center gap-2 text-xs">
                  <span className="mono text-violet">{c.id}</span>
                  <Pill tone={c.decision === "patched" ? "good" : "warn"}>{c.decision.replace("_", " ")}</Pill>
                  <span className="ml-auto text-faint">{timeAgo(c.ts)}</span>
                </div>
                <div className="mt-0.5 text-[11px] text-muted">
                  by {c.actor} · cited by <b className="text-fg">{c.reused}</b> later triage{c.reused === 1 ? "" : "s"}
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>
      <section>
        <Label>Procedural · playbooks</Label>
        <div className="flex flex-col gap-2">
          {brain.playbooks.map((p) => {
            const t = p.successes + p.failures || 1;
            return (
              <div key={p.key} className="rounded-xl border border-line bg-surface-2/60 p-3">
                <div className="flex items-center gap-2 text-xs">
                  <BookMarked className="h-3.5 w-3.5 text-violet" />
                  <span className="mono">{p.key}</span>
                  <span className="mono ml-auto text-good">{p.successes}✓</span>
                  <span className="mono text-bad">{p.failures}✗</span>
                </div>
                <div className="mt-2 h-1 rounded-full bg-line">
                  <div className="h-1 rounded-full bg-good" style={{ width: `${(p.successes / t) * 100}%` }} />
                </div>
                <p className="mt-2 text-[11px] leading-snug text-muted">{p.steps}</p>
              </div>
            );
          })}
        </div>
      </section>
      <button onClick={onReset} className="mb-1 flex items-center justify-center gap-1.5 rounded-lg border border-line-strong py-2 text-xs text-muted transition hover:border-bad hover:text-bad">
        <RotateCcw className="h-3.5 w-3.5" /> Reset demo memory
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ company brain */
export function CompanyView({
  tenant,
  overview,
  selected,
  onSelect,
}: {
  tenant: string;
  overview: GraphData | null;
  selected: string | null;
  onSelect: (s: string) => void;
}) {
  const [card, setCard] = useState<ServiceCard | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selected) {
      setCard(null);
      setLoading(false);
      return;
    }
    let live = true;
    setLoading(true);
    api
      .service(tenant, selected)
      .then((c) => live && setCard(c))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [tenant, selected]);

  const services = [...(overview?.nodes ?? [])].sort((a, b) => b.centrality - a.centrality);
  const humans = card?.experts.filter((e) => e.kind !== "bot") ?? [];
  const bots = card?.experts.filter((e) => e.kind === "bot") ?? [];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="flex flex-wrap gap-1.5">
        {services.map((s) => (
          <button
            key={s.id}
            onClick={() => onSelect(s.id)}
            className={clsx(
              "rounded-lg border px-2 py-1 text-[11px] transition",
              selected === s.id ? "border-accent bg-accent/10 text-accent" : "border-line-strong text-muted hover:text-fg",
            )}
          >
            {s.id}
          </button>
        ))}
      </div>
      <div className="scroll -mr-2 min-h-0 flex-1 overflow-y-auto pr-2">
        {!selected && <Empty title="Pick a service" hint="Ownership, expertise and the decisions behind its dependencies, each traced to a source commit." />}
        {loading && <div className="flex justify-center py-8"><Spinner /></div>}
        {card && !loading && (
          <div className="flex flex-col gap-5">
            <section>
              <Label>Owners · CODEOWNERS</Label>
              <div className="flex flex-wrap gap-1.5">
                {card.owners.length ? card.owners.map((o) => (
                  <Pill key={o.owner} tone={o.kind === "team" ? "violet" : "neutral"} className="max-w-full !leading-tight break-all py-1">
                    <User className="h-3 w-3 shrink-0" /> {o.owner}
                  </Pill>
                )) : <span className="text-xs text-muted">No CODEOWNERS entry. Nobody is accountable.</span>}
              </div>
            </section>
            <section>
              <Label>Expertise · commit history</Label>
              <div className="flex flex-col gap-1">
                {humans.map((e) => (
                  <div key={e.name} className="flex items-center gap-2 text-xs">
                    <User className="h-3 w-3 text-muted" />
                    <span>{e.name}</span>
                    <span className="mono ml-auto text-faint">{e.commits} commits</span>
                  </div>
                ))}
                {humans.length === 0 && <span className="text-xs text-muted">No human commits to this service's manifest. It is maintained by automation.</span>}
                {bots.map((e) => (
                  <div key={e.name} className="flex items-center gap-2 text-xs text-muted">
                    <Bot className="h-3 w-3" /> {e.name}
                    <span className="mono ml-auto text-faint">{e.commits} commits</span>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <Label>Decisions · traced to source</Label>
              <div className="flex flex-col gap-2">
                {card.decisions.length === 0 && <span className="text-xs text-muted">No recorded dependency decisions.</span>}
                {card.decisions.map((d) => (
                  <a key={d.id} href={d.source} target="_blank" rel="noreferrer"
                     className="group rounded-xl border border-line bg-surface-2/50 p-2.5 transition hover:border-line-strong">
                    <div className="flex items-start gap-2 text-xs leading-snug">
                      <GitCommit className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
                      <span>{d.text}</span>
                    </div>
                    <div className="mt-1.5 flex items-center gap-2 text-[10.5px] text-faint">
                      <span>{d.author}</span>·<span>{d.date.slice(0, 10)}</span>
                      {d.superseded_by ? <Pill tone="warn" className="ml-auto"><History className="h-3 w-3" /> superseded</Pill> : <Pill tone="good" className="ml-auto">current</Pill>}
                      <ExternalLink className="h-3 w-3 opacity-0 transition group-hover:opacity-100" />
                    </div>
                  </a>
                ))}
              </div>
            </section>
            <section>
              <Label>Graph queries</Label>
              <div className="flex flex-col gap-1">{card.traces.slice(0, 3).map((t, i) => <Cypher key={i} trace={t} />)}</div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
