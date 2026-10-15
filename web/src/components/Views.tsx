"use client";

import clsx from "clsx";
import { useEffect, useState } from "react";
import { api, Brain, GraphData, Risk, ServiceCard } from "@/lib/api";
import Bench from "./Bench";
import { Cypher, Empty, Label, Loading, Priority, Severity, timeAgo } from "./ui";

/* ------------------------------------------------------------------ risk board */
export function RiskBoard({ risk, activeId, onPick }: { risk: Risk | null; activeId?: string; onPick: (id: string) => void }) {
  if (!risk) return <Loading what="Ranking advisories" />;
  const cells: [string, string][] = [
    ["P0", "critical and reachable"],
    ["P1", "critical, or high and reachable"],
    ["P2", "the rest"],
  ];
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="grid grid-cols-3 border-y border-rule">
        {cells.map(([p, hint], i) => (
          <div key={p} className={clsx("px-3 py-2.5", i > 0 && "border-l border-rule")}>
            <div className={clsx("serif num text-[30px] leading-none", p === "P0" && "text-red")}>{risk.summary[p] ?? 0}</div>
            <div className="mt-1.5 flex items-baseline gap-1.5">
              <span className="mono text-[10.5px] font-semibold">{p}</span>
              <span className="text-[10.5px] leading-tight text-faint">{hint}</span>
            </div>
          </div>
        ))}
      </div>
      <Label className="mt-4">Ranked by severity, then exposure</Label>
      <ul className="scroll -mr-3 flex min-h-0 flex-1 flex-col overflow-y-auto pr-3">
        {risk.advisories.map((a) => (
          <li key={a.id} className="border-b border-rule">
            <button
              onClick={() => onPick(a.cve ?? a.id)}
              className={clsx(
                "grid w-full grid-cols-[34px_1fr] gap-x-3 border-l-2 py-2.5 pl-2 pr-1 text-left transition-colors hover:bg-sunk",
                activeId === a.id ? "border-ink bg-sunk" : "border-transparent",
              )}
            >
              <div className="pt-0.5"><Priority p={a.priority} /></div>
              <div className="min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="mono truncate text-[11.5px] text-ink-2">{a.cve ?? a.id}</span>
                  <Severity s={a.severity} />
                </div>
                <div className="mt-0.5 line-clamp-2 text-[13px] leading-snug">{a.summary}</div>
                <div className="mono mt-1 truncate text-[10.5px] text-faint">
                  {a.packages[0]} → {a.services.join(", ")}
                </div>
              </div>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------------ memory */
export function MemoryView({ tenant, brain, onReset }: { tenant: string; brain: Brain | null; onReset: () => void }) {
  if (!brain) return <Loading what="Reading memory" />;
  const reused = brain.cases.reduce((a, c) => a + c.reused, 0);
  const stats: [number, string][] = [
    [brain.runs, "triage runs"],
    [brain.cases.length, "cases kept"],
    [reused, "times reused"],
  ];
  return (
    <div className="scroll -mr-3 flex min-h-0 flex-1 flex-col overflow-y-auto pr-3">
      <div className="grid grid-cols-3 border-y border-rule">
        {stats.map(([n, k], i) => (
          <div key={k} className={clsx("px-3 py-2.5", i > 0 && "border-l border-rule")}>
            <div className="serif num text-[30px] leading-none">{n}</div>
            <div className="mt-1.5 text-[10.5px] text-faint">{k}</div>
          </div>
        ))}
      </div>

      <section className="mt-5">
        <Label>Episodic · cases</Label>
        {brain.cases.length === 0 ? (
          <Empty title="Nothing remembered yet" hint="Triage a CVE and approve a decision. The next related advisory will cite it." />
        ) : (
          <ol>
            {[...brain.cases].reverse().map((c) => (
              <li key={c.id} className="border-b border-rule py-2.5">
                <div className="flex items-baseline gap-2 text-[12.5px]">
                  <span className="mono text-blue">{c.id}</span>
                  <span className="font-medium capitalize">{c.decision.replace("_", " ")}</span>
                  <span className="ml-auto text-faint">{timeAgo(c.ts)}</span>
                </div>
                <div className="mt-0.5 text-[12px] text-ink-2">
                  by {c.actor} · cited by {c.reused} later triage{c.reused === 1 ? "" : "s"}
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="mt-6">
        <Label>Procedural · playbooks</Label>
        <ul>
          {brain.playbooks.map((p) => {
            const total = p.successes + p.failures;
            return (
              <li key={p.key} className="border-b border-rule py-2.5">
                <div className="mono text-[12px] break-words">{p.key}</div>
                <div className="mono num mt-0.5 flex gap-3 whitespace-nowrap text-[11px]">
                  <span className="text-green">{p.successes} worked</span>
                  <span className={p.failures ? "text-red" : "text-faint"}>{p.failures} failed</span>
                </div>
                <div className="mt-1.5 h-[3px] bg-rule">
                  <div className="h-[3px] bg-green" style={{ width: total ? `${(p.successes / total) * 100}%` : 0 }} />
                </div>
                <p className="mt-1.5 text-[12px] leading-snug text-ink-2">{p.steps}</p>
              </li>
            );
          })}
        </ul>
      </section>

      <Bench tenant={tenant} />

      <button onClick={onReset} className="btn btn-quiet my-5 self-start">Reset my memory</button>
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
  const [loaded, setLoaded] = useState<{ key: string; card: ServiceCard } | null>(null);

  useEffect(() => {
    if (!selected) return;
    let live = true;
    api
      .service(tenant, selected)
      .then((c) => live && setLoaded({ key: `${tenant}/${selected}`, card: c }))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [tenant, selected]);

  const card = selected && loaded?.key === `${tenant}/${selected}` ? loaded.card : null;
  const loading = !!selected && !card;
  const services = [...(overview?.nodes ?? [])].sort((a, b) => b.centrality - a.centrality);
  const humans = card?.experts.filter((e) => e.kind !== "bot") ?? [];
  const bots = card?.experts.filter((e) => e.kind === "bot") ?? [];

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Label>Services · by PageRank</Label>
      <div className="flex flex-wrap gap-x-3.5 gap-y-1.5 border-b border-rule pb-3">
        {services.map((s) => (
          <button
            key={s.id}
            onClick={() => onSelect(s.id)}
            className={clsx(
              "text-[12.5px] underline-offset-4 hover:underline",
              selected === s.id ? "font-semibold underline decoration-2" : "text-ink-2",
            )}
          >
            {s.id}
          </button>
        ))}
      </div>

      <div className="scroll -mr-3 min-h-0 flex-1 overflow-y-auto pr-3 pt-4">
        {!selected && <Empty title="Pick a service" hint="Who owns it, who knows it, and the decisions behind its dependencies, each traced to a commit." />}
        {loading && <Loading what="Querying the graph" />}
        {card && (
          <div className="fade-in">
            <h3 className="serif text-[26px] leading-none">{card.service}</h3>
            {card.exposure_path && (
              <p className="mono mt-2 text-[11.5px] text-amber">▲ reachable from the internet via {card.exposure_path.join(" → ")}</p>
            )}

            <section className="mt-6 border-t border-rule pt-4">
              <Label>Owners · CODEOWNERS</Label>
              {card.owners.length ? (
                <ul className="text-[13px]">
                  {card.owners.map((o) => (
                    <li key={o.owner} className="flex items-baseline gap-2 py-0.5">
                      <span>{o.owner.split("/").map((part, i, a) => (<span key={i}>{part}{i < a.length - 1 && <>/<wbr /></>}</span>))}</span>
                      <span className="label">{o.kind}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[13px] text-ink-2">No CODEOWNERS entry. Nobody is accountable for this service.</p>
              )}
            </section>

            <section className="mt-6 border-t border-rule pt-4">
              <Label>Expertise · commit history</Label>
              {humans.length === 0 && (
                <p className="text-[13px] text-ink-2">No human has touched this service&apos;s manifest. Automation maintains it.</p>
              )}
              <ul className="text-[13px]">
                {humans.map((e) => (
                  <li key={e.name} className="flex items-baseline py-0.5">
                    {e.name}
                    <span className="mono num ml-auto text-[11px] text-faint">{e.commits} commits</span>
                  </li>
                ))}
                {bots.map((e) => (
                  <li key={e.name} className="flex items-baseline py-0.5 text-ink-2">
                    {e.name} <span className="label ml-2">bot</span>
                    <span className="mono num ml-auto text-[11px] text-faint">{e.commits} commits</span>
                  </li>
                ))}
              </ul>
            </section>

            <section className="mt-6 border-t border-rule pt-4">
              <Label>Decisions · traced to source</Label>
              {card.decisions.length === 0 && <p className="text-[13px] text-ink-2">No recorded dependency decisions.</p>}
              <ul>
                {card.decisions.map((d) => (
                  <li key={d.id} className="border-b border-rule py-2.5 first:pt-0">
                    <a href={d.source} target="_blank" rel="noreferrer" className="block text-[13px] leading-snug hover:text-blue">
                      {d.text}
                    </a>
                    <div className="mt-1 flex items-baseline gap-2 text-[11.5px] text-faint">
                      <span>{d.author}</span>
                      <span className="mono">{d.date.slice(0, 10)}</span>
                      <span className={clsx("label ml-auto !text-[10px]", d.superseded_by ? "!text-amber" : "!text-green")}>
                        {d.superseded_by ? "superseded" : "current"}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </section>

            <section className="mt-6 border-t border-rule pt-4">
              <Label>Graph queries behind this page</Label>
              {card.traces.slice(0, 3).map((t, i) => <Cypher key={i} trace={t} />)}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
