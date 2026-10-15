"use client";

import { useState } from "react";
import clsx from "clsx";
import { api, TriageResult } from "@/lib/api";
import { Cypher, Label, Priority, Severity, VERDICT, timeAgo } from "./ui";

function Chain({ items, hot }: { items: string[]; hot?: boolean }) {
  return (
    <span className="mono text-[12px] leading-[1.7]">
      {items.map((s, i) => (
        <span key={i}>
          <span className={clsx(hot && i === items.length - 1 && "font-semibold text-red")}>{s}</span>
          {i < items.length - 1 && (
            <>
              <span className="px-1.5 text-faint">→</span>
              <wbr />
            </>
          )}
        </span>
      ))}
    </span>
  );
}

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="mt-7 border-t border-rule pt-4">
      <Label right={right}>{title}</Label>
      {children}
    </section>
  );
}

export default function ResultPanel({
  r,
  tenant,
  onReplay,
  onDecided,
}: {
  r: TriageResult;
  tenant: string;
  onReplay: () => void;
  onDecided: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [done, setDone] = useState<{ id: string; what: string } | null>(null);
  const [why, setWhy] = useState("");
  const v = VERDICT[r.verdict] ?? { word: r.verdict, color: "text-ink" };

  async function decide(decision: "patched" | "not_affected" | "accepted_risk") {
    if (!r.advisory) return;
    setBusy(decision);
    try {
      const eco = r.services[0]?.paths[0]?.pkg_key.split(":")[0];
      const rationale = decision === "patched" ? `Approved fix: ${r.actions[0]?.title ?? "upgrade vulnerable package"}` : why.trim();
      const out = await api.decide(tenant, {
        advisory_id: r.advisory.id, decision, rationale, actor: "you",
        services: r.services.map((s) => s.service), eco,
      });
      setDone({ id: out.case_id, what: decision.replace("_", " ") });
      onDecided();
    } finally {
      setBusy(null);
    }
  }

  const graphMs = r.steps.reduce((a, s) => a + s.ms, 0);

  return (
    <article className="fade-in">
      <div className="flex items-baseline justify-between">
        <span className="label">Case file · {r.run_id.slice(4)}</span>
        <button onClick={onReplay} className="mono text-[11px] text-faint underline underline-offset-2 hover:text-ink">
          replay traversal
        </button>
      </div>

      <h2 className={clsx("serif mt-3 text-[40px] font-medium leading-none tracking-[-0.01em]", v.color)}>{v.word}</h2>
      <div className="mt-3 flex items-center gap-3">
        <Priority p={r.priority} />
        {r.advisory && <Severity s={r.advisory.severity} />}
        {r.advisory && <span className="mono text-[11.5px] text-ink-2">{r.advisory.cve ?? r.advisory.id}</span>}
      </div>
      <p className="serif mt-4 text-[18px] leading-[1.35]">{r.headline}</p>
      {r.advisory && (
        <p className="mt-2 text-[13px] text-ink-2">
          {r.advisory.summary}{" "}
          <a href={r.advisory.url} target="_blank" rel="noreferrer" className="link">
            advisory
          </a>
        </p>
      )}
      {r.verdict === "NOT_AFFECTED" && r.reason === "no_path" && (
        <p className="serif mt-4 border-l-2 border-green pl-3 text-[15px] italic text-ink-2">
          Proof by absence. The traversal returned zero paths: no service depends, directly or transitively, on a package
          this advisory affects.
        </p>
      )}

      {r.services.length > 0 && (
        <Section title={`Blast radius · ${r.services.length} service${r.services.length > 1 ? "s" : ""}`}>
          <div className="flex flex-col">
            {r.services.map((s) => {
              const best = [...s.paths].sort((a, b) => a.hops - b.hops)[0];
              return (
                <div key={s.service} className="border-b border-rule py-3 first:pt-0 last:border-b-0">
                  <div className="flex items-baseline gap-3">
                    <h4 className="serif text-[20px] leading-none">{s.service}</h4>
                    {s.exposure_unknown ? (
                      <span className="label !text-amber" title="No deployment topology for this repository">▲ exposure unknown, assumed reachable</span>
                    ) : (
                      s.exposed && <span className="label !text-amber">▲ internet-exposed</span>
                    )}
                    {s.dev_only && <span className="label">dev only</span>}
                  </div>
                  <dl className="mt-2.5 grid grid-cols-[96px_minmax(0,1fr)] gap-y-1.5 text-[12.5px] [&>dd]:break-words">
                    {s.exposure_path && (
                      <>
                        <dt className="label pt-0.5">Reached via</dt>
                        <dd><Chain items={s.exposure_path} /></dd>
                      </>
                    )}
                    <dt className="label pt-0.5">Dependency</dt>
                    <dd><Chain items={[s.service, ...best.path.slice(1).map((p) => p.slice(p.indexOf(":") + 1))]} hot /></dd>
                    <dt className="label pt-0.5">Fix</dt>
                    <dd className="mono text-[12px] text-green">{best.pkg} ≥ {best.fixed ?? "?"}</dd>
                    <dt className="label pt-0.5">Owners</dt>
                    <dd>{s.owners.length ? s.owners.map((o) => o.owner.split("/").pop()).join(", ") : <span className="text-faint">none on record</span>}</dd>
                    <dt className="label pt-0.5">Callers</dt>
                    <dd>{s.callers.length} upstream</dd>
                  </dl>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {r.precedents.length > 0 && (
        <Section title="Memory · precedent">
          <div className="flex flex-col gap-3">
            {r.precedents.map((p) => (
              <div key={p.id} className="border-l-2 border-blue pl-3">
                <div className="flex items-baseline gap-2 text-[12px]">
                  <span className="mono text-blue">{p.id}</span>
                  <span className="font-medium capitalize">{p.decision.replace("_", " ")}</span>
                  {p.exact && <span className="label">same advisory</span>}
                  <span className="ml-auto text-faint">{timeAgo(p.ts)}</span>
                </div>
                <p className="mt-1 text-[13px]">{p.rationale}</p>
                <p className="mt-0.5 text-[12px] text-ink-2">
                  {p.cve ?? p.advisory} · {p.packages.slice(0, 3).join(", ")} · by {p.actor}
                  {p.playbooks[0] && <> · playbook <span className="mono">{p.playbooks[0]}</span></>}
                </p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {r.actions.length > 0 && (
        <Section title="Proposed actions" right={<span className="label !text-amber">needs your approval</span>}>
          <ul className="flex flex-col">
            {r.actions.map((a) => (
              <li key={a.id} className="border-b border-rule">
                <details>
                  <summary className="flex cursor-pointer items-baseline gap-2 py-2 text-[13px] hover:text-blue">
                    <span className="mono text-faint">↳</span>
                    <span>{a.title}</span>
                  </summary>
                  <pre className="mono mb-2 whitespace-pre-wrap bg-sunk px-3 py-2 text-[11.5px] leading-[1.6] text-ink-2">{a.body}</pre>
                </details>
              </li>
            ))}
          </ul>
          {done ? (
            <p className="mt-4 text-[13px] text-green">
              Recorded as <b>{done.what}</b> in memory, <span className="mono">{done.id}</span>. The next related advisory will cite it.
            </p>
          ) : (
            <div className="mt-4">
              <input
                value={why}
                onChange={(e) => setWhy(e.target.value)}
                placeholder="Rationale (needed for VEX or accepting risk)"
                aria-label="Rationale"
                className="w-full border-0 border-b border-rule-strong bg-transparent px-0 py-1.5 text-[13px] outline-none placeholder:text-faint focus:border-ink"
              />
              <div className="mt-3 flex flex-wrap gap-2">
                <button className="btn btn-solid" disabled={!!busy || r.verdict === "NOT_AFFECTED"} onClick={() => decide("patched")}>
                  {busy === "patched" ? "Recording…" : "Approve fix"}
                </button>
                <button className="btn" disabled={!!busy || !why.trim()} onClick={() => decide("not_affected")}>
                  VEX: not affected
                </button>
                <button className="btn btn-quiet" disabled={!!busy || !why.trim()} onClick={() => decide("accepted_risk")}>
                  Accept risk
                </button>
              </div>
              <p className="mt-2 text-[11.5px] text-faint">Nothing is executed. Approving writes the decision into the graph as memory.</p>
            </div>
          )}
        </Section>
      )}

      <Section
        title="Agent handoffs"
        right={<span className="mono num text-[11px] text-faint">{graphMs.toFixed(0)} ms in graph · {r.total_ms} ms total</span>}
      >
        <ol>
          {r.steps.map((s, i) => (
            <li
              key={i}
              className="fade-in grid grid-cols-[88px_1fr_auto] gap-x-3 border-b border-rule py-2 first:pt-0"
              style={{ animationDelay: `${i * 120}ms` }}
            >
              <div className="label !text-ink-2 pt-0.5">{s.agent}</div>
              <div className="min-w-0">
                <div className="text-[13px] leading-snug">{s.summary}</div>
                <div className="mono text-[10.5px] text-faint">{s.tool}</div>
                {s.traces.slice(0, 3).map((t, k) => (
                  <Cypher key={k} trace={t} />
                ))}
              </div>
              <div className="mono num pt-0.5 text-[11px] text-faint">{s.ms > 0 ? `${s.ms} ms` : ""}</div>
            </li>
          ))}
        </ol>
      </Section>
    </article>
  );
}
