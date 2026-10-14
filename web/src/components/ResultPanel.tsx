"use client";

import { motion } from "framer-motion";
import { ArrowRight, BookMarked, Check, ExternalLink, GitPullRequest, Network, RotateCcw, ShieldCheck, Users } from "lucide-react";
import { useState } from "react";
import clsx from "clsx";
import { api, TriageResult } from "@/lib/api";
import { Cypher, Label, Pill, PriorityBadge, SevBadge, Spinner, VerdictBadge, timeAgo } from "./ui";

const AGENT_TONE: Record<string, string> = {
  Triage: "text-accent border-accent/40",
  Investigator: "text-violet border-violet/40",
  Judge: "text-warn border-warn/40",
  Remediator: "text-good border-good/40",
};

function Chain({ items, accent }: { items: string[]; accent?: boolean }) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      {items.map((s, i) => (
        <span key={i} className="flex items-center gap-1">
          <span className={clsx("mono rounded-md border px-1.5 py-0.5 text-[11px]", accent && i === items.length - 1 ? "border-bad/50 text-bad" : "border-line-strong text-fg")}>
            {s}
          </span>
          {i < items.length - 1 && <ArrowRight className="h-3 w-3 text-faint" />}
        </span>
      ))}
    </div>
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
  const prod = r.services.filter((s) => !s.dev_only);

  async function decide(decision: "patched" | "not_affected" | "accepted_risk") {
    if (!r.advisory) return;
    setBusy(decision);
    try {
      const eco = r.services[0]?.paths[0]?.pkg_key.split(":")[0];
      const rationale =
        decision === "patched"
          ? `Approved fix: ${r.actions[0]?.title ?? "upgrade vulnerable package"}`
          : why.trim();
      const out = await api.decide(tenant, {
        advisory_id: r.advisory.id,
        decision,
        rationale,
        actor: "you",
        services: r.services.map((s) => s.service),
        eco,
      });
      setDone({ id: out.case_id, what: decision.replace("_", " ") });
      onDecided();
    } finally {
      setBusy(null);
    }
  }

  const stepTotal = r.steps.reduce((a, s) => a + s.ms, 0);

  return (
    <div className="flex flex-col gap-5">
      {/* verdict */}
      <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
        <div className="flex items-center gap-2">
          <VerdictBadge v={r.verdict} />
          <PriorityBadge p={r.priority} />
          {r.advisory && <SevBadge s={r.advisory.severity} />}
          <button onClick={onReplay} className="ml-auto flex items-center gap-1 text-[11px] text-muted hover:text-fg" title="Replay the traversal">
            <RotateCcw className="h-3 w-3" /> replay
          </button>
        </div>
        <p className="mt-2.5 text-[15px] font-medium leading-snug text-fg">{r.headline}</p>
        {r.advisory && (
          <div className="mt-2 text-xs text-muted">
            <span className="mono text-fg">{r.advisory.cve ?? r.advisory.id}</span> · {r.advisory.summary}{" "}
            <a href={r.advisory.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-accent hover:underline">
              source <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        )}
        {r.verdict === "NOT_AFFECTED" && r.reason === "no_path" && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-good/30 bg-good/5 p-2.5 text-xs text-good">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              Proof by absence: the graph query returned <b>zero paths</b>. No service depends, directly or transitively, on a
              package this advisory affects.
            </span>
          </div>
        )}
      </motion.section>

      {/* timeline */}
      <section>
        <Label right={<span className="mono text-[11px] text-accent">{stepTotal.toFixed(0)}ms in graph · {r.total_ms}ms total</span>}>
          Agent handoffs
        </Label>
        <ol className="relative ml-1.5 border-l border-line-strong pl-4">
          {r.steps.map((s, i) => (
            <motion.li
              key={i}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 + i * 0.28 }}
              className="relative pb-3 last:pb-0"
            >
              <span className={clsx("absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 bg-bg", AGENT_TONE[s.agent] ?? "border-line-strong")} />
              <div className="flex items-center gap-2 text-[11px]">
                <span className={clsx("font-semibold", (AGENT_TONE[s.agent] ?? "").split(" ")[0])}>{s.agent}</span>
                <span className="mono text-faint">{s.tool}</span>
                {s.ms > 0 && <span className="mono ml-auto text-faint">{s.ms}ms</span>}
              </div>
              <div className="mt-0.5 text-xs leading-snug text-[#c3cce0]">{s.summary}</div>
              {s.traces.length > 0 && (
                <div className="mt-1.5 flex flex-col gap-1">
                  {s.traces.slice(0, 3).map((t, k) => (
                    <Cypher key={k} trace={t} />
                  ))}
                </div>
              )}
            </motion.li>
          ))}
        </ol>
      </section>

      {/* services */}
      {r.services.length > 0 && (
        <section>
          <Label>Blast radius · {r.services.length} service{r.services.length > 1 ? "s" : ""}</Label>
          <div className="flex flex-col gap-2.5">
            {r.services.map((s) => {
              const best = [...s.paths].sort((a, b) => a.hops - b.hops)[0];
              return (
                <div key={s.service} className="rounded-xl border border-line bg-surface-2/60 p-3">
                  <div className="flex items-center gap-2">
                    <Network className="h-3.5 w-3.5 text-muted" />
                    <span className="text-sm font-semibold">{s.service}</span>
                    {s.exposed && <Pill tone="warn">internet-exposed</Pill>}
                    {s.dev_only && <Pill>dev-only</Pill>}
                  </div>
                  {s.exposure_path && (
                    <div className="mt-2">
                      <div className="mb-1 text-[10px] uppercase tracking-wider text-faint">Attack path in</div>
                      <Chain items={s.exposure_path} />
                    </div>
                  )}
                  <div className="mt-2">
                    <div className="mb-1 text-[10px] uppercase tracking-wider text-faint">Dependency chain</div>
                    <Chain items={[s.service, ...best.path.slice(1).map((p) => p.split(":")[1])]} accent />
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted">
                    <span>
                      fix: <span className="mono text-good">{best.pkg} ≥ {best.fixed ?? "?"}</span>
                    </span>
                    <span className="flex items-center gap-1">
                      <Users className="h-3 w-3" />
                      {s.owners.length ? s.owners.map((o) => o.owner.split("/").pop()).join(", ") : "no owner"}
                    </span>
                    <span>{s.callers.length} upstream caller{s.callers.length === 1 ? "" : "s"}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* precedents */}
      {r.precedents.length > 0 && (
        <section>
          <Label>Memory · precedent</Label>
          <div className="flex flex-col gap-2">
            {r.precedents.map((p) => (
              <motion.div
                key={p.id}
                initial={{ opacity: 0, scale: 0.97 }}
                animate={{ opacity: 1, scale: 1 }}
                className="rounded-xl border border-violet/40 bg-violet/5 p-3"
              >
                <div className="flex items-center gap-2 text-xs">
                  <BookMarked className="h-3.5 w-3.5 text-violet" />
                  <span className="mono text-violet">{p.id}</span>
                  <Pill tone={p.decision === "patched" ? "good" : "warn"}>{p.decision.replace("_", " ")}</Pill>
                  {p.exact && <Pill tone="violet">same advisory</Pill>}
                  <span className="ml-auto text-faint">{timeAgo(p.ts)}</span>
                </div>
                <p className="mt-1.5 text-xs text-[#c3cce0]">{p.rationale}</p>
                <div className="mt-1 text-[11px] text-muted">
                  {p.cve ?? p.advisory} · {p.packages.slice(0, 3).join(", ")} · by {p.actor}
                  {p.playbooks[0] && <> · playbook <span className="mono text-violet">{p.playbooks[0]}</span></>}
                </div>
              </motion.div>
            ))}
          </div>
        </section>
      )}

      {/* gated actions */}
      {r.actions.length > 0 && (
        <section>
          <Label right={<Pill tone="warn">human approval required</Pill>}>Proposed actions</Label>
          <div className="flex flex-col gap-2">
            {r.actions.map((a) => (
              <details key={a.id} className="group rounded-xl border border-line bg-surface-2/60 p-3 open:border-line-strong">
                <summary className="flex cursor-pointer list-none items-center gap-2 text-xs font-medium">
                  <GitPullRequest className="h-3.5 w-3.5 text-good" />
                  <span className="truncate">{a.title}</span>
                </summary>
                <pre className="mono mt-2 whitespace-pre-wrap text-[11px] leading-5 text-muted">{a.body}</pre>
              </details>
            ))}
          </div>
          {done ? (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-good/40 bg-good/10 p-2.5 text-xs text-good">
              <Check className="h-4 w-4" />
              <span>
                Recorded as <b>{done.what}</b> in memory (<span className="mono">{done.id}</span>). The next related advisory will cite it.
              </span>
            </div>
          ) : (
            <div className="mt-3 flex flex-col gap-2">
              <input
                value={why}
                onChange={(e) => setWhy(e.target.value)}
                placeholder="Rationale (required for VEX / accept risk)…"
                className="w-full rounded-lg border border-line-strong bg-bg px-3 py-2 text-xs outline-none placeholder:text-faint focus:border-accent"
              />
              <div className="flex flex-wrap gap-2">
                <button
                  disabled={!!busy || r.verdict === "NOT_AFFECTED"}
                  onClick={() => decide("patched")}
                  className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-bg transition hover:brightness-110 disabled:opacity-40"
                >
                  {busy === "patched" ? <Spinner /> : <Check className="h-3.5 w-3.5" />} Approve fix
                </button>
                <button
                  disabled={!!busy || !why.trim()}
                  onClick={() => decide("not_affected")}
                  className="rounded-lg border border-line-strong px-3 py-1.5 text-xs font-medium text-fg transition hover:border-good hover:text-good disabled:opacity-40"
                >
                  VEX: not affected
                </button>
                <button
                  disabled={!!busy || !why.trim()}
                  onClick={() => decide("accepted_risk")}
                  className="rounded-lg border border-line-strong px-3 py-1.5 text-xs font-medium text-fg transition hover:border-warn hover:text-warn disabled:opacity-40"
                >
                  Accept risk
                </button>
              </div>
              {prod.length > 0 && <p className="text-[11px] text-faint">Nothing is executed; approval writes the decision into the graph as memory.</p>}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
