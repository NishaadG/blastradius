"use client";

import clsx from "clsx";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import GraphCanvas from "@/components/GraphCanvas";
import ResultPanel from "@/components/ResultPanel";
import { CompanyView, MemoryView, RiskBoard } from "@/components/Views";
import RepoAnalyzer from "@/components/RepoAnalyzer";
import { Label } from "@/components/ui";
import { api, AskResult, Brain, GraphData, healthy, ID_RE, Risk, TenantInfo, TriageResult } from "@/lib/api";

type Tab = "risk" | "memory" | "company";
const TABS: { id: Tab; label: string }[] = [
  { id: "risk", label: "Risk board" },
  { id: "memory", label: "Memory" },
  { id: "company", label: "Company" },
];

function Mark() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden className="translate-y-[3px]">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.3" />
      <circle cx="12" cy="12" r="5.5" stroke="currentColor" strokeWidth="1.3" />
      <circle cx="12" cy="12" r="1.8" fill="var(--red)" />
    </svg>
  );
}

export default function Home() {
  const [tenants, setTenants] = useState<TenantInfo[]>([]);
  const [tenant, setTenant] = useState<string>("boutique");
  const [overview, setOverview] = useState<GraphData | null>(null);
  const [risk, setRisk] = useState<Risk | null>(null);
  const [brain, setBrain] = useState<Brain | null>(null);
  const [tab, setTab] = useState<Tab>("risk");
  const [result, setResult] = useState<TriageResult | null>(null);
  const [answer, setAnswer] = useState<AskResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [replayKey, setReplayKey] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const caseRef = useRef<HTMLElement>(null);

  const refreshBrain = useCallback((t: string) => api.brain(t).then(setBrain).catch(() => {}), []);
  const refreshRisk = useCallback((t: string) => api.risk(t).then(setRisk).catch((e) => setError(String(e))), []);

  const refreshTenants = useCallback(
    () => api.tenants().then((t) => { setTenants(t); return t; }),
    [],
  );
  useEffect(() => {
    refreshTenants()
      .then((t) => {
        if (t.length && !t.find((x) => x.id === "boutique")) setTenant(t[0].id);
      })
      .catch(() => setError("Cannot reach the Blastradius API. Is the backend running and FalkorDB up?"));
  }, [refreshTenants]);

  const [forceStart, setForceStart] = useState(false);

  const runId = result?.run_id;
  useEffect(() => {
    caseRef.current?.scrollTo({ top: 0 });
  }, [runId]);

  const [evalInfo, setEvalInfo] = useState<{ passed: number; total: number } | null>(null);
  useEffect(() => {
    api.evals().then((e) => e.available && setEvalInfo({ passed: e.passed ?? 0, total: e.total ?? 0 })).catch(() => {});
  }, []);

  const [online, setOnline] = useState(true);
  useEffect(() => {
    let live = true;
    const tick = async () => {
      const ok = await healthy();
      if (live) setOnline(ok);
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, []);

  const tenantRef = useRef(tenant);
  useEffect(() => {
    tenantRef.current = tenant;
  }, [tenant]);

  const switchTenant = useCallback((id: string) => {
    if (id === tenantRef.current) return; // same tenant: keep loaded data, nothing to refetch
    setTenant(id);
    setResult(null);
    setAnswer(null);
    setSelected(null);
    setOverview(null);
    setRisk(null);
    setBrain(null);
  }, []);

  useEffect(() => {
    api.graph(tenant).then(setOverview).catch(() => {});
    refreshRisk(tenant);
    refreshBrain(tenant);
  }, [tenant, refreshBrain, refreshRisk]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === "Escape") {
        inputRef.current?.blur();
        setAnswer(null);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const run = useCallback(
    async (text: string, forTenant?: string): Promise<TriageResult | null> => {
      const q = text.trim();
      if (!q) return null;
      const t = forTenant ?? tenant;
      setRunning(true);
      setError(null);
      setAnswer(null);
      inputRef.current?.blur();
      try {
        if (ID_RE.test(q) && q.split(/\s+/).length === 1) {
          setInput(q);
          const r = await api.triage(t, q);
          setForceStart(false);
          setResult(r);
          setReplayKey((k) => k + 1);
          refreshBrain(t);
          return r;
        }
        const a = await api.ask(tenant, q);
        setAnswer(a);
        if (a.triage) {
          setForceStart(false);
          setResult(a.triage);
          setReplayKey((k) => k + 1);
          refreshBrain(tenant);
        } else {
          const svc = overview?.nodes.find((n) => q.toLowerCase().includes(n.id))?.id;
          if (svc) {
            setTab("company");
            setSelected(svc);
            setResult(null);
          }
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setRunning(false);
      }
      return null;
    },
    [tenant, refreshBrain, overview],
  );

  /* ---------------------------------------------------------------- guided demo */
  const [demo, setDemo] = useState<{ i: number; total: number; text: string } | null>(null);
  const cancelDemo = useRef(false);

  const playDemo = useCallback(async () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const total = 8;
    cancelDemo.current = false;
    const say = async (i: number, text: string, ms: number) => {
      if (cancelDemo.current) throw new Error("stopped");
      setDemo({ i, total, text });
      await sleep(ms);
      if (cancelDemo.current) throw new Error("stopped");
    };
    try {
      setTab("risk");
      switchTenant("boutique");
      await api.reset("boutique");
      await sleep(1800);
      await say(1, "A critical CVE lands: arbitrary code execution in protobufjs. Which of our services are exposed?", 2200);
      const r1 = await run("CVE-2026-41242", "boutique");
      await say(2, "The agent walks the graph: internet-exposed frontend, then payment, then the gRPC loader, down to the vulnerable protobufjs. A deterministic judge decides, not the LLM.", 7000);
      if (r1?.advisory) {
        await say(3, "A human approves the fix. The decision is written back into the graph as episodic memory.", 1800);
        await api.decide("boutique", {
          advisory_id: r1.advisory.id, decision: "patched", rationale: `Approved fix: ${r1.actions[0]?.title ?? "upgrade"}`,
          actor: "you", services: r1.services.map((s) => s.service), eco: "npm",
        });
        refreshBrain("boutique");
        await sleep(1400);
      }
      await say(4, "Days later, a different protobufjs advisory arrives.", 1800);
      await run("CVE-2026-48712", "boutique");
      await say(4, "Memory kicks in: the agent cites the earlier case, found by traversal from advisory to package to case, and reuses the playbook.", 7000);
      setTab("memory");
      await say(5, "Cases, reuse counts and playbook success rates all live in the same FalkorDB graph.", 4500);
      setTab("risk");
      await run("GHSA-jfh8-c2jp-5v3q", "boutique");
      await say(6, "Log4Shell? Proven not affected: the traversal returns zero paths. The absence of a path is evidence.", 6000);
      setResult(null);
      setTab("company");
      setSelected("paymentservice");
      await say(7, "Company brain: owners, expertise and decisions, each traced to a source commit.", 5500);
      setSelected(null);
      setTab("memory");
      switchTenant("otel");
      await say(8, "Each tenant is its own FalkorDB graph. OpenTelemetry's memory is empty: nothing leaks across tenants.", 6000);
    } catch {
      /* stopped */
    } finally {
      setDemo(null);
    }
  }, [run, refreshBrain, switchTenant]);

  const autoStarted = useRef(false);
  const playRef = useRef(playDemo);
  useEffect(() => {
    playRef.current = playDemo;
  });
  useEffect(() => {
    if (autoStarted.current) return;
    if (new URLSearchParams(window.location.search).get("demo") === "1") {
      autoStarted.current = true;
      setTimeout(() => playRef.current(), 1500);
    }
  }, []);

  const samples = useMemo(() => {
    const top = (risk?.advisories ?? []).filter((a) => a.priority === "P0").slice(0, 3);
    return [
      ...top.map((a) => ({ label: `Critical ${a.packages[0]?.split("@")[0]} advisory`, q: a.cve ?? a.id })),
      { label: "Log4Shell, in a stack with no Java", q: "GHSA-jfh8-c2jp-5v3q" },
      { label: "Who owns paymentservice?", q: "who owns paymentservice?" },
    ];
  }, [risk]);

  const curated = tenants.filter((t) => t.kind === "curated");
  const mine = tenants.filter((t) => t.kind === "byo");
  const current = tenants.find((t) => t.id === tenant);
  const exposureKnown = current?.exposure_known ?? true;
  const showStart = !result || forceStart;
  const nodeCount = current ? Object.values(current.nodes).reduce((a, b) => a + b, 0) : 0;
  const edgeCount = current ? Object.values(current.edges).reduce((a, b) => a + b, 0) : 0;
  const isUp = online && tenants.length > 0;

  return (
    <main className="flex h-dvh flex-col overflow-y-auto lg:overflow-hidden">
      <header className="flex shrink-0 flex-wrap items-center gap-x-7 gap-y-2 border-b border-rule px-5 py-2.5 lg:h-12 lg:flex-nowrap lg:py-0">
        <div className="flex items-baseline gap-2.5">
          <Mark />
          <span className="serif text-[22px] font-medium leading-none tracking-[-0.01em]">Blastradius</span>
          <span className="label hidden xl:inline">supply-chain triage on a graph</span>
        </div>
        <nav className="flex items-center gap-5" aria-label="Tenant">
          {curated.map((t) => (
            <button
              key={t.id}
              onClick={() => switchTenant(t.id)}
              aria-current={tenant === t.id}
              className={clsx(
                "whitespace-nowrap border-b-2 py-1 text-[13px] transition-colors",
                tenant === t.id ? "border-ink font-medium" : "border-transparent text-ink-2 hover:text-ink",
              )}
            >
              {t.title}
            </button>
          ))}
          {mine.length > 0 && (
            <select
              value={mine.some((t) => t.id === tenant) ? tenant : ""}
              onChange={(e) => e.target.value && switchTenant(e.target.value)}
              aria-label="Repositories you analysed"
              className={clsx(
                "max-w-[180px] cursor-pointer border-0 border-b-2 bg-transparent py-1 text-[13px] outline-none",
                mine.some((t) => t.id === tenant) ? "border-ink font-medium" : "border-transparent text-ink-2",
              )}
            >
              <option value="">Your repos ({mine.length})</option>
              {mine.map((t) => (
                <option key={t.id} value={t.id}>{t.title}</option>
              ))}
            </select>
          )}
        </nav>
        <div className="ml-auto flex items-center gap-5">
          <span className="mono num hidden items-center gap-2 text-[11px] text-ink-2 md:flex">
            <i className={clsx("inline-block h-[7px] w-[7px]", isUp ? "bg-green" : "bg-red")} />
            {isUp ? `FalkorDB · ${nodeCount.toLocaleString()} nodes · ${edgeCount.toLocaleString()} edges` : "FalkorDB offline"}
          </span>
          {evalInfo && (
            <span className="mono hidden text-[11px] text-ink-2 xl:block" title="python -m evals.run, computed without the graph">
              {evalInfo.passed}/{evalInfo.total} evals pass
            </span>
          )}
          <button className="btn btn-quiet hidden sm:block" onClick={() => setForceStart((v) => !v)} aria-pressed={forceStart}>
            Analyse a repo
          </button>
          <button className={clsx("btn", !demo && "btn-solid")} onClick={() => (demo ? (cancelDemo.current = true) : playDemo())}>
            {demo ? "Stop demo" : "Guided demo"}
          </button>
        </div>
      </header>

      {!online && (
        <div role="alert" className="border-b border-red bg-red-tint px-5 py-2 text-[13px] text-red">
          <b>FalkorDB is offline.</b> Blastradius has nothing to say without the graph: every verdict is a traversal, so there is no fallback and no
          cached answer. It resumes the moment the database is back.
        </div>
      )}

      <div className="flex flex-col lg:grid lg:min-h-0 lg:flex-1 lg:grid-cols-[340px_minmax(0,1fr)_430px]">
        {/* left: lists */}
        <aside className="flex min-h-[480px] flex-col border-rule px-5 pb-4 pt-3 max-lg:order-3 max-lg:border-t lg:min-h-0 lg:border-r">
          <div className="mb-3 flex gap-5 border-b border-rule" role="tablist">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                onClick={() => setTab(t.id)}
                className={clsx(
                  "-mb-px border-b-2 pb-2 text-[13px] transition-colors",
                  tab === t.id ? "border-ink font-medium" : "border-transparent text-ink-2 hover:text-ink",
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
          {!exposureKnown && (
            <p className="mb-3 border-l-2 border-amber pl-3 text-[12px] leading-snug text-ink-2">
              No deployment topology for this repository, so exposure is unknown and every service is assumed reachable from the internet.
            </p>
          )}
          {tab === "risk" && <RiskBoard risk={risk} activeId={result?.advisory?.id} onPick={run} />}
          {tab === "memory" && (
            <MemoryView tenant={tenant} brain={brain} onReset={async () => { await api.reset(tenant); setResult(null); refreshBrain(tenant); }} />
          )}
          {tab === "company" && (
            <CompanyView tenant={tenant} overview={overview} selected={selected} onSelect={setSelected} />
          )}
        </aside>

        {/* centre: command + graph */}
        <section className="relative flex flex-col max-lg:order-1 lg:min-h-0">
          <form
            onSubmit={(e) => { e.preventDefault(); run(input); }}
            className="flex items-center gap-3 border-b border-rule px-5 py-2.5"
          >
            <span className="mono text-[15px] text-faint" aria-hidden>›</span>
            <input
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste a CVE or GHSA id, or ask a question"
              aria-label="Triage a vulnerability or ask a question"
              className="min-w-0 flex-1 bg-transparent py-1 text-[14px] outline-none placeholder:text-faint"
            />
            <span className="label hidden sm:block">ctrl k</span>
            <button type="submit" className="btn btn-solid" disabled={running}>{running ? "Working…" : "Run"}</button>
          </form>

          {(answer || (error && online)) && (
            <div className="fade-in flex items-start gap-4 border-b border-rule bg-panel px-5 py-3">
              <div className="min-w-0 flex-1">
                {error && !answer ? (
                  <p className="text-[13px] text-red">{error}</p>
                ) : (
                  <>
                    <p className="serif whitespace-pre-wrap text-[17px] leading-snug">{answer?.answer}</p>
                    <p className="mono mt-1.5 text-[10.5px] text-faint">
                      {answer?.tool_calls.map((t) => t.tool).join(" · ")} · {answer?.mode === "gemini" ? "Gemini free tier" : "offline router, no LLM"}
                    </p>
                  </>
                )}
              </div>
              <button onClick={() => { setAnswer(null); setError(null); }} aria-label="Dismiss" className="mono text-[15px] leading-none text-faint hover:text-ink">×</button>
            </div>
          )}

          <div className="relative min-h-[360px] flex-1">
            <GraphCanvas overview={overview} focus={result?.subgraph ?? null} replayKey={replayKey} selected={selected}
              onSelect={(s) => { setSelected(s); setTab("company"); }} />
            {!overview && !error && <div className="mono absolute inset-0 flex items-center justify-center text-[11px] text-faint">Loading graph…</div>}
            <div className="mono pointer-events-none absolute bottom-3 left-5 flex flex-wrap gap-x-5 gap-y-1 text-[10.5px] text-ink-2">
              <span><i className="mr-1.5 inline-block h-[9px] w-[9px] border-[3px] border-double border-amber align-[-1px]" />{exposureKnown ? "internet-exposed" : "exposure unknown"}</span>
              <span><i className="mr-1.5 inline-block h-[2px] w-3.5 bg-red align-middle" />attack path</span>
              <span><i className="mr-1.5 inline-block h-[9px] w-[9px] bg-red align-[-1px]" />vulnerable package</span>
              {!result && <span className="text-faint">node size = PageRank</span>}
            </div>
            {demo && (
              <div className="fade-in absolute inset-x-0 bottom-0 z-10 bg-ink text-paper" role="status" aria-live="polite">
                <div className="h-[2px] bg-paper/20"><div className="h-[2px] bg-paper transition-all duration-500" style={{ width: `${(demo.i / demo.total) * 100}%` }} /></div>
                <div className="flex items-start gap-4 px-5 py-3.5">
                  <span className="mono num pt-1 text-[11px] opacity-60">{String(demo.i).padStart(2, "0")}/{String(demo.total).padStart(2, "0")}</span>
                  <p className="serif text-[18px] leading-snug">{demo.text}</p>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* right: case file or orientation */}
        <aside ref={caseRef} className="scroll border-rule bg-panel lg:min-h-0 lg:overflow-y-auto px-6 py-5 max-lg:order-2 max-lg:border-t lg:border-l">
          {!showStart && result ? (
            <ResultPanel key={result.run_id} r={result} tenant={tenant} onReplay={() => setReplayKey((k) => k + 1)}
              onDecided={() => { refreshBrain(tenant); refreshRisk(tenant); }} />
          ) : (
            <div className="fade-in">
              <span className="label">Start here</span>
              <h2 className="serif mt-3 text-[32px] font-medium leading-[1.08] tracking-[-0.01em]">
                Is this CVE in our system, and how does it get there?
              </h2>
              <p className="mt-4 text-[14px] leading-relaxed text-ink-2">
                Blastradius follows the dependency and call graph in FalkorDB from an advisory to the services it reaches,
                then out to the internet. It names the owners, remembers what you decided last time, and treats
                &ldquo;no path&rdquo; as an answer.
              </p>
              <button className="btn btn-solid mt-5" onClick={() => playDemo()} disabled={!!demo}>Play the guided demo</button>

              <section className="mt-8 border-t border-rule pt-4">
                <Label>Try one</Label>
                <ul>
                  {samples.map((s) => (
                    <li key={s.q} className="border-b border-rule">
                      <button onClick={() => run(s.q)} className="flex w-full items-baseline gap-3 py-2.5 text-left text-[13.5px] hover:text-blue">
                        <span>{s.label}</span>
                        <span className="mono ml-auto truncate text-[10.5px] text-faint">{s.q}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>

              <RepoAnalyzer
                onDone={async (t) => {
                  await refreshTenants();
                  switchTenant(t);
                  setForceStart(false);
                }}
              />

              <section className="mt-8 border-t border-rule pt-4">
                <Label>How to read the graph</Label>
                <dl className="grid grid-cols-[22px_1fr] gap-y-2.5 text-[13px] text-ink-2">
                  <dt><i className="mt-1 inline-block h-[10px] w-[10px] border-[3px] border-double border-amber" /></dt>
                  <dd>A double ring marks a service reachable from the internet.</dd>
                  <dt><i className="mt-2 inline-block h-[2px] w-3.5 bg-red" /></dt>
                  <dd>Red is the path an attacker would travel, drawn hop by hop.</dd>
                  <dt><i className="mt-1 inline-block h-[10px] w-[10px] bg-red" /></dt>
                  <dd>A filled red box is the vulnerable package itself.</dd>
                </dl>
              </section>
            </div>
          )}
        </aside>
      </div>
    </main>
  );
}
