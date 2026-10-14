"use client";

import clsx from "clsx";
import { AnimatePresence, motion } from "framer-motion";
import { Brain as BrainIcon, Building2, CornerDownLeft, Search, ShieldAlert, Sparkles, Waypoints, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import GraphCanvas from "@/components/GraphCanvas";
import ResultPanel from "@/components/ResultPanel";
import { CompanyView, MemoryView, RiskBoard } from "@/components/Views";
import { Pill, Spinner } from "@/components/ui";
import { api, AskResult, Brain, GraphData, ID_RE, Risk, TenantInfo, TriageResult } from "@/lib/api";

type Tab = "risk" | "memory" | "company";

const TABS: { id: Tab; label: string; icon: typeof ShieldAlert }[] = [
  { id: "risk", label: "Risk board", icon: ShieldAlert },
  { id: "memory", label: "Memory", icon: BrainIcon },
  { id: "company", label: "Company", icon: Building2 },
];

const STATIC_SAMPLES = [
  { label: "Log4Shell (no Java deps here)", q: "GHSA-jfh8-c2jp-5v3q" },
  { label: "Who owns paymentservice?", q: "who owns paymentservice?" },
  { label: "What is the blast radius of checkout?", q: "blast radius of checkoutservice" },
];

function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden>
      <circle cx="16" cy="16" r="3" fill="#ff4d6d" />
      <circle cx="16" cy="16" r="8" stroke="#35e0f2" strokeOpacity=".7" strokeWidth="1.5" strokeDasharray="3 3" />
      <circle cx="16" cy="16" r="13" stroke="#35e0f2" strokeOpacity=".3" strokeWidth="1.5" />
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
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const refreshBrain = useCallback((t: string) => api.brain(t).then(setBrain).catch(() => {}), []);
  const refreshRisk = useCallback((t: string) => api.risk(t).then(setRisk).catch((e) => setError(String(e))), []);

  useEffect(() => {
    api.tenants().then((t) => {
      setTenants(t);
      if (t.length && !t.find((x) => x.id === "boutique")) setTenant(t[0].id);
    }).catch(() => setError("Cannot reach the Blastradius API. Is the backend running on :8000 and FalkorDB up?"));
  }, []);

  useEffect(() => {
    setResult(null);
    setAnswer(null);
    setSelected(null);
    setOverview(null);
    setRisk(null);
    setBrain(null);
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
    async (text: string) => {
      const q = text.trim();
      if (!q) return;
      setRunning(true);
      setError(null);
      setAnswer(null);
      inputRef.current?.blur();
      try {
        if (ID_RE.test(q) && q.split(/\s+/).length === 1) {
          const r = await api.triage(tenant, q);
          setResult(r);
          setReplayKey((k) => k + 1);
          refreshBrain(tenant);
        } else {
          const a = await api.ask(tenant, q);
          setAnswer(a);
          if (a.triage) {
            setResult(a.triage);
            setReplayKey((k) => k + 1);
            refreshBrain(tenant);
          } else {
            const m = q.toLowerCase();
            const svc = overview?.nodes.find((n) => m.includes(n.id))?.id;
            if (svc) {
              setTab("company");
              setSelected(svc);
              setResult(null);
            }
          }
        }
      } catch (e) {
        setError(String(e));
      } finally {
        setRunning(false);
      }
    },
    [tenant, refreshBrain, overview],
  );

  const samples = useMemo(() => {
    const top = (risk?.advisories ?? []).filter((a) => a.priority === "P0").slice(0, 3);
    return [
      ...top.map((a) => ({ label: `${a.cve ?? a.id} · ${a.packages[0]?.split("@")[0]}`, q: a.cve ?? a.id })),
      ...STATIC_SAMPLES,
    ];
  }, [risk]);

  const current = tenants.find((t) => t.id === tenant);
  const nodeCount = current ? Object.values(current.nodes).reduce((a, b) => a + b, 0) : 0;
  const edgeCount = current ? Object.values(current.edges).reduce((a, b) => a + b, 0) : 0;
  const healthy = tenants.length > 0;

  return (
    <main className="relative flex h-dvh flex-col overflow-y-auto lg:block lg:overflow-hidden">
      {/* header */}
      <header className="glass z-30 flex h-14 shrink-0 items-center gap-4 border-x-0 border-t-0 px-4 lg:absolute lg:inset-x-0 lg:top-0">
        <div className="flex items-center gap-2.5">
          <Logo />
          <div className="leading-none">
            <div className="text-[15px] font-semibold tracking-tight">Blastradius</div>
            <div className="mt-0.5 hidden text-[10.5px] text-muted sm:block">supply-chain triage · powered by a graph</div>
          </div>
        </div>
        <div className="ml-2 flex items-center rounded-lg border border-line bg-bg/60 p-0.5" role="tablist" aria-label="Tenant">
          {tenants.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tenant === t.id}
              onClick={() => setTenant(t.id)}
              className={clsx("rounded-md px-2.5 py-1 text-xs font-medium transition", tenant === t.id ? "bg-surface-2 text-fg shadow-sm" : "text-muted hover:text-fg")}
            >
              {t.title}
            </button>
          ))}
        </div>
        <div className="ml-auto hidden items-center gap-3 md:flex">
          <Pill tone={healthy ? "good" : "bad"} className="gap-1.5 py-1">
            <span className={clsx("h-1.5 w-1.5 rounded-full", healthy ? "bg-good" : "bg-bad")} />
            FalkorDB · {nodeCount.toLocaleString()} nodes · {edgeCount.toLocaleString()} edges
          </Pill>
          <span className="text-[11px] text-faint">graph isolated per tenant</span>
        </div>
      </header>

      {/* canvas */}
      <div className="relative h-[46vh] shrink-0 lg:absolute lg:inset-0 lg:h-auto">
        <div className="grid-bg absolute inset-0" />
        <GraphCanvas overview={overview} focus={result?.subgraph ?? null} replayKey={replayKey} panelOpen={!!result} selected={selected} onSelect={(s) => { setSelected(s); setTab("company"); }} />
        {!overview && !error && <div className="absolute inset-0 flex items-center justify-center"><Spinner className="h-5 w-5" /></div>}
        <div className="pointer-events-none absolute bottom-4 left-1/2 hidden -translate-x-1/2 items-center gap-4 rounded-full border border-line bg-surface/80 px-4 py-1.5 text-[11px] text-muted backdrop-blur lg:flex">
          <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full border border-warn bg-warn/30" /> internet-exposed</span>
          <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-accent" /> traversed path</span>
          <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-bad" /> vulnerable package</span>
          <span className="text-faint">{result ? "dependency chain, hop by hop" : "node size = PageRank"}</span>
        </div>
      </div>

      {/* command bar */}
      <div className="relative z-20 mx-auto w-full max-w-[640px] px-4 pt-3 lg:absolute lg:left-1/2 lg:top-[68px] lg:-translate-x-1/2 lg:pt-0">
        <div className={clsx("glass flex items-center gap-2 rounded-2xl px-3.5 py-2.5 transition", focused && "border-accent/60 shadow-[0_0_0_4px_rgba(53,224,242,0.08)]")}>
          {running ? <Spinner /> : <Search className="h-4 w-4 text-muted" />}
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onFocus={() => setFocused(true)}
            onBlur={() => setTimeout(() => setFocused(false), 120)}
            onKeyDown={(e) => e.key === "Enter" && run(input)}
            placeholder="Paste a CVE / GHSA id, or ask: who owns paymentservice?"
            aria-label="Triage a vulnerability or ask a question"
            className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-faint"
          />
          <kbd className="mono hidden rounded border border-line-strong px-1.5 py-0.5 text-[10px] text-faint sm:block">Ctrl K</kbd>
          <button onClick={() => run(input)} className="flex items-center gap-1 rounded-lg bg-accent px-2.5 py-1 text-xs font-semibold text-bg transition hover:brightness-110" aria-label="Run">
            Run <CornerDownLeft className="h-3 w-3" />
          </button>
        </div>
        <AnimatePresence>
          {focused && !input && (
            <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="glass mt-2 rounded-2xl p-2">
              <div className="px-2 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">Try</div>
              {samples.map((s) => (
                <button
                  key={s.q}
                  onMouseDown={(e) => { e.preventDefault(); setInput(s.q); run(s.q); }}
                  className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs text-[#c3cce0] hover:bg-surface-2"
                >
                  <Sparkles className="h-3 w-3 text-accent" /> {s.label}
                  <span className="mono ml-auto truncate text-[10px] text-faint">{s.q}</span>
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
        <AnimatePresence>
          {(answer || error) && (
            <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className={clsx("glass mt-2 rounded-2xl p-3.5 text-sm", error && "border-bad/50")}>
              <div className="flex items-start gap-2">
                <div className="min-w-0 flex-1">
                  {error ? <p className="text-bad">{error}</p> : <p className="whitespace-pre-wrap leading-snug">{answer?.answer}</p>}
                  {answer && (
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {answer.tool_calls.map((t, i) => <Pill key={i} tone="accent" className="mono">{t.tool}</Pill>)}
                      <Pill>{answer.mode === "gemini" ? "Gemini free tier" : "offline router · $0"}</Pill>
                    </div>
                  )}
                </div>
                <button onClick={() => { setAnswer(null); setError(null); }} aria-label="Dismiss" className="text-faint hover:text-fg"><X className="h-4 w-4" /></button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* left panel */}
      <aside className="glass relative z-10 mx-4 mt-3 flex min-h-[420px] flex-col rounded-2xl p-3.5 lg:absolute lg:bottom-4 lg:left-4 lg:top-[68px] lg:mx-0 lg:mt-0 lg:min-h-0 lg:w-[360px]">
        <div className="mb-3 flex gap-1 rounded-xl border border-line bg-bg/60 p-0.5" role="tablist">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={clsx("flex flex-1 items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition", tab === t.id ? "bg-surface-2 text-fg" : "text-muted hover:text-fg")}
            >
              <t.icon className="h-3.5 w-3.5" /> {t.label}
            </button>
          ))}
        </div>
        {tab === "risk" && <RiskBoard risk={risk} activeId={result?.advisory?.id} onPick={run} />}
        {tab === "memory" && (
          <MemoryView brain={brain} onReset={async () => { await api.reset(tenant); setResult(null); refreshBrain(tenant); }} />
        )}
        {tab === "company" && <CompanyView tenant={tenant} overview={overview} selected={selected} onSelect={setSelected} />}
      </aside>

      {/* right panel */}
      <AnimatePresence>
        {result && (
          <motion.aside
            key={result.run_id}
            initial={{ opacity: 0, x: 24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 24 }}
            transition={{ type: "spring", stiffness: 260, damping: 28 }}
            className="glass relative z-10 mx-4 mb-4 mt-3 flex flex-col rounded-2xl lg:absolute lg:bottom-4 lg:right-4 lg:top-[68px] lg:mx-0 lg:mb-0 lg:mt-0 lg:w-[420px]"
          >
            <div className="flex items-center gap-2 border-b border-line px-4 py-3">
              <Waypoints className="h-4 w-4 text-accent" />
              <span className="text-sm font-semibold">Triage</span>
              <span className="mono truncate text-xs text-muted">{result.advisory?.cve ?? result.ident}</span>
              <button onClick={() => setResult(null)} aria-label="Close triage" className="ml-auto text-faint hover:text-fg"><X className="h-4 w-4" /></button>
            </div>
            <div className="scroll min-h-0 flex-1 overflow-y-auto p-4">
              <ResultPanel r={result} tenant={tenant} onReplay={() => setReplayKey((k) => k + 1)} onDecided={() => { refreshBrain(tenant); refreshRisk(tenant); }} />
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </main>
  );
}
