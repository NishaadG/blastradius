"use client";

import { useState } from "react";
import { api, BenchResult } from "@/lib/api";
import { Label } from "./ui";

export default function Bench({ tenant }: { tenant: string }) {
  const [res, setRes] = useState<BenchResult | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run(agents: number) {
    setBusy(agents);
    setErr(null);
    try {
      setRes(await api.bench(tenant, agents));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="mt-6 border-t border-rule pt-4">
      <Label>Shared memory under load</Label>
      <p className="mb-3 text-[12px] leading-snug text-ink-2">
        Many agents reading paths, looking up precedents and writing cases to the same graph at once. Writes use a throwaway
        session that is deleted afterwards.
      </p>
      <div className="flex gap-2">
        {[10, 50, 100].map((n) => (
          <button key={n} className="btn btn-quiet" disabled={busy !== null} onClick={() => run(n)}>
            {busy === n ? "Running…" : `${n} agents`}
          </button>
        ))}
      </div>
      {err && <p className="mt-2 text-[12.5px] text-red">{err}</p>}
      {res && (
        <div className="fade-in mt-4">
          <div className="grid grid-cols-3 border-y border-rule">
            {[
              [res.ops_per_sec.toLocaleString(), "ops per second"],
              [`${res.overall.p50_ms}`, "p50 ms"],
              [`${res.overall.p95_ms}`, "p95 ms"],
            ].map(([n, k], i) => (
              <div key={k} className={i > 0 ? "border-l border-rule px-3 py-2" : "px-3 py-2"}>
                <div className="serif num text-[24px] leading-none">{n}</div>
                <div className="mt-1 text-[10.5px] text-faint">{k}</div>
              </div>
            ))}
          </div>
          <table className="mono num mt-2 w-full text-[11px]">
            <thead>
              <tr className="text-left text-faint"><th className="py-1 font-normal">operation</th><th className="font-normal">count</th><th className="font-normal">p50</th><th className="font-normal">p95</th></tr>
            </thead>
            <tbody>
              {Object.entries(res.by_op).map(([k, v]) => (
                <tr key={k} className="border-t border-rule"><td className="py-1">{k}</td><td>{v.count}</td><td>{v.p50_ms} ms</td><td>{v.p95_ms} ms</td></tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-[11.5px] text-faint">
            {res.agents} concurrent agents for {res.seconds}s · {res.operations.toLocaleString()} operations · {res.errors} errors
            {res.backpressure_retries ? ` · ${res.backpressure_retries} retries after FalkorDB backpressure` : ""}. FalkorDB executes writes one at a
            time, so write latency includes queueing.
          </p>
        </div>
      )}
    </section>
  );
}
