"use client";

import { useEffect, useRef, useState } from "react";
import { api, IngestJob } from "@/lib/api";
import { Label } from "./ui";

const REPO_URL = "https://github.com/NishaadG/blastradius";

export default function RepoAnalyzer({ onDone }: { onDone: (tenant: string) => void }) {
  const [repo, setRepo] = useState("");
  const [job, setJob] = useState<IngestJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(() => () => { if (timer.current) window.clearTimeout(timer.current); }, []);

  function poll(id: string) {
    timer.current = window.setTimeout(async () => {
      try {
        const j = await api.ingestJob(id);
        setJob(j);
        if (j.status === "running") poll(id);
        else if (j.status === "done" && j.tenant) onDone(j.tenant);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, 1200);
  }

  async function start(e: React.FormEvent) {
    e.preventDefault();
    const value = repo.trim().replace(/^https?:\/\/github\.com\//, "").replace(/\.git$/, "").replace(/\/$/, "");
    setError(null);
    setJob(null);
    setStarting(true);
    try {
      const { job: id } = await api.startIngest(value);
      setJob({ id, repo: value, status: "running", log: [], tenant: null, error: null });
      poll(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  }

  const running = job?.status === "running";

  return (
    <section className="mt-8 border-t border-rule pt-4">
      <Label>Analyse a public repository</Label>
      <form onSubmit={start} className="flex items-end gap-3">
        <input
          value={repo}
          onChange={(e) => setRepo(e.target.value)}
          placeholder="owner/name, e.g. apache/druid"
          aria-label="Public GitHub repository"
          className="mono min-w-0 flex-1 border-0 border-b border-rule-strong bg-transparent px-0 py-1.5 text-[12.5px] outline-none placeholder:text-faint focus:border-ink"
        />
        <button className="btn" disabled={starting || running || repo.trim().length < 3}>
          {running ? "Analysing…" : "Analyse"}
        </button>
      </form>

      {(job || error) && (
        <div className="mt-3 border-l-2 border-rule-strong pl-3">
          {job?.log.slice(-5).map((l, i) => (
            <div key={i} className="mono text-[11px] leading-[1.6] text-ink-2">{l}</div>
          ))}
          {running && <div className="mono text-[11px] text-faint">working…</div>}
          {job?.status === "done" && <div className="text-[12.5px] text-green">Done. Opened as a new tenant; try the risk board.</div>}
          {(error || job?.error) && <div className="text-[12.5px] text-red">{error ?? job?.error}</div>}
        </div>
      )}

      <p className="mt-3 text-[12px] leading-relaxed text-faint">
        This hosted demo is limited: public repositories only, up to 15 dependency manifests, one analysis at a time. It
        has no deployment topology for your repo, so exposure is unknown and every service is assumed reachable. For real
        use, <a className="link" href={REPO_URL} target="_blank" rel="noreferrer">clone the repository and run Blastradius
        yourself</a>; that is the better way, with no limits.
      </p>
    </section>
  );
}
