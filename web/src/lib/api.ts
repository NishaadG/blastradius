// Empty string = same origin (production, behind the reverse proxy). Locally .env.local points at :8000.
export const API = process.env.NEXT_PUBLIC_API ?? "";

/** One id per browser: memory written by this visitor is invisible to (and not wipeable by) other visitors. */
export function sessionId(): string {
  try {
    let s = localStorage.getItem("br-session");
    if (!s) {
      s = crypto.randomUUID();
      localStorage.setItem("br-session", s);
    }
    return s;
  } catch {
    return "anon";
  }
}

export type Trace = { cypher: string; params: Record<string, unknown>; ms: number; rows: number };
export type Step = { agent: string; tool: string; summary: string; ms: number; traces: Trace[] };
export type Owner = { owner: string; kind: string };
export type Caller = { service: string; exposed: boolean; distance: number };
export type PathRow = {
  service: string;
  exposed: boolean;
  pkg_key: string;
  pkg: string;
  version: string;
  dev: boolean;
  fixed: string | null;
  hops: number;
  path: string[];
};
export type ServiceFinding = {
  service: string;
  paths: PathRow[];
  dev_only: boolean;
  exposed: boolean;
  exposure_path: string[] | null;
  exposure_unknown?: boolean;
  reach?: { analyzed: boolean; level?: "called" | "imported" | "required"; symbol?: string; stack?: string[] };
  owners: Owner[];
  callers: Caller[];
};
export type Precedent = {
  id: string;
  decision: string;
  rationale: string;
  actor: string;
  ts: number;
  advisory: string;
  cve: string | null;
  packages: string[];
  services: string[];
  playbooks: string[];
  exact: boolean;
};
export type Action = {
  id: string;
  kind: string;
  service: string | null;
  title: string;
  body: string;
  playbook: string | null;
  status: string;
};
export type Advisory = {
  id: string;
  cve: string | null;
  summary: string;
  severity: string;
  published: string;
  url: string;
};
export type Subgraph = {
  nodes: { id: string; label: string; type: "service" | "package" | "vuln" }[];
  edges: { source: string; target: string; type: "CALLS" | "DEPENDS_ON" }[];
  sequence: { source: string; target: string }[];
};
export type Verdict = "AFFECTED" | "NOT_AFFECTED" | "NEEDS_HUMAN";
export type TriageResult = {
  run_id: string;
  tenant: string;
  ident: string;
  verdict: Verdict;
  reason: string;
  priority: "P0" | "P1" | "P2" | null;
  headline: string;
  advisory: Advisory | null;
  services: ServiceFinding[];
  precedents: Precedent[];
  actions: Action[];
  subgraph: Subgraph;
  steps: Step[];
  total_ms: number;
};
export type TenantInfo = {
  id: string;
  title: string;
  repo: string | null;
  kind: "curated" | "byo";
  exposure_known: boolean;
  nodes: Record<string, number>;
  edges: Record<string, number>;
};
export type GraphData = {
  nodes: { id: string; exposed: boolean; kind: string; centrality: number }[];
  edges: { source: string; target: string }[];
  trace: Trace[];
  exposure_known: boolean;
};
export type BenchResult = {
  tenant: string;
  agents: number;
  seconds: number;
  errors: number;
  backpressure_retries?: number;
  operations: number;
  ops_per_sec: number;
  overall: { p50_ms: number; p95_ms: number; p99_ms: number; mean_ms: number };
  by_op: Record<string, { count: number; p50_ms: number; p95_ms: number }>;
};
export type IngestJob = { id: string; repo: string; status: "running" | "done" | "error"; log: string[]; tenant: string | null; error: string | null };
export type AppConfig = { public: boolean; max_repo_services: number; max_packages: number };
export type RiskItem = {
  id: string;
  cve: string | null;
  severity: string;
  summary: string;
  services: string[];
  packages: string[];
  fixed: string[];
  exposed: boolean;
  new?: boolean;
  reach?: "called" | "not_called" | null;
  priority: "P0" | "P1" | "P2" | "DEV";
};
export type Risk = { advisories: RiskItem[]; summary: Record<string, number> };
export type RescanResult = {
  tenant: string;
  packages: number;
  applicable: number;
  scanned_at: number;
  new: { id: string; cve: string | null; severity: string; priority: string; services: string[]; summary: string }[];
};
export type Brain = {
  cases: { id: string; decision: string; ts: number; reused: number; actor: string }[];
  runs: number;
  playbooks: { key: string; successes: number; failures: number; steps: string }[];
};
export type ServiceCard = {
  service: string;
  owners: Owner[];
  experts: { name: string; kind: string; commits: number; last: string }[];
  decisions: { id: string; text: string; author: string; date: string; source: string; superseded_by: string | null; rationale?: string | null; kind?: string | null; discussion?: string | null; discussion_title?: string | null }[];
  callers: Caller[];
  exposure_path: string[] | null;
  traces: Trace[];
};
export type ToolCall = { tool: string; args: Record<string, unknown>; ms?: number; summary?: string; thought?: string };
export type AskResult = { answer: string; tool_calls: ToolCall[]; triage: TriageResult | null; mode: string; fallback_reason?: string | null };

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", "X-Session": sessionId(), ...(init?.headers ?? {}) },
  });
  if (!r.ok) {
    const body = await r.text();
    let detail = body;
    try {
      detail = JSON.parse(body).detail ?? body;
    } catch {
      /* not json */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return r.json();
}
const post = <T,>(p: string, body: unknown) => j<T>(p, { method: "POST", body: JSON.stringify(body) });

export async function healthy(): Promise<boolean> {
  try {
    const r = await fetch(`${API}/api/health`, { cache: "no-store" });
    return r.ok;
  } catch {
    return false;
  }
}

export type EvalInfo = { available: boolean; passed?: number; total?: number };

export const api = {
  config: () => j<AppConfig>("/api/config"),
  rescan: (t: string) => post<RescanResult>(`/api/${t}/rescan`, {}),
  sbom: (t: string) => j<unknown>(`/api/${t}/sbom`),
  startSbom: (sbom: string) => post<{ job: string }>("/api/sbom", { sbom }),
  vex: (t: string) => j<{ statements: unknown[] }>(`/api/${t}/vex`),
  bench: (t: string, agents: number) => j<BenchResult>(`/api/${t}/bench?agents=${agents}&seconds=4`),
  startIngest: (repo: string) => post<{ job: string }>("/api/ingest", { repo }),
  ingestJob: (id: string) => j<IngestJob>(`/api/ingest/${id}`),
  evals: () => j<EvalInfo>("/api/evals"),
  tenants: () => j<TenantInfo[]>("/api/tenants"),
  graph: (t: string) => j<GraphData>(`/api/${t}/graph`),
  risk: (t: string) => j<Risk>(`/api/${t}/risk`),
  brain: (t: string) => j<Brain>(`/api/${t}/brain`),
  service: (t: string, s: string) => j<ServiceCard>(`/api/${t}/service/${encodeURIComponent(s)}`),
  triage: (t: string, identifier: string) => post<TriageResult>(`/api/${t}/triage`, { identifier }),
  ask: (t: string, question: string) => post<AskResult>(`/api/${t}/ask`, { question }),
  decide: (
    t: string,
    body: { advisory_id: string; decision: string; rationale: string; actor?: string; services: string[]; eco?: string },
  ) => post<{ case_id: string }>(`/api/${t}/decide`, body),
  reset: (t: string) => post<{ ok: boolean }>(`/api/${t}/reset-memory`, {}),
};

export const ID_RE = /(CVE-\d{4}-\d{3,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)/i;
