export const API = process.env.NEXT_PUBLIC_API ?? "http://localhost:8000";

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
  repo: string;
  nodes: Record<string, number>;
  edges: Record<string, number>;
};
export type GraphData = {
  nodes: { id: string; exposed: boolean; kind: string; centrality: number }[];
  edges: { source: string; target: string }[];
  trace: Trace[];
};
export type RiskItem = {
  id: string;
  cve: string | null;
  severity: string;
  summary: string;
  services: string[];
  packages: string[];
  fixed: string[];
  exposed: boolean;
  priority: "P0" | "P1" | "P2" | "DEV";
};
export type Risk = { advisories: RiskItem[]; summary: Record<string, number> };
export type Brain = {
  cases: { id: string; decision: string; ts: number; reused: number; actor: string }[];
  runs: number;
  playbooks: { key: string; successes: number; failures: number; steps: string }[];
};
export type ServiceCard = {
  service: string;
  owners: Owner[];
  experts: { name: string; kind: string; commits: number; last: string }[];
  decisions: { id: string; text: string; author: string; date: string; source: string; superseded_by: string | null }[];
  callers: Caller[];
  exposure_path: string[] | null;
  traces: Trace[];
};
export type AskResult = { answer: string; tool_calls: { tool: string; args: Record<string, unknown> }[]; triage: TriageResult | null; mode: string };

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
const post = <T,>(p: string, body: unknown) => j<T>(p, { method: "POST", body: JSON.stringify(body) });

export const api = {
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
