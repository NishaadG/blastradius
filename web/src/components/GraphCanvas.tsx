"use client";

import { useEffect, useRef } from "react";
import cytoscape, { Core, ElementDefinition } from "cytoscape";
import dagre from "cytoscape-dagre";
import type { GraphData, Subgraph } from "@/lib/api";

const g = globalThis as unknown as { __brDagre?: boolean };
if (!g.__brDagre) {
  cytoscape.use(dagre);
  g.__brDagre = true;
}

function theme() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n: string) => cs.getPropertyValue(n).trim();
  return {
    paper: v("--paper"), panel: v("--panel"), sunk: v("--sunk"), ink: v("--ink"), ink2: v("--ink-2"),
    faint: v("--faint"), rule: v("--rule-strong"), red: v("--red"), amber: v("--amber"),
  };
}

const SANS = "IBM Plex Sans, system-ui, sans-serif";
const MONO = "IBM Plex Mono, ui-monospace, monospace";

/** A schematic, not a neon graph: square nodes, orthogonal edges, ink on paper, red only for the attack path. */
function buildStyle(t: ReturnType<typeof theme>) {
  return [
    {
      selector: "node",
      style: {
        label: "data(label)", color: t.ink, "font-family": SANS, "font-size": 11, "font-weight": 500,
        "text-wrap": "ellipsis", "text-max-width": "190px",
        "background-color": t.panel, "border-width": 1, "border-color": t.ink,
        "transition-property": "opacity, background-color, border-color, border-width", "transition-duration": 260,
      },
    },
    {
      selector: "node.ov",
      style: {
        shape: "ellipse", width: "data(size)", height: "data(size)", "text-valign": "bottom", "text-margin-y": 6,
        "background-color": t.paper, "border-color": t.ink2,
      },
    },
    { selector: "node.ov.exposed", style: { "border-style": "double", "border-width": 4, "border-color": t.amber } },
    {
      selector: "node.fx[type='service']",
      style: {
        shape: "rectangle", width: "data(w)", height: 30, "text-valign": "center", "text-halign": "center",
        "font-weight": 600, "font-size": 12, "border-width": 1.25, "background-color": t.panel,
      },
    },
    {
      selector: "node.fx[type='package']",
      style: {
        shape: "rectangle", width: "data(w)", height: 24, "text-valign": "center", "text-halign": "center",
        "font-family": MONO, "font-size": 10, "font-weight": 400, color: t.ink2, "border-color": t.rule,
        "background-color": t.paper,
      },
    },
    {
      selector: "node.fx[type='vuln']",
      style: {
        shape: "rectangle", width: "data(w)", height: 28, "text-valign": "center", "text-halign": "center",
        "font-family": MONO, "font-size": 10.5, "font-weight": 600, color: t.paper,
        "background-color": t.red, "border-color": t.red,
      },
    },
    { selector: "node.fx.exposed", style: { "border-style": "double", "border-width": 4, "border-color": t.amber } },
    { selector: "node.dim", style: { opacity: 0.3 } },
    { selector: "node.lit", style: { "border-color": t.red, "border-width": 1.75 } },
    { selector: "node.lit[type='service']", style: { "border-color": t.red } },
    { selector: "node.sel", style: { "border-color": t.ink, "border-width": 3 } },
    {
      selector: "edge",
      style: {
        width: 1, "curve-style": "taxi", "taxi-direction": "auto", "taxi-turn": "50%", "line-color": t.rule,
        "target-arrow-color": t.rule, "target-arrow-shape": "triangle", "arrow-scale": 0.7,
        "transition-property": "opacity, line-color, width, target-arrow-color", "transition-duration": 260,
      },
    },
    { selector: "edge.ov", style: { "curve-style": "bezier", opacity: 0.7 } },
    { selector: "edge.fe", style: { "taxi-direction": "vertical" } },
    { selector: "edge[type='DEPENDS_ON']", style: { "line-style": "dashed", "line-dash-pattern": [4, 3] } },
    { selector: "edge.dim", style: { opacity: 0.2 } },
    { selector: "edge.lit", style: { "line-color": t.red, "target-arrow-color": t.red, width: 2, opacity: 1, "z-index": 10 } },
  ] as unknown as cytoscape.StylesheetJson;
}

type Props = {
  overview: GraphData | null;
  focus: Subgraph | null;
  replayKey: number;
  selected: string | null;
  onSelect: (service: string) => void;
};

function overviewElements(o: GraphData): ElementDefinition[] {
  const max = Math.max(...o.nodes.map((n) => n.centrality), 1e-9);
  return [
    ...o.nodes.map((n) => ({
      data: { id: n.id, label: n.id, type: "service", size: 16 + 24 * (n.centrality / max) },
      classes: "ov" + (n.exposed ? " exposed" : ""),
    })),
    ...o.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, type: "CALLS" }, classes: "ov" })),
  ];
}

function focusElements(f: Subgraph, exposed: Set<string>): ElementDefinition[] {
  return [
    ...f.nodes.map((n) => {
      const per = n.type === "service" ? 7.6 : 6.3;
      const w = Math.min(n.label.length, 28) * per + 26;
      return {
        data: { id: n.id, label: n.label, type: n.type, w },
        classes: `fx ${n.type}${exposed.has(n.id) ? " exposed" : ""}`,
      };
    }),
    ...f.edges.map((e, i) => ({ data: { id: `f${i}`, source: e.source, target: e.target, type: e.type }, classes: "fe" })),
  ];
}

export default function GraphCanvas({ overview, focus, replayKey, selected, onSelect }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const timers = useRef<number[]>([]);
  const onSelectRef = useRef(onSelect);
  useEffect(() => {
    onSelectRef.current = onSelect;
  });

  useEffect(() => {
    if (!host.current) return;
    const c = cytoscape({
      container: host.current, style: buildStyle(theme()), wheelSensitivity: 0.3, minZoom: 0.2, maxZoom: 3,
    });
    cy.current = c;
    (window as unknown as { __cy?: Core }).__cy = c;
    c.on("tap", "node.ov", (ev) => onSelectRef.current(ev.target.id()));
    const fit = () => {
      c.resize();
      if (c.elements().length) c.fit(undefined, 44);
      if (c.zoom() > 1.15) {
        c.zoom(1.15);
        c.center();
      }
    };
    const ro = new ResizeObserver(fit);
    ro.observe(host.current);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onScheme = () => c.style(buildStyle(theme()));
    mq.addEventListener("change", onScheme);
    return () => {
      ro.disconnect();
      mq.removeEventListener("change", onScheme);
      timers.current.forEach(clearTimeout);
      c.destroy();
    };
  }, []);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    timers.current.forEach(clearTimeout);
    timers.current = [];
    c.elements().remove();
    const layout = (opts: object) =>
      c.layout({ name: "dagre", rankDir: "LR", nodeSep: 22, rankSep: 80, padding: 20, animate: false, ...opts } as never).run();
    const fit = (cap: number) => {
      c.resize();
      c.fit(undefined, 44);
      if (c.zoom() > cap) {
        c.zoom(cap);
        c.center();
      }
    };

    if (focus && focus.nodes.length) {
      const exposed = new Set(overview?.nodes.filter((n) => n.exposed).map((n) => n.id) ?? []);
      c.add(focusElements(focus, exposed));
      layout({ rankDir: "TB", rankSep: 42, nodeSep: 28 });
      fit(1.3);
      c.elements().addClass("dim");
      const edges = c.edges().toArray().sort((a, b) => (a.data("type") === "CALLS" ? 0 : 1) - (b.data("type") === "CALLS" ? 0 : 1));
      edges.forEach((e, i) => {
        timers.current.push(
          window.setTimeout(() => {
            e.removeClass("dim").addClass("lit");
            e.source().removeClass("dim").addClass("lit");
            e.target().removeClass("dim").addClass("lit");
          }, 300 + i * 380),
        );
      });
    } else if (overview) {
      c.add(overviewElements(overview));
      layout({});
      fit(1.25);
    }
  }, [overview, focus, replayKey]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.nodes().removeClass("sel");
    if (selected && !focus) c.getElementById(selected).addClass("sel");
  }, [selected, focus, overview]);

  return (
    <div className="absolute inset-0">
      <div ref={host} className="h-full w-full" aria-label="Dependency and call graph" role="img" />
    </div>
  );
}
