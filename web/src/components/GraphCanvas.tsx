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

const ACCENT = "#35e0f2";

const STYLE = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      color: "#c3cce0",
      "font-size": 11,
      "font-family": "Inter, system-ui, sans-serif",
      "font-weight": 500,
      "text-wrap": "ellipsis",
      "text-max-width": "170px",
      "background-color": "#121823",
      "border-width": 1.5,
      "border-color": "#2a3547",
      "transition-property": "opacity, background-color, border-color, underlay-opacity, border-width",
      "transition-duration": 320,
    },
  },
  {
    selector: "node.ov",
    style: {
      shape: "ellipse",
      width: "data(size)",
      height: "data(size)",
      "text-valign": "bottom",
      "text-margin-y": 7,
      "font-size": 12,
    },
  },
  {
    selector: "node.fx[type='service']",
    style: {
      shape: "round-rectangle",
      width: "data(w)",
      height: 32,
      "text-halign": "center",
      "text-valign": "center",
      "text-halign": "center",
      "border-color": "#3b4a63",
      color: "#e8ecf4",
      "font-weight": 600,
    },
  },
  {
    selector: "node.fx[type='package']",
    style: {
      shape: "round-rectangle",
      width: "data(w)",
      height: 26,
      "text-valign": "center",
      "text-halign": "center",
      "font-family": "JetBrains Mono, ui-monospace, monospace",
      "font-size": 10,
      color: "#9aa7bf",
    },
  },
  {
    selector: "node.fx[type='vuln']",
    style: {
      shape: "round-rectangle",
      width: "data(w)",
      height: 30,
      "text-valign": "center",
      "text-halign": "center",
      "font-family": "JetBrains Mono, ui-monospace, monospace",
      "font-size": 10.5,
      "font-weight": 600,
      color: "#fff",
      "background-color": "#3a1420",
      "border-color": "#ff4d6d",
    },
  },
  {
    selector: "node.exposed",
    style: {
      "border-color": "#ffb547",
      "underlay-color": "#ffb547",
      "underlay-opacity": 0.16,
      "underlay-padding": 9,
      "underlay-shape": "ellipse",
    },
  },
  {
    selector: "node.vuln.hit",
    style: { "underlay-color": "#ff4d6d", "underlay-opacity": 0.32, "underlay-padding": 12, "border-width": 2.5 },
  },
  { selector: "node.dim", style: { opacity: 0.28 } },
  {
    selector: "node.lit",
    style: { "border-color": ACCENT, "border-width": 2, opacity: 1, "underlay-color": ACCENT, "underlay-opacity": 0.14, "underlay-padding": 8 },
  },
  { selector: "node.lit.vuln", style: { "border-color": "#ff4d6d" } },
  { selector: "node.sel", style: { "border-color": "#ffffff", "border-width": 2.5 } },
  {
    selector: "edge",
    style: {
      width: 1.3,
      "curve-style": "bezier",
      "line-color": "#2a3547",
      "target-arrow-color": "#2a3547",
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.8,
      opacity: 0.9,
      "transition-property": "opacity, line-color, width, target-arrow-color",
      "transition-duration": 320,
    },
  },
  { selector: "edge[type='DEPENDS_ON']", style: { "line-style": "dashed", "line-dash-pattern": [5, 4] } },
  { selector: "edge.dim", style: { opacity: 0.12 } },
  {
    selector: "edge.lit",
    style: { "line-color": ACCENT, "target-arrow-color": ACCENT, width: 2.8, opacity: 1, "z-index": 10 },
  },
] as unknown as cytoscape.StylesheetJson;

type Props = {
  overview: GraphData | null;
  focus: Subgraph | null;
  replayKey: number;
  panelOpen: boolean;
  selected: string | null;
  onSelect: (service: string) => void;
};

function overviewElements(o: GraphData, exposedBy: Set<string>): ElementDefinition[] {
  const max = Math.max(...o.nodes.map((n) => n.centrality), 1e-9);
  return [
    ...o.nodes.map((n) => ({
      data: { id: n.id, label: n.id, type: "service", size: 24 + 26 * (n.centrality / max) },
      classes: "ov" + (n.exposed || exposedBy.has(n.id) ? " exposed" : ""),
    })),
    ...o.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, type: "CALLS" } })),
  ];
}

function focusElements(f: Subgraph): ElementDefinition[] {
  return [
    ...f.nodes.map((n) => {
      const per = n.type === "service" ? 7.4 : 6.2;
      const w = Math.min(n.label.length, 26) * per + 28;
      return { data: { id: n.id, label: n.label, type: n.type, w }, classes: `fx ${n.type}` };
    }),
    ...f.edges.map((e, i) => ({ data: { id: `f${i}`, source: e.source, target: e.target, type: e.type } })),
  ];
}

/** Fit the graph into the free area between the floating panels. */
function fitFree(c: Core, hasRight: boolean, maxZoom: number) {
  if (c.elements().length === 0) return;
  const lg = window.innerWidth >= 1024;
  const left = lg ? 392 : 16, right = lg && hasRight ? 436 : 16, top = lg ? 130 : 16, bottom = lg ? 72 : 16;
  const bb = c.elements().boundingBox({ includeLabels: true });
  const aw = Math.max(c.width() - left - right, 120), ah = Math.max(c.height() - top - bottom, 120);
  const z = Math.min(aw / Math.max(bb.w, 1), ah / Math.max(bb.h, 1), maxZoom);
  c.zoom(z);
  c.pan({ x: left + (aw - bb.w * z) / 2 - bb.x1 * z, y: top + (ah - bb.h * z) / 2 - bb.y1 * z });
}

export default function GraphCanvas({ overview, focus, replayKey, panelOpen, selected, onSelect }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const timers = useRef<number[]>([]);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const hasFocus = useRef(false);
  hasFocus.current = panelOpen;

  useEffect(() => {
    if (!host.current) return;
    const c = cytoscape({ container: host.current, style: STYLE, wheelSensitivity: 0.25, minZoom: 0.2, maxZoom: 2.5 });
    cy.current = c;
    (window as unknown as { __cy?: Core }).__cy = c;
    c.on("tap", "node.ov", (ev) => onSelectRef.current(ev.target.id()));
    const ro = new ResizeObserver(() => {
      c.resize();
      fitFree(c, hasFocus.current, hasFocus.current ? 1.25 : 1);
    });
    ro.observe(host.current);
    return () => {
      ro.disconnect();
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
      c.layout({ name: "dagre", rankDir: "LR", nodeSep: 26, rankSep: 90, padding: 30, animate: false, ...opts } as never).run();

    if (focus && focus.nodes.length) {
      c.add(focusElements(focus));
      layout({ rankDir: "TB", rankSep: 46, nodeSep: 30 });
      fitFree(c, true, 1.25);
      c.elements().addClass("dim");
      const edges = c.edges().toArray().sort((a, b) => (a.data("type") === "CALLS" ? 0 : 1) - (b.data("type") === "CALLS" ? 0 : 1));
      edges.forEach((e, i) => {
        timers.current.push(
          window.setTimeout(() => {
            e.removeClass("dim").addClass("lit");
            e.source().removeClass("dim").addClass("lit");
            e.target().removeClass("dim").addClass("lit");
          }, 350 + i * 420),
        );
      });
      timers.current.push(
        window.setTimeout(() => c.nodes(".vuln").addClass("hit"), 350 + edges.length * 420 + 100),
      );
    } else if (overview) {
      const exposed = new Set(overview.nodes.filter((n) => n.exposed).map((n) => n.id));
      c.add(overviewElements(overview, exposed));
      layout({});
      fitFree(c, panelOpen, 1);
    }
  }, [overview, focus, replayKey, panelOpen]);

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
