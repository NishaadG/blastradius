import { Fragment, type ReactNode } from "react";

// The model answers in light markdown. Render the few constructs it uses (bullets, **bold**, `code`, [links](url))
// as elements; everything else stays plain text. No HTML is ever injected.
const INLINE = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g;

function inline(text: string): ReactNode[] {
  return text.split(INLINE).map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) return <b key={i} className="font-semibold">{inline(part.slice(2, -2))}</b>;
    if (part.startsWith("`") && part.endsWith("`")) return <code key={i} className="mono text-[0.82em]">{part.slice(1, -1)}</code>;
    const link = /^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/.exec(part);
    if (link) return <a key={i} className="link" href={link[2]} target="_blank" rel="noreferrer">{link[1]}</a>;
    return <Fragment key={i}>{part}</Fragment>;
  });
}

export default function Answer({ text }: { text: string }) {
  const lines = text.split("\n").map((l) => l.trimEnd()).filter((l) => l.trim());
  const out: ReactNode[] = [];
  let items: ReactNode[] = [];
  const flush = () => {
    if (items.length) out.push(<ul key={`u${out.length}`} className="my-1 list-disc space-y-0.5 pl-5">{items}</ul>);
    items = [];
  };
  lines.forEach((l, i) => {
    const m = /^\s*[-*•]\s+(.*)$/.exec(l);
    if (m) items.push(<li key={i}>{inline(m[1])}</li>);
    else {
      flush();
      out.push(<p key={i} className="my-1 first:mt-0">{inline(l)}</p>);
    }
  });
  flush();
  return <>{out}</>;
}
