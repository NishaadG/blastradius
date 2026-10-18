// Records crisp 1080p demo clips (Chrome screencast frames -> H.264), one file per beat, with a visible cursor.
// usage: node record.mjs <outdir> <clip...>     clips: guided chat reach repo offline title
// env: BASE (live site), LOCAL (local web, for the offline clip), FALKOR_CONTAINER
import { chromium } from "playwright";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const out = path.resolve(process.argv[2]);
const clips = process.argv.slice(3);
const BASE = process.env.BASE ?? "https://13-203-50-195.sslip.io";
const LOCAL = process.env.LOCAL ?? "http://localhost:3001";
const FALKOR = process.env.FALKOR_CONTAINER ?? "blastradius-falkordb-1";
fs.mkdirSync(out, { recursive: true });

const CURSOR = `
  addEventListener("DOMContentLoaded", () => {
    const c = document.createElement("div"); c.id = "__cur";
    c.style.cssText = "position:fixed;z-index:99999;left:-40px;top:-40px;width:18px;height:18px;margin:-9px 0 0 -9px;border-radius:50%;" +
      "background:rgba(20,20,20,.35);border:2px solid rgba(255,255,255,.9);box-shadow:0 1px 4px rgba(0,0,0,.35);pointer-events:none;" +
      "transition:left .55s cubic-bezier(.3,.7,.3,1),top .55s cubic-bezier(.3,.7,.3,1),transform .12s,opacity .4s";
    document.body.appendChild(c);
  });`;

async function session(name) {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1.2 });
  await ctx.addInitScript(CURSOR);
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  const dir = path.join(out, `.${name}`);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir);
  const frames = [];
  const marks = {};
  cdp.on("Page.screencastFrame", async (f) => {
    const file = path.join(dir, `${String(frames.length).padStart(6, "0")}.jpg`);
    fs.writeFileSync(file, Buffer.from(f.data, "base64"));
    frames.push({ file, t: f.metadata.timestamp });
    await cdp.send("Page.screencastFrameAck", { sessionId: f.sessionId }).catch(() => {});
  });
  const start = () => cdp.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });
  const mark = (k) => (marks[k] = Date.now() / 1000);
  async function finish(speedup = []) {
    const end = Date.now() / 1000;
    await cdp.send("Page.stopScreencast").catch(() => {});
    await browser.close();
    // durations from frame timestamps; a [from,to] window is squeezed to `to-from` -> `len` seconds
    let list = "ffconcat version 1.0\n";
    for (let i = 0; i < frames.length; i++) {
      const t0 = frames[i].t, t1 = i + 1 < frames.length ? frames[i + 1].t : end;
      let d = Math.max(t1 - t0, 0.001);
      for (const w of speedup) if (t0 >= w.from && t0 < w.to) d *= w.len / (w.to - w.from);
      list += `file '${frames[i].file.replace(/\\/g, "/")}'\nduration ${d.toFixed(4)}\n`;
    }
    list += `file '${frames.at(-1).file.replace(/\\/g, "/")}'\n`;
    fs.writeFileSync(path.join(dir, "list.txt"), list);
    const mp4 = path.join(out, `${name}.mp4`);
    execSync(`ffmpeg -v error -y -f concat -safe 0 -i "${path.join(dir, "list.txt")}" -vf "fps=30,scale=1920:1080:flags=lanczos,format=yuv420p" -c:v libx264 -crf 16 -preset slow -movflags +faststart "${mp4}"`);
    fs.rmSync(dir, { recursive: true, force: true });
    console.log("wrote", mp4);
  }
  return { page, start, mark, marks, finish };
}

async function point(page, loc) {
  const b = await loc.boundingBox();
  if (!b) return;
  await page.evaluate(([x, y]) => { const c = document.getElementById("__cur"); if (c) { c.style.opacity = "1"; c.style.left = x + "px"; c.style.top = y + "px"; } },
    [b.x + b.width / 2, b.y + b.height / 2]);
  await page.waitForTimeout(650);
}
async function click(page, loc) {
  await point(page, loc);
  await page.evaluate(() => { const c = document.getElementById("__cur"); if (c) { c.style.transform = "scale(.7)"; setTimeout(() => (c.style.transform = ""), 150); setTimeout(() => (c.style.opacity = "0"), 900); } });
  await loc.click();
}
async function ask(page, text) {
  const input = page.getByPlaceholder("Paste a CVE or GHSA id, or ask a question");
  await click(page, input);
  await input.fill("");
  await input.pressSequentially(text, { delay: 45 });
  await page.waitForTimeout(400);
  await click(page, page.getByRole("button", { name: "Run", exact: true }));
}
const hold = (page, s) => page.waitForTimeout(s * 1000);

const CLIPS = {
  // the built-in guided demo: protobufjs path, approval, precedent, Log4Shell no-path, company brain, tenant isolation
  async guided() {
    const s = await session("01-guided");
    await s.page.goto(BASE, { waitUntil: "networkidle" });
    await hold(s.page, 1.5);
    await s.start();
    await hold(s.page, 3);
    await click(s.page, s.page.getByRole("button", { name: "Guided demo", exact: true }));
    await s.page.getByRole("button", { name: "Stop demo", exact: true }).waitFor();
    await s.page.getByRole("button", { name: "Guided demo", exact: true }).waitFor({ timeout: 180000 });
    await hold(s.page, 3);
    await s.finish();
  },
  // the LLM picks tools; every fact comes from the graph; the trace is visible
  async chat() {
    const s = await session("02-chat");
    await s.page.goto(BASE, { waitUntil: "networkidle" });
    await hold(s.page, 1.5);
    await s.start();
    await hold(s.page, 2);
    for (const q of ["Why did we upgrade golang.org/x/net?", "Are we affected by CVE-2026-41242, and who should fix it?"]) {
      await ask(s.page, q);
      const sum = s.page.locator("summary", { hasText: "how this was answered" });
      await sum.waitFor({ timeout: 120000 });
      const mode = await sum.textContent();
      if (!mode.includes("Gemini")) console.warn("WARNING: answered without Gemini:", mode);
      await hold(s.page, 2);
      await point(s.page, sum);
      await hold(s.page, 9);
    }
    await s.finish();
  },
  // function-level reachability: govulncheck call stack stored on the graph edge
  async reach() {
    const s = await session("03-reach");
    await s.page.goto(BASE, { waitUntil: "networkidle" });
    await hold(s.page, 1.5);
    await s.start();
    await hold(s.page, 2);
    await ask(s.page, "CVE-2026-97032");
    await s.page.getByText("Affected", { exact: true }).waitFor({ timeout: 60000 });
    await hold(s.page, 5);
    const r = s.page.getByText(/called from|call stack|vulnerable function/i).first();
    if (await r.count()) { await r.scrollIntoViewIfNeeded(); await point(s.page, r); }
    await hold(s.page, 8);
    await s.finish();
  },
  // any public repo: Log4Shell found through a transitive dependency no manifest names
  async repo() {
    const s = await session("04-repo");
    await s.page.goto(BASE, { waitUntil: "networkidle" });
    await hold(s.page, 1.5);
    await s.start();
    await hold(s.page, 2);
    const input = s.page.getByLabel("Public GitHub repository");
    if (!(await input.isVisible())) await click(s.page, s.page.getByRole("button", { name: "Analyse a repo", exact: true }));
    await click(s.page, input);
    await input.pressSequentially("christophetd/log4shell-vulnerable-app", { delay: 45 });
    await hold(s.page, 0.5);
    await click(s.page, s.page.getByRole("button", { name: "Analyse", exact: true }));
    s.mark("a");
    await s.page.getByText(/Done\. Opened as a new tenant|rate limit|too many/i).waitFor({ timeout: 240000 });
    s.mark("b");
    await hold(s.page, 3);
    await ask(s.page, "CVE-2021-44228");
    await s.page.getByText("Affected", { exact: true }).waitFor({ timeout: 60000 });
    await hold(s.page, 10);
    const sp = s.marks.b - s.marks.a > 8 ? [{ from: s.marks.a + 3, to: s.marks.b - 1, len: 3 }] : [];
    await s.finish(sp);
  },
  // the graph is not decoration: stop FalkorDB and the product stops (LOCAL stack)
  async offline() {
    const s = await session("05-offline");
    await s.page.goto(LOCAL, { waitUntil: "networkidle" });
    await hold(s.page, 2);
    await s.start();
    await hold(s.page, 2);
    await ask(s.page, "CVE-2026-41242");
    await s.page.getByText("Affected", { exact: true }).waitFor({ timeout: 60000 });
    await hold(s.page, 5);
    execSync(`docker stop ${FALKOR}`);
    await s.page.getByRole("alert").waitFor({ timeout: 60000 });
    await hold(s.page, 4);
    await ask(s.page, "CVE-2026-41242");
    await hold(s.page, 5);
    execSync(`docker start ${FALKOR}`);
    await s.page.getByRole("alert").waitFor({ state: "detached", timeout: 90000 });
    await hold(s.page, 2);
    await ask(s.page, "CVE-2026-41242");
    await s.page.getByText("Affected", { exact: true }).waitFor({ timeout: 60000 });
    await hold(s.page, 5);
    await s.finish();
  },
  async title() {
    const s = await session("06-title");
    await s.page.goto(pathToFileURL(path.join(path.dirname(fileURLToPath(import.meta.url)), "title.html")).href, { waitUntil: "networkidle" });
    await s.page.evaluate(() => document.fonts.ready);
    await s.start();
    await hold(s.page, 7);
    await s.finish();
  },
};

for (const c of clips) {
  console.log("recording", c);
  await CLIPS[c]();
}
