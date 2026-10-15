// usage: node look.mjs <outdir>   -- landing (light/dark) + mobile
import { chromium } from "playwright";
import fs from "node:fs";
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const base = process.env.BASE ?? "http://localhost:3001";
const browser = await chromium.launch();
for (const scheme of ["light", "dark"]) {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, colorScheme: scheme });
  const p = await ctx.newPage();
  await p.goto(base, { waitUntil: "load" });
  await p.waitForTimeout(2500);
  await p.screenshot({ path: `${out}/landing-${scheme}.png` });
  if (scheme === "dark") {
    await p.fill("input[aria-label^='Triage']", "CVE-2026-41242");
    await p.keyboard.press("Enter");
    await p.waitForTimeout(5000);
    await p.screenshot({ path: `${out}/triage-dark.png` });
  }
  await ctx.close();
}
const m = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const mp = await m.newPage();
await mp.goto(base, { waitUntil: "load" });
await mp.waitForTimeout(2500);
await mp.fill("input[aria-label^='Triage']", "CVE-2026-41242");
await mp.keyboard.press("Enter");
await mp.waitForTimeout(5000);
await mp.screenshot({ path: `${out}/mobile.png`, fullPage: true });
await browser.close();
