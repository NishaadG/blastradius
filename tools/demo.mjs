// Records the guided demo to a .webm and saves a few checkpoint frames.
// usage: node demo.mjs <outdir>
import { chromium } from "playwright";
import fs from "node:fs";

const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const base = process.env.BASE ?? "http://localhost:3001";
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 }, recordVideo: { dir: out, size: { width: 1600, height: 900 } } });
const page = await ctx.newPage();
const errs = [];
page.on("pageerror", (e) => errs.push(e.message));
page.on("console", (m) => m.type() === "error" && errs.push(m.text()));
await page.goto(`${base}?demo=1`, { waitUntil: "networkidle" });
const marks = [9, 20, 33, 45, 56, 66, 75];
let t = 0;
for (const m of marks) {
  await page.waitForTimeout((m - t) * 1000);
  t = m;
  await page.screenshot({ path: `${out}/t${String(m).padStart(2, "0")}.png` });
}
await page.waitForTimeout(8000);
await ctx.close();
await browser.close();
console.log(errs.join("\n") || "no errors");
console.log(fs.readdirSync(out).join(", "));
