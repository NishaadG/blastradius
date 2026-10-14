// full demo flow with screenshots. usage: node flow.mjs <outdir>
import { chromium } from "playwright";
import fs from "node:fs";

const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const base = process.env.BASE ?? "http://localhost:3001";
const api = process.env.API ?? "http://localhost:8000";
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
const errs = [];
page.on("pageerror", (e) => errs.push(e.message));
page.on("console", (m) => m.type() === "error" && errs.push(m.text()));
const shot = (n) => page.screenshot({ path: `${out}/${n}.png` });
const run = async (q) => {
  await page.fill("input[aria-label^='Triage']", q);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(5200);
};

await fetch(`${api}/api/boutique/reset-memory`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
await page.goto(base, { waitUntil: "networkidle" });
await page.waitForTimeout(1200);
await run("CVE-2026-41242");
await shot("1-triage");
await page.getByRole("button", { name: "Approve fix" }).click();
await page.waitForTimeout(1200);
await run("CVE-2026-48712");
await shot("2-precedent");
await page.getByRole("tab", { name: /Memory/ }).click();
await page.waitForTimeout(800);
await shot("3-memory");
await page.getByRole("tab", { name: /Company/ }).click();
await page.getByRole("button", { name: "paymentservice", exact: true }).click();
await page.waitForTimeout(1500);
await shot("4-company");
await run("GHSA-jfh8-c2jp-5v3q");
await shot("5-nopath");
await page.fill("input[aria-label^='Triage']", "who owns paymentservice?");
await page.keyboard.press("Enter");
await page.waitForTimeout(1500);
await shot("6-ask");
await page.getByRole("tab", { name: /OpenTelemetry/ }).click();
await page.waitForTimeout(2500);
await shot("7-otel");
console.log(errs.join("\n") || "no errors");
await browser.close();
