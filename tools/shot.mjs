// usage: node shot.mjs <out-prefix> [identifier]   -- screenshots the app (overview, then after a triage)
import { chromium } from "playwright";

const prefix = process.argv[2] ?? "shot";
const ident = process.argv[3] ?? "CVE-2026-41242";
const base = process.env.BASE ?? "http://localhost:3001";
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
const logs = [];
page.on("console", (m) => ["error", "warning"].includes(m.type()) && logs.push(`${m.type()}: ${m.text()}`));
page.on("pageerror", (e) => logs.push(`pageerror: ${e.message}`));
await page.goto(base, { waitUntil: "networkidle" });
await page.waitForTimeout(1500);
await page.screenshot({ path: `${prefix}-1-overview.png` });
await page.fill("input[aria-label^='Triage']", ident);
await page.keyboard.press("Enter");
await page.waitForTimeout(5500);
await page.screenshot({ path: `${prefix}-2-triage.png` });
console.log(logs.join("\n") || "no console errors");
await browser.close();
