// Drives the new features in a real browser. usage: node features.mjs <outdir> [base]
import { chromium } from "playwright";
import fs from "node:fs";
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const base = process.argv[3] ?? "http://localhost";
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
const errs = [];
page.on("pageerror", (e) => errs.push(e.message));
page.on("console", (m) => m.type() === "error" && errs.push(m.text()));
await page.goto(base, { waitUntil: "load" });
await page.waitForTimeout(2500);

// 1. analyse a real public repo end to end
await page.getByRole("button", { name: "Analyse a repo" }).click();
await page.fill("input[aria-label='Public GitHub repository']", "christophetd/log4shell-vulnerable-app");
await page.getByRole("button", { name: "Analyse", exact: true }).click();
await page.waitForTimeout(3000);
await page.screenshot({ path: `${out}/1-analysing.png` });
await page.getByRole("combobox", { name: /Repositories you analysed/ }).waitFor({ timeout: 90000 });
await page.waitForTimeout(2500);
await page.screenshot({ path: `${out}/2-analysed.png` });

// 2. the real Log4Shell, found through a transitive dependency
await page.fill("input[aria-label^='Triage']", "CVE-2021-44228");
await page.keyboard.press("Enter");
await page.waitForTimeout(6000);
await page.screenshot({ path: `${out}/3-log4shell.png` });

// 3. concurrency benchmark
await page.getByRole("tab", { name: "Memory" }).click();
await page.getByRole("button", { name: "100 agents" }).scrollIntoViewIfNeeded();
await page.getByRole("button", { name: "50 agents" }).click();
await page.waitForTimeout(7000);
await page.getByRole("button", { name: "50 agents" }).scrollIntoViewIfNeeded();
await page.screenshot({ path: `${out}/4-bench.png` });
console.log(errs.join("\n") || "no errors");
await browser.close();
