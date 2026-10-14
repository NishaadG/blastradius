import { chromium } from "playwright";
const out = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
await page.goto(process.env.BASE ?? "http://localhost:3001", { waitUntil: "load" });
await page.waitForTimeout(5000); // health poll interval is 3s
await page.screenshot({ path: out });
await browser.close();
