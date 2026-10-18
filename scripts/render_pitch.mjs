// Requires the existing frontend Playwright development dependency.
import { chromium } from "../frontend/node_modules/playwright-core/index.mjs";
import { fileURLToPath } from "node:url";
const lang = process.argv[2] || "ko";
if (!["ko", "en"].includes(lang)) throw new Error("Language must be ko or en");
const stem = lang === "en" ? "AgentZero-Pitch-EN" : "AgentZero-Pitch";
const pageUrl = new URL(`../docs/${stem}.html`, import.meta.url);
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1 });
  await page.goto(pageUrl.href);
  await page.evaluate(() => document.fonts.ready);
  await page.pdf({ path: fileURLToPath(new URL(`../docs/${stem}.pdf`, import.meta.url)), width: "1600px", height: "900px", printBackground: true, margin: { top: "0", right: "0", bottom: "0", left: "0" } });
  await page.screenshot({ path: fileURLToPath(new URL(`../docs/${stem}.png`, import.meta.url)) });
  console.log("Created PDF and PNG preview.");
} finally {
  await browser.close();
}
