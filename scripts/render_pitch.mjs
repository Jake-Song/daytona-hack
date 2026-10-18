// Requires the existing frontend Playwright development dependency.
import { chromium } from "../frontend/node_modules/playwright-core/index.mjs";
import { fileURLToPath } from "node:url";
const pageUrl = new URL("../docs/AgentZero-Pitch.html", import.meta.url);
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1 });
  await page.goto(pageUrl.href);
  await page.evaluate(() => document.fonts.ready);
  await page.pdf({ path: fileURLToPath(new URL("../docs/AgentZero-Pitch.pdf", import.meta.url)), width: "1600px", height: "900px", printBackground: true, margin: { top: "0", right: "0", bottom: "0", left: "0" } });
  await page.screenshot({ path: fileURLToPath(new URL("../docs/AgentZero-Pitch.png", import.meta.url)) });
  console.log("Created PDF and PNG preview.");
} finally {
  await browser.close();
}
