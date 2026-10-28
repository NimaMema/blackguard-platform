// End-to-end test of the public showcase: landing page and the zero-install interactive demo.
// Run: node tests/e2e/showcase.e2e.js   (needs the `playwright` and `axe-core` npm packages + Chromium)
"use strict";
const {chromium} = require("playwright");
const http = require("http");
const fs = require("fs");
const path = require("path");
const {checkA11y} = require("./a11y");

const SITE = path.resolve(__dirname, "..", "..", "..", "showcase");
const TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png"};

function serve() {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/+/, "") || "index.html";
    const file = path.resolve(SITE, rel);
    if (!file.startsWith(SITE + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, {"Content-Type": TYPES[path.extname(file)] || "application/octet-stream"});
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function main() {
  const server = await serve();
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch();
  const problems = [];
  let step = "landing";
  const page = await browser.newPage({viewport: {width: 1440, height: 900}});
  const apiRequests = [];
  page.on("console", m => { if (m.type() === "error") problems.push(`[${step}] console: ${m.text()}`); });
  page.on("pageerror", e => problems.push(`[${step}] pageerror: ${e.message}`));
  page.on("request", r => { if (r.url().includes("/api/")) apiRequests.push(r.url()); });
  page.on("response", r => { if (r.status() >= 400) problems.push(`[${step}] HTTP ${r.status()} ${r.url()}`); });
  try {
    // Landing page: honest labelling, working links, images present, accessible.
    await page.goto(`${base}/index.html`);
    for (const text of ["EXPERIMENTAL", "Not independently security-reviewed or certified", "synthetic data"]) {
      if (!(await page.locator(`text=${text}`).count())) problems.push(`landing page is missing "${text}"`);
    }
    const broken = await page.locator("img").evaluateAll(imgs => imgs.filter(i => !i.complete || i.naturalWidth === 0).map(i => i.getAttribute("src")));
    await page.locator("#screens img").last().scrollIntoViewIfNeeded();
    await page.waitForTimeout(500);
    const stillBroken = await page.locator("img").evaluateAll(imgs => imgs.filter(i => i.complete && i.naturalWidth === 0).map(i => i.getAttribute("src")));
    if (stillBroken.length) problems.push(`broken images: ${stillBroken.join(", ")} (initially pending: ${broken.length})`);
    await checkA11y(page, "landing", problems);

    // Demo: opens straight into the dashboard with no sign-in and no backend.
    step = "demo";
    await page.click("text=Launch the interactive demo");
    await page.locator("#authGate.hidden").waitFor({state: "attached"});
    await page.locator("#metricEvents").filter({hasText: /\d/}).waitFor();
    if (!(await page.locator(".demo-ribbon", {hasText: "Synthetic data"}).isVisible())) problems.push("demo ribbon not visible");
    if ((await page.textContent("#modeTag")).trim() !== "DEMO DATA") problems.push("demo must be labelled DEMO DATA");
    if (await page.isVisible("#onboarding")) problems.push("first-run checklist should be hidden in the demo");
    await checkA11y(page, "demo overview", problems);

    for (const view of ["incidents", "events", "devices", "agents", "responses", "rules", "audit", "settings"]) {
      step = `demo ${view}`;
      await page.click(`.nav-item[data-view=${view}]`);
      await page.locator(`#${view}.view.active`).waitFor();
      await page.waitForTimeout(450);
      if (await page.locator(`#${view} .error-state`).count()) problems.push(`error state shown on ${view}`);
      await checkA11y(page, `demo ${view}`, problems);
    }

    step = "demo investigation";
    await page.click(".nav-item[data-view=incidents]");
    await page.selectOption("#incidentSeverity", "critical");
    await page.waitForTimeout(400);
    await page.locator("#incidentList .link-title").first().click();
    await page.locator("#incidentWorkspace .workspace-title").waitFor();
    await checkA11y(page, "demo incident workspace", problems);
    await page.fill("#incidentWorkspace textarea", "Reviewer note added in the demo.");
    await page.click("text=Save note");
    await page.locator("#incidentWorkspace", {hasText: "Reviewer note added in the demo."}).waitFor();
    const propose = page.locator("#incidentWorkspace .response-option button:has-text('Propose')").first();
    await propose.click();
    await page.locator("#toast.show", {hasText: "proposed"}).waitFor();

    step = "global search";
    await page.press("body", "/");
    if (!(await page.evaluate(() => document.activeElement && document.activeElement.id === "globalSearch"))) problems.push("'/' should focus global search");
    await page.keyboard.type("203.0.113.77");
    await page.locator("#searchResults .search-option").first().waitFor();
    if (await page.getAttribute("#globalSearch", "aria-expanded") !== "true") problems.push("search combobox should be expanded");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await page.waitForTimeout(500);

    step = "ledger sort + time range";
    await page.click(".nav-item[data-view=events]");
    await page.locator("#eventRows tr.clickable").first().waitFor();
    await page.click("#eventTable th button[data-sort=host]");
    if (await page.getAttribute("#eventTable th:has(button[data-sort=host])", "aria-sort") !== "descending") problems.push("sorting should set aria-sort");
    await page.selectOption("#eventRange", "60");
    await page.waitForTimeout(500);
    const lastHour = await page.locator("#eventRows tr.clickable").count();
    await page.selectOption("#eventRange", "");
    await page.waitForTimeout(500);
    const all = await page.locator("#eventRows tr.clickable").count();
    if (!(lastHour < all)) problems.push(`time range filter had no effect (${lastHour} vs ${all})`);

    step = "unsupported action";
    await page.click(".nav-item[data-view=agents]");
    await page.click("#newInvite");
    await page.fill("#modal input[name=name]", "Visitor laptop");
    await page.click("#modalOk");
    await page.locator("#toast.show", {hasText: "static demo"}).waitFor();

    step = "mobile";
    await page.setViewportSize({width: 390, height: 844});
    await page.click("#menuToggle");
    await page.click(".nav-item[data-view=overview]");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (overflow > 1) problems.push(`demo overflows horizontally on mobile by ${overflow}px`);
    await page.goto(`${base}/index.html`);
    const landingOverflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (landingOverflow > 1) problems.push(`landing overflows horizontally on mobile by ${landingOverflow}px`);

    if (apiRequests.length) problems.push(`demo made ${apiRequests.length} network API requests; it must be fully offline`);
  } catch (err) {
    problems.push(`[${step}] ${err.message.split("\n")[0]}`);
  } finally {
    await browser.close();
    server.close();
  }
  if (problems.length) {
    console.error("SHOWCASE E2E FAILED:\n - " + problems.join("\n - "));
    process.exit(1);
  }
  console.log("SHOWCASE E2E OK: landing page, offline demo, every view, investigation, search, sorting, time range, unsupported-action message, mobile, WCAG A/AA (axe) checks.");
}

main().catch(err => { console.error(err); process.exit(1); });
