// Reproducible portfolio assets: screenshots, social images and a demo walkthrough video.
//
//   python3 scripts/build_showcase.py            # rebuild the static demo snapshot first
//   node scripts/capture_showcase.js [--no-video]
//
// Requires the `playwright` npm package and Chromium. Everything captured comes from the
// static demo (synthetic data); no real BLACKGUARD instance is contacted.
"use strict";
const {chromium} = require("playwright");
const http = require("http");
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..", "..");
const SITE = path.join(REPO, "showcase");
const SCREENS = path.join(SITE, "assets", "screens");
const DOC_SHOTS = path.join(REPO, "blackguard", "docs", "screenshots");
const PORTFOLIO = path.join(REPO, "blackguard", "docs", "portfolio");
const MEDIA = path.join(REPO, "blackguard", "docs", "media");
const TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json"};

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

async function openDemo(page, base) {
  await page.goto(`${base}/demo/index.html`);
  await page.locator("#authGate.hidden").waitFor({state: "attached"});
  await page.locator("#metricEvents").filter({hasText: /\d/}).waitFor();
  await page.waitForTimeout(400);
}

async function go(page, view) {
  await page.click(`.nav-item[data-view=${view}]`);
  await page.locator(`#${view}.view.active`).waitFor();
  await page.waitForTimeout(600);
}

async function openCritical(page) {
  await go(page, "incidents");
  await page.selectOption("#incidentSeverity", "critical");
  await page.waitForTimeout(500);
  await page.locator("#incidentList .link-title").first().click();
  await page.locator("#incidentWorkspace .workspace-title").waitFor();
  await page.waitForTimeout(400);
}

async function screenshots(browser, base) {
  for (const dir of [SCREENS, DOC_SHOTS, PORTFOLIO]) fs.mkdirSync(dir, {recursive: true});
  const page = await browser.newPage({viewport: {width: 1440, height: 900}});
  const shot = async (name, docName) => {
    await page.screenshot({path: path.join(SCREENS, `${name}.png`)});
    if (docName) fs.copyFileSync(path.join(SCREENS, `${name}.png`), path.join(DOC_SHOTS, `${docName}.png`));
  };
  await openDemo(page, base);
  await shot("command-centre", "01-command-centre");
  await openCritical(page);
  await shot("investigation", "02-investigation");
  await page.locator("#incidentWorkspace .response-panel").scrollIntoViewIfNeeded();
  await page.evaluate(() => window.scrollBy(0, -90));
  await page.waitForTimeout(300);
  await shot("response", "03-guardian-response");
  await go(page, "events");
  await shot("ledger", "04-event-ledger");
  await go(page, "agents");
  await shot("agents", "05-agents");
  await go(page, "devices");
  await shot("devices", "06-devices");
  await go(page, "rules");
  await shot("rules", "07-detection-rules");
  await page.close();

  const mobile = await browser.newPage({viewport: {width: 390, height: 844}, deviceScaleFactor: 2});
  await openDemo(mobile, base);
  await mobile.screenshot({path: path.join(SCREENS, "mobile.png")});
  fs.copyFileSync(path.join(SCREENS, "mobile.png"), path.join(DOC_SHOTS, "08-mobile.png"));
  await mobile.close();

  const landing = await browser.newPage({viewport: {width: 1440, height: 900}});
  await landing.goto(`${base}/index.html`);
  await landing.waitForTimeout(500);
  await landing.screenshot({path: path.join(DOC_SHOTS, "00-showcase-site.png")});
  await landing.close();

  for (const [file, width, height] of [["social-preview.png", 1280, 640], ["linkedin-thumbnail.png", 1200, 627]]) {
    const card = await browser.newPage({viewport: {width, height}});
    await card.goto(`${base}/assets/social-card.html`);
    await card.waitForTimeout(300);
    await card.screenshot({path: path.join(PORTFOLIO, file)});
    await card.close();
  }
  fs.copyFileSync(path.join(PORTFOLIO, "social-preview.png"), path.join(SITE, "assets", "social-preview.png"));
}

async function video(browser, base) {
  fs.mkdirSync(MEDIA, {recursive: true});
  const context = await browser.newContext({viewport: {width: 1280, height: 720}, recordVideo: {dir: MEDIA, size: {width: 1280, height: 720}}});
  const page = await context.newPage();
  const pause = ms => page.waitForTimeout(ms);
  await openDemo(page, base);
  await pause(3500);                                     // 0–4 s   command centre, posture, demo ribbon
  await page.mouse.wheel(0, 650); await pause(3000);     // 4–7 s   activity chronicle + watchlist
  await openCritical(page); await pause(4000);           // 7–13 s  critical incident: evidence + reasoning
  await page.mouse.wheel(0, 500); await pause(3000);     // timeline
  await page.locator("#incidentWorkspace .response-panel").scrollIntoViewIfNeeded(); await pause(3500);  // Guardian Response
  await page.fill("#globalSearch", "203.0.113.77"); await pause(2500);   // global search
  await page.keyboard.press("Escape");
  await go(page, "events"); await page.fill("#eventSearch", "203.0.113.77");
  await page.click("#eventFilters button[type=submit]"); await pause(2500);
  await page.locator("#eventRows tr.clickable").first().click(); await pause(3000);  // evidence drawer
  await page.click("#drawer .drawer-head button");
  await go(page, "agents"); await pause(3500);           // agent health + outage cause
  await go(page, "rules"); await pause(3500);            // rule library + ATT&CK
  await go(page, "overview"); await pause(2000);
  const recorded = await page.video().path();
  await context.close();
  const target = path.join(MEDIA, "blackguard-demo.webm");
  fs.renameSync(recorded, target);
  for (const f of fs.readdirSync(MEDIA)) if (f.endsWith(".webm") && f !== "blackguard-demo.webm") fs.unlinkSync(path.join(MEDIA, f));
  return target;
}

(async () => {
  const server = await serve();
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch();
  try {
    await screenshots(browser, base);
    if (!process.argv.includes("--no-video")) console.log("Video:", await video(browser, base));
    console.log("Screenshots:", SCREENS, "and", DOC_SHOTS);
  } finally {
    await browser.close();
    server.close();
  }
})().catch(err => { console.error(err); process.exit(1); });
