// Browser end-to-end test: starts the real server, completes first-run setup and exercises every view.
// Run: node tests/e2e/dashboard.e2e.js [screenshot-dir]   (requires the `playwright` npm package + Chromium)
"use strict";
const {chromium} = require("playwright");
const {spawn} = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const SHOTS = process.argv[2] || fs.mkdtempSync(path.join(os.tmpdir(), "bg-shots-"));
const PORT = 18000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
const PASSWORD = "correct horse battery staple";
const {checkA11y} = require("./a11y");

function startServer(dataDir) {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", ["start.py"], {cwd: ROOT, env: {...process.env, BLACKGUARD_DATA_DIR: dataDir, BLACKGUARD_PORT: String(PORT)}});
    let out = "";
    const timer = setTimeout(() => reject(new Error("server did not start:\n" + out)), 20000);
    const onData = chunk => {
      out += chunk;
      const m = out.match(/\n {4}(\S{20,})\n/);
      if (m && out.includes("listening")) { clearTimeout(timer); resolve({proc, code: m[1]}); }
    };
    proc.stdout.on("data", onData);
    proc.stderr.on("data", onData);
    proc.on("exit", c => reject(new Error(`server exited ${c}:\n${out}`)));
  });
}

async function main() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-e2e-"));
  const {proc, code} = await startServer(dataDir);
  const browser = await chromium.launch();
  const problems = [];
  let step = "start";
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  try {
    page.on("console", msg => { if (msg.type() === "error") problems.push(`[${step}] console: ${msg.text()}`); });
    page.on("pageerror", err => problems.push(`[${step}] pageerror: ${err.message}`));
    page.on("response", r => { if (r.status() >= 500) problems.push(`[${step}] HTTP ${r.status()} ${r.url()}`); });

    step = "setup";
    await page.goto(BASE);
    await page.waitForSelector("#setupForm:not([hidden])");
    await checkA11y(page, "setup screen", problems);
    await page.fill("#setupCode", code);
    await page.fill("#setupUser", "owner");
    await page.fill("#setupPass", PASSWORD);
    await page.fill("#setupPass2", PASSWORD);
    await page.click("#setupForm button[type=submit]");
    await page.waitForSelector("#authGate.hidden", {state: "attached"});
    // Locator-based wait (no page.waitForFunction): the dashboard's CSP forbids 'unsafe-eval',
    // which some Playwright/Chromium versions need to evaluate waitForFunction predicates.
    await page.locator("#metricEvents").filter({hasText: /\d/}).waitFor();
    const label = await page.textContent("#modeTag");
    if (label.trim() !== "DEMO DATA") problems.push(`dataset label should be DEMO DATA, got ${label}`);
    if (await page.isHidden("#dataBanner")) problems.push("demo-data banner should be visible");
    step = "onboarding";
    await page.locator("#onboarding").waitFor();
    const doneSteps = await page.locator("#onboardingSteps li.done").count();
    if (doneSteps !== 1) problems.push(`fresh install should have exactly 1 completed onboarding step, got ${doneSteps}`);
    await checkA11y(page, "overview (real server)", problems);
    step = "setup";
    await page.screenshot({path: path.join(SHOTS, "01-command-centre.png"), fullPage: false});

    step = "inject demo";
    await page.click("#injectDemo");
    await page.waitForSelector("#toast.show");

    step = "views";
    for (const view of ["incidents", "events", "devices", "agents", "responses", "rules", "audit", "settings", "overview"]) {
      await page.click(`.nav-item[data-view=${view}]`);
      await page.waitForSelector(`#${view}.view.active`);
      await page.waitForTimeout(350);
      if (await page.locator(`#${view} .error-state`).count()) problems.push(`error state shown on ${view}`);
    }

    step = "incident workspace";
    await page.click(".nav-item[data-view=incidents]");
    await page.waitForSelector("#incidentList .incident-card");
    await page.selectOption("#incidentSeverity", "critical");
    await page.waitForTimeout(500);
    await page.click("#incidentList .incident-card .link-title");
    await page.waitForSelector("#incidentWorkspace .workspace-title");
    await page.fill("#incidentWorkspace textarea", "Checked with household: not a real sign-in (demo).");
    await page.click("text=Save note");
    await page.waitForSelector("text=Checked with household");
    await page.click("#incidentWorkspace .response-option button:has-text('Propose')");
    await page.waitForSelector("#incidentWorkspace .response-row button:has-text('Approve…')");
    await page.click("#incidentWorkspace .response-row button:has-text('Approve…')");
    await page.waitForSelector("#modal[open]");
    await page.check("#modal input[name=ack]");
    await page.click("#modalOk");
    await page.waitForSelector("#incidentWorkspace .response-row .status-approved");
    await page.screenshot({path: path.join(SHOTS, "02-investigation.png"), fullPage: true});

    step = "global search (real API)";
    await page.click("#globalSearch");
    await page.keyboard.type("VPN");
    await page.locator("#searchResults .search-option").first().waitFor();
    await page.keyboard.press("Escape");
    if (await page.isVisible("#searchResults")) problems.push("Escape should close search results");

    step = "event ledger + drawer";
    await page.click(".nav-item[data-view=events]");
    await page.fill("#eventSearch", "VPN");
    await page.click("#eventFilters button[type=submit]");
    await page.waitForSelector("#eventRows tr.clickable");
    await page.click("#eventRows tr.clickable");
    await page.waitForSelector("#drawer:not([hidden]) .kv");
    await page.screenshot({path: path.join(SHOTS, "03-event-drawer.png")});
    await page.click("#drawer .drawer-head button");

    step = "agent enrollment";
    await page.click(".nav-item[data-view=agents]");
    await page.click("#newInvite");
    await page.fill("#modal input[name=name]", "Living-room PC");
    await page.click("#modalOk");
    await page.waitForSelector("#inviteResult .code-display");
    const inviteCode = (await page.textContent("#inviteResult .code-display")).trim();
    if (!/^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/.test(inviteCode)) problems.push(`unexpected invite code ${inviteCode}`);
    await page.screenshot({path: path.join(SHOTS, "04-enrollment.png")});

    step = "rules";
    await page.click(".nav-item[data-view=rules]");
    const firstRule = page.locator("#ruleList .rule-card").first();
    await firstRule.locator("input[type=number]").first().fill("6");
    await firstRule.locator("button:has-text('Save rule')").click();
    await page.waitForSelector("#toast.show:has-text('saved')");

    step = "settings";
    await page.click(".nav-item[data-view=settings]");
    await page.fill("#newUser", "viewer1");
    await page.selectOption("#newRole", "viewer");
    await page.fill("#newPass", "another long passphrase");
    await page.click("#userForm button[type=submit]");
    await page.waitForSelector("#userList :text('viewer1')");
    await page.waitForSelector("#healthList .kv");
    await checkA11y(page, "settings (real server)", problems);
    step = "onboarding dismiss";
    await page.click(".nav-item[data-view=overview]");
    await page.click("#dismissOnboarding");
    await page.reload();
    await page.locator("#metricEvents").filter({hasText: /\d/}).waitFor();
    if (await page.isVisible("#onboarding")) problems.push("dismissed onboarding checklist should stay hidden");
    step = "settings";

    step = "audit";
    await page.click(".nav-item[data-view=audit]");
    await page.waitForSelector("#auditChain.ok");

    step = "mobile";
    await page.setViewportSize({width: 390, height: 844});
    await page.click("#menuToggle");
    await page.click(".nav-item[data-view=overview]");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (overflow > 1) problems.push(`horizontal overflow on mobile: ${overflow}px`);
    await page.screenshot({path: path.join(SHOTS, "05-mobile.png")});

    step = "sign out";
    await page.click("#signOut");
    await page.waitForSelector("#authGate:not(.hidden) #loginForm:not([hidden])");
    await checkA11y(page, "sign-in screen", problems);
    step = "sign in";
    await page.fill("#loginUser", "owner");
    await page.fill("#loginPass", PASSWORD);
    await page.click("#loginForm button[type=submit]");
    await page.waitForSelector("#authGate.hidden", {state: "attached"});
  } catch (err) {
    problems.push(`[${step}] ${err.message.split("\n")[0]}`);
    await page.screenshot({path: path.join(SHOTS, "failure.png"), fullPage: true}).catch(() => {});
  } finally {
    await browser.close();
    proc.kill("SIGINT");
  }
  console.log(`Screenshots: ${SHOTS}`);
  if (problems.length) {
    console.error("E2E FAILED:\n - " + problems.join("\n - "));
    process.exit(1);
  }
  console.log("E2E OK: setup, onboarding, every view, investigation workflow, global search, enrollment, rules, users, audit, mobile layout, sign-out/in, WCAG A/AA (axe) checks.");
}

main().catch(err => { console.error(err); process.exit(1); });
