"use strict";
/* BLACKGUARD dashboard. All data is rendered with textContent (never innerHTML) to prevent XSS. */

const $ = id => document.getElementById(id);
const S = {
  user: null, csrf: "", overview: null, revision: -1, view: "overview", incidentId: null,
  eventCursor: null, auditBefore: null, knownIncidents: null, online: null, eventTypes: {}, loading: {},
};
const VIEW_LABELS = {
  overview: "COMMAND CENTRE", incidents: "INCIDENTS", incident: "INVESTIGATION", events: "EVENT LEDGER",
  devices: "DEVICE INVENTORY", agents: "AGENTS", responses: "GUARDIAN RESPONSE", rules: "DETECTION RULES",
  audit: "AUDIT LOG", settings: "SETTINGS",
};
const EVENT_TYPES = {
  auth_failure: "Authentication failure", auth_success: "Authentication success", account_created: "Account created",
  account_deleted: "Account deleted", account_enabled: "Account enabled", account_disabled: "Account disabled",
  account_locked: "Account locked out", password_reset: "Password reset", group_membership_change: "Group membership change",
  privilege_change: "Privilege change", privilege_use: "Privileged command", policy_change: "Security policy change",
  audit_log_cleared: "Audit log cleared", service_installed: "Service installed", network_block: "Firewall denial",
  network_allow: "Firewall allow", config_change: "Device configuration change", dhcp_lease: "DHCP lease",
  service_error: "Service error", file_access: "File access", collector_notice: "Collector notice",
};
const TRUST_LABELS = {
  verified_agent: "verified agent", legacy_token: "legacy token (unverified)", manual_import: "manual import (unverified)",
  demo: "fictional demo", server: "BLACKGUARD server",
};

/* ------------------------------------------------------------------ DOM helpers */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = String(value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}
const text = (id, value) => { const el = $(id); if (el) el.textContent = String(value ?? "—"); };
const can = perm => !!S.user && S.user.permissions.includes(perm);

let toastTimer;
function toast(message, kind = "") {
  const el = $("toast");
  el.textContent = message;
  el.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), kind === "error" ? 7000 : 4300);
}

function fmtTime(value, withDate = true) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  const opts = withDate ? {month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"} : {hour: "2-digit", minute: "2-digit"};
  return d.toLocaleString("en-GB", {timeZone: "UTC", hour12: false, ...opts}) + " UTC";
}
function ago(value) {
  if (!value) return "never";
  const s = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (!Number.isFinite(s)) return "—";
  if (s < 60) return `${Math.max(0, s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const sevPill = level => h("span", {class: `severity ${level}`, text: String(level || "").toUpperCase()});
const confPill = level => h("span", {class: `pill conf-${level}`, title: "Rule confidence", text: `CONFIDENCE ${String(level).toUpperCase()}`});
function modePill(mode, trust) {
  const label = mode === "demo" ? "DEMO" : mode === "live" ? "LIVE" : "IMPORTED";
  return h("span", {class: `pill mode-${mode}`, title: trust ? `Origin: ${TRUST_LABELS[trust] || trust}` : "", text: label});
}
const statusPill = status => h("span", {class: `pill status-${status}`, text: String(status).replace("_", " ").toUpperCase()});
const empty = message => h("p", {class: "empty", text: message});
function errorBox(message, retry) {
  return h("div", {class: "panel error-state", role: "alert"},
    h("strong", {text: "Could not load this view."}), h("p", {text: message}),
    retry ? h("button", {class: "btn outline-btn small", text: "Retry", onclick: retry}) : null);
}

/* ------------------------------------------------------------------ API */
class ApiError extends Error { constructor(message, status) { super(message); this.status = status; } }

async function api(path, {method = "GET", body} = {}) {
  let response;
  try {
    response = await fetch(path, {
      method, credentials: "same-origin", cache: "no-store",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": S.csrf},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    setOnline(false);
    throw new ApiError("Cannot reach the BLACKGUARD server. Is it running?", 0);
  }
  setOnline(true);
  let data = {};
  const type = response.headers.get("Content-Type") || "";
  if (type.includes("application/json")) data = await response.json().catch(() => ({}));
  if (response.status === 401 && !path.startsWith("/api/v1/auth/login") && !path.startsWith("/api/v1/setup")) {
    showAuth("Your session ended. Please sign in again.");
  }
  if (!response.ok) throw new ApiError(data.error || `Request failed (${response.status})`, response.status);
  return data;
}

async function download(path, fallbackName) {
  const response = await fetch(path, {credentials: "same-origin", cache: "no-store"});
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new ApiError(data.error || "Download failed", response.status);
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const url = URL.createObjectURL(await response.blob());
  const a = h("a", {href: url, download: match ? match[1] : fallbackName});
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function act(button, fn, success) {
  if (button) button.disabled = true;
  try {
    const result = await fn();
    if (success) toast(typeof success === "function" ? success(result) : success);
    await refreshAll(true);
    return result;
  } catch (err) {
    toast(err.message, "error");
    return null;
  } finally {
    if (button) button.disabled = false;
  }
}

function setOnline(ok) {
  if (S.online === ok) return;
  S.online = ok;
  $("statusCard").classList.toggle("offline", !ok);
  text("statusTitle", ok ? "WARDEN ONLINE" : "CONNECTION LOST");
  text("statusSub", ok ? "LOCAL / PRIVATE" : "RETRYING…");
}

/* ------------------------------------------------------------------ modal + drawer */
function modal({title, body = [], okText = "Confirm", danger = false, cancelText = "Cancel"}) {
  const dialog = $("modal");
  text("modalTitle", title);
  $("modalBody").replaceChildren(...body);
  $("modalOk").textContent = okText;
  $("modalOk").className = `btn ${danger ? "danger-btn" : "gold-btn"}`;
  $("modalCancel").textContent = cancelText;
  $("modalCancel").hidden = cancelText === null;
  return new Promise(resolve => {
    const form = $("modalForm");
    const onClose = () => {
      dialog.removeEventListener("close", onClose);
      resolve(dialog.returnValue === "ok" ? new FormData(form) : null);
    };
    dialog.returnValue = "";
    dialog.addEventListener("close", onClose);
    dialog.showModal();
    const first = $("modalBody").querySelector("input,select,textarea");
    (first || $("modalOk")).focus();
  });
}
const field = (label, input, hint) => h("label", {class: "modal-field"}, label, input, hint ? h("small", {text: hint}) : null);

let drawerReturnFocus = null;
function openDrawer(title, nodes) {
  if ($("drawer").hidden) drawerReturnFocus = document.activeElement;
  text("drawerTitle", title);
  $("drawerBody").replaceChildren(...nodes);
  $("drawer").hidden = false;
  document.body.classList.add("drawer-open");
  $("drawer").querySelector("[data-close-drawer].topbar-action").focus();
}
function closeDrawer() {
  $("drawer").hidden = true;
  document.body.classList.remove("drawer-open");
  if (drawerReturnFocus && document.contains(drawerReturnFocus)) drawerReturnFocus.focus();
  drawerReturnFocus = null;
}

/* ------------------------------------------------------------------ auth */
function showAuth(message = "") {
  S.user = null;
  $("authGate").classList.remove("hidden");
  $("authError").textContent = message;
}

async function bootstrap() {
  try {
    const setup = await api("/api/v1/setup/status");
    text("footerVersion", `v${setup.version} · EST. MMXXVI`);
    if (setup.needs_setup) {
      $("loginForm").hidden = true;
      $("setupForm").hidden = false;
      text("authEyebrow", "FIRST-RUN SETUP");
      text("authTitle", "Raise the banner.");
      text("authIntro", "Create the first administrator. The one-time setup code is printed in the terminal (or container log) where the server started.");
      $("authGate").classList.remove("hidden");
      return;
    }
  } catch (err) {
    showAuth(err.message);
    return;
  }
  try {
    const me = await api("/api/v1/auth/me");
    signedIn(me);
  } catch (err) {
    showAuth("");
  }
}

function signedIn(data) {
  S.user = data.user;
  S.csrf = data.csrf;
  $("authGate").classList.add("hidden");
  $("loginPass").value = "";
  text("whoami", `${S.user.display_name.toUpperCase()} · ${S.user.role.toUpperCase()}`);
  for (const el of document.querySelectorAll("[data-perm]")) el.hidden = !can(el.dataset.perm);
  setOnline(true);
  route();
  refreshAll(true);
}

$("loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  $("authError").textContent = "Checking…";
  try {
    signedIn(await api("/api/v1/auth/login", {method: "POST", body: {username: $("loginUser").value.trim(), password: $("loginPass").value}}));
  } catch (err) {
    $("authError").textContent = err.message;
  }
});

$("setupForm").addEventListener("submit", async event => {
  event.preventDefault();
  if ($("setupPass").value !== $("setupPass2").value) { $("authError").textContent = "Passwords do not match."; return; }
  $("authError").textContent = "Creating administrator…";
  try {
    const data = await api("/api/v1/setup", {method: "POST", body: {setup_code: $("setupCode").value.trim(), username: $("setupUser").value.trim(), password: $("setupPass").value}});
    $("setupForm").hidden = true;
    $("loginForm").hidden = false;
    text("authTitle", "Enter the keep.");
    signedIn(data);
    toast("Administrator created. Welcome to BLACKGUARD.");
  } catch (err) {
    $("authError").textContent = err.message;
  }
});

$("signOut").addEventListener("click", async () => {
  try { await api("/api/v1/auth/logout", {method: "POST", body: {}}); } catch (err) { /* already signed out */ }
  S.csrf = "";
  S.knownIncidents = null;
  showAuth("Signed out.");
});

/* ------------------------------------------------------------------ routing */
function route() {
  const [view, id] = (location.hash.replace(/^#\/?/, "") || "overview").split("/");
  navigate(VIEW_LABELS[view] ? view : "overview", id, false);
}
window.addEventListener("hashchange", route);

function navigate(view, id, push = true) {
  if (view === "audit" && !can("view_audit")) view = "overview";
  if (push) {
    const hash = `#/${view}${id ? "/" + id : ""}`;
    if (location.hash !== hash) { location.hash = hash; return; }
  }
  S.view = view;
  S.incidentId = view === "incident" ? Number(id) : null;
  for (const section of document.querySelectorAll(".view")) section.classList.toggle("active", section.id === view);
  for (const button of document.querySelectorAll(".nav-item")) {
    const active = button.dataset.view === view || (view === "incident" && button.dataset.view === "incidents");
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  }
  text("currentViewLabel", VIEW_LABELS[view]);
  $("sidebar").classList.remove("open");
  if (S.user) loadView(view);
  window.scrollTo({top: 0});
}

for (const button of document.querySelectorAll(".nav-item")) button.addEventListener("click", () => { $("sidebar").classList.remove("open"); navigate(button.dataset.view); });
document.addEventListener("click", event => {
  const go = event.target.closest("[data-go]");
  if (go) navigate(go.dataset.go);
  if (event.target.closest("[data-close-drawer]")) closeDrawer();
});
document.addEventListener("keydown", event => { if (event.key === "Escape" && !$("drawer").hidden) closeDrawer(); });
$("menuToggle").addEventListener("click", () => $("sidebar").classList.toggle("open"));

const LOADERS = {
  overview: () => renderOverview(), incidents: loadIncidents, incident: () => loadIncident(S.incidentId),
  events: () => loadEvents(false), devices: loadDevices, agents: loadAgents, responses: loadResponses,
  rules: loadRules, audit: () => loadAudit(false), settings: loadSettings,
};
async function loadView(view) {
  if (S.loading[view]) return;
  S.loading[view] = true;
  try { await LOADERS[view](); }
  finally { S.loading[view] = false; }
}

/* ------------------------------------------------------------------ polling */
async function refreshAll(force = false) {
  if (!S.user) return;
  try {
    const {revision} = await api("/api/v1/revision");
    if (!force && revision === S.revision) return;
    S.revision = revision;
    S.overview = await api("/api/v1/overview");
    renderChrome();
    if (S.view === "overview") renderOverview();
    else if (!["events", "audit"].includes(S.view) || force) loadView(S.view);
    text("updatedLabel", fmtTime(new Date().toISOString(), false));
  } catch (err) {
    if (err.status !== 401) setOnline(false);
  }
}
setInterval(() => { if (S.user && document.visibilityState === "visible") refreshAll(false); }, 4000);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refreshAll(false); });

/* ------------------------------------------------------------------ chrome + overview */
function renderChrome() {
  const o = S.overview;
  if (!o) return;
  const s = o.stats;
  text("navIncidents", s.incidents_active);
  text("navDevices", s.devices);
  const attention = s.agents_pending + s.agents_attention;
  $("navAgents").hidden = !attention;
  text("navAgents", attention);
  $("navResponses").hidden = !s.responses_pending;
  text("navResponses", s.responses_pending);
  text("modeTag", s.dataset_label);
  $("modeTagWrap").className = `mode-tag ${s.live_events || s.imported_events ? "has-live" : ""}`;
  const banner = $("dataBanner");
  if (s.demo_events && !(s.live_events || s.imported_events)) {
    banner.hidden = false;
    banner.replaceChildren(h("strong", {text: "Demo data only. "}),
      "Everything shown is fictional training data. Enroll an agent (Agents → Enroll a device) to monitor real devices.");
  } else if (s.demo_events) {
    banner.hidden = false;
    banner.replaceChildren(h("strong", {text: "Mixed data. "}), `${s.demo_events} fictional demo events are stored alongside real data and are labelled DEMO. Remove them in Settings when ready.`);
  } else banner.hidden = true;
  const warnings = o.warnings || [];
  const healthBanner = $("healthBanner");
  healthBanner.hidden = !warnings.length;
  healthBanner.classList.toggle("critical", warnings.some(w => w.level === "critical"));
  healthBanner.replaceChildren(h("strong", {text: `System health: ${warnings.length} issue${warnings.length === 1 ? "" : "s"}. `}),
    warnings[0] ? warnings[0].message : "", warnings.length > 1 ? " " : "",
    warnings.length ? h("button", {class: "text-link", text: "DETAILS ↗", onclick: () => navigate("settings")}) : null);
  notifyNewIncidents(o.incidents);
}

function notifyNewIncidents(list) {
  const ids = new Set(list.map(i => i.id));
  if (S.knownIncidents) {
    const fresh = list.filter(i => !S.knownIncidents.has(i.id) && i.mode !== "demo");
    if (fresh.length) {
      toast(`${fresh.length} new incident${fresh.length === 1 ? "" : "s"}: ${fresh[0].title}`);
      if ("Notification" in window && Notification.permission === "granted") {
        new Notification("BLACKGUARD — new finding", {body: `${fresh[0].severity.toUpperCase()}: ${fresh[0].title}`, icon: "/shield.svg"});
      }
    }
  }
  S.knownIncidents = new Set([...(S.knownIncidents || []), ...ids]);
}

function renderOverview() {
  const o = S.overview;
  if (!o) return;
  const s = o.stats;
  text("metricEvents", s.total_events.toLocaleString());
  text("metricEventsSub", `${s.live_events} live · ${s.imported_events} imported · ${s.demo_events} demo`);
  text("metricIncidents", s.incidents_active);
  text("metricIncidentsSub", `${s.incidents_live_active} from real data · ${s.incidents_by_status.investigating || 0} investigating`);
  text("metricCritical", `${s.active_by_severity.critical} / ${s.active_by_severity.high}`);
  text("metricAgents", `${s.agents_online}/${s.agents_active}`);
  text("metricAgentsSub", s.agents_pending ? `${s.agents_pending} awaiting approval` : s.agents_attention ? `${s.agents_attention} need attention` : s.agents_active ? "All approved agents reporting" : "No agents enrolled yet");
  renderChart(o.histogram);
  renderOnboarding(o);
  const sev = s.active_by_severity;
  for (const key of ["critical", "high", "medium", "low"]) text(`count${key[0].toUpperCase()}${key.slice(1)}`, sev[key]);
  text("threatPosture", o.posture);
  $("threatRing").className = `threat-ring posture-${o.posture.toLowerCase()}`;
  text("threatSub", {ELEVATED: "Critical findings need review", WATCHFUL: "High-severity findings open", GUARDED: "Medium findings open", STABLE: "No urgent unresolved findings"}[o.posture]);

  const inc = $("incidentPreview");
  inc.replaceChildren(...(o.incidents.length ? o.incidents.map(i => h("button", {class: "preview-row clickable", onclick: () => navigate("incident", i.id)},
    h("div", {}, h("strong", {text: i.title}), h("small", {text: `${i.rule_id} · ${i.affected_hosts.join(", ")} · ${ago(i.last_seen)}`})),
    h("div", {class: "pill-stack"}, sevPill(i.severity), modePill(i.mode)))) : [empty("No active incidents.")]));
  const ev = $("eventPreview");
  ev.replaceChildren(...(o.events.length ? o.events.map(e => h("button", {class: "preview-row clickable", onclick: () => showEvent(e.id)},
    h("div", {}, h("strong", {text: e.message}), h("small", {text: `${e.host} · ${EVENT_TYPES[e.type] || e.type} · ${ago(e.timestamp)}`})),
    modePill(e.mode, e.trust))) : [empty("No events stored yet.")]));
  const ag = $("agentPreview");
  ag.replaceChildren(...(o.agents.length ? o.agents.map(a => h("button", {class: "preview-row clickable", onclick: () => navigate("agents")},
    h("div", {}, h("strong", {text: a.name}), h("small", {text: `${a.hostname || "—"} · last contact ${ago(a.last_contact_at)} · spool ${a.health.spool_depth ?? "—"}`})),
    connPill(a))) : [empty("No agents yet. Enroll a device you own to start real monitoring.")]));
}

function storageGet(key) { try { return localStorage.getItem(key); } catch (err) { return null; } }
function storageSet(key, value) { try { localStorage.setItem(key, value); } catch (err) { /* private mode: not remembered */ } }

function renderOnboarding(o) {
  const panel = $("onboarding");
  const s = o.stats, setup = o.setup || {};
  const steps = [
    {done: true, title: "Create your administrator account", detail: "Done: you are signed in with an individual account."},
    {done: s.agents_active + s.agents_pending > 0, title: "Enroll your first agent", detail: "Agents → Enroll a device creates a one-time code for a computer you own.", go: "agents"},
    {done: s.agents_online > 0, title: "Approve it and watch it come online", detail: "Compare the fingerprint the agent printed, then approve it.", go: "agents"},
    {done: !!setup.backup_verified, title: "Make a verified backup", detail: "Settings → Back up now (a daily backup also runs automatically).", go: "settings"},
    {done: !!setup.tls, optional: true, title: "Enable TLS before connecting other machines", detail: "Optional while everything runs on this computer. See docs/DEPLOYMENT.md.", go: "settings"},
    {done: s.demo_events === 0, title: "Remove the fictional demo data", detail: "Once real events arrive: Settings → Demo data.", go: "settings"},
  ];
  const remaining = steps.filter(step => !step.done && !step.optional).length;
  panel.hidden = !can("manage_system") || remaining === 0 || storageGet("bg-onboarding-hidden") === "1";
  if (panel.hidden) return;
  $("onboardingSteps").replaceChildren(...steps.map(step => h("li", {class: step.done ? "done" : ""},
    h("span", {class: "step-mark", "aria-hidden": "true", text: step.done ? "✓" : step.optional ? "◇" : "○"}),
    h("div", {}, h("strong", {}, step.title, step.optional ? h("span", {class: "pill", text: "OPTIONAL"}) : null,
      h("span", {class: "sr-only", text: step.done ? " (complete)" : " (to do)"})), h("small", {text: step.detail})),
    !step.done && step.go ? h("button", {class: "btn outline-btn small", text: "Open ↗", onclick: () => navigate(step.go)}) : null)));
}
$("dismissOnboarding").addEventListener("click", () => { storageSet("bg-onboarding-hidden", "1"); $("onboarding").hidden = true; });

function connPill(agent) {
  const label = {online: "● ONLINE", offline: "○ OFFLINE", pending: "◌ PENDING", suspended: "⚠ SUSPENDED", revoked: "✕ REVOKED", legacy: "LEGACY"}[agent.connection] || agent.connection;
  return h("span", {class: `state-pill conn-${agent.connection}`, text: label});
}

function renderChart(buckets) {
  const chart = $("activityChart");
  const total = buckets.reduce((sum, b) => sum + b.live + b.imported + b.demo, 0);
  const max = Math.max(1, ...buckets.map(b => b.live + b.imported + b.demo));
  text("chartTotal", total.toLocaleString());
  text("chartMax", max);
  text("chartStart", buckets.length ? fmtTime(buckets[0].hour, false) : "—");
  chart.replaceChildren(...buckets.map(b => {
    const sum = b.live + b.imported + b.demo;
    const bar = h("div", {class: "bar stacked", title: `${fmtTime(b.hour, false)}: ${b.live} live, ${b.imported} imported, ${b.demo} demo`});
    bar.style.height = `${Math.max(1.5, sum / max * 96)}%`;
    for (const kind of ["demo", "imported", "live"]) {
      if (!b[kind]) continue;
      const seg = h("span", {class: `seg ${kind}`});
      seg.style.height = `${b[kind] / sum * 100}%`;
      bar.append(seg);
    }
    return bar;
  }));
  chart.setAttribute("aria-label", `Hourly event volume, ${total} events in 24 hours`);
}

$("runDetection").addEventListener("click", e => act(e.currentTarget, () => api("/api/v1/detect", {method: "POST", body: {}}), r => `Sweep complete: ${r.created} new, ${r.updated} updated incidents.`));
$("runDetection2").addEventListener("click", e => act(e.currentTarget, () => api("/api/v1/detect", {method: "POST", body: {}}), r => `Sweep complete: ${r.created} new, ${r.updated} updated incidents.`));
$("injectDemo").addEventListener("click", e => act(e.currentTarget, () => api("/api/v1/demo/inject", {method: "POST", body: {}}), r => `Fictional attack added (${r.incidents_created} new demo incident${r.incidents_created === 1 ? "" : "s"}).`));
$("downloadReport").addEventListener("click", async e => {
  const choice = await modal({title: "Export investigation report", okText: "Download",
    body: [h("p", {text: "Markdown report of all incidents with evidence timelines and the 500 most recent events. It may contain account names and IP addresses."}),
      field("", h("span", {class: "check"}, h("input", {type: "checkbox", name: "pseudo", value: "1"}), " Pseudonymise hosts, IPs and accounts (for sharing outside your household)"))]});
  if (!choice) return;
  act(e.currentTarget, () => download(`/api/v1/report${choice.get("pseudo") ? "?pseudonymize=1" : ""}`, "BLACKGUARD-report.md"), "Report downloaded. Store it securely.");
});
$("enableNotify").addEventListener("click", async () => {
  if (!("Notification" in window)) { toast("Browser notifications are unavailable here."); return; }
  const permission = await Notification.requestPermission();
  toast(permission === "granted" ? "Browser notifications enabled for new real (non-demo) incidents." : "Notifications were not enabled.");
});

/* ------------------------------------------------------------------ incidents */
function incidentParams() {
  const p = new URLSearchParams();
  for (const [key, id] of [["status", "incidentStatus"], ["severity", "incidentSeverity"], ["mode", "incidentMode"], ["q", "incidentSearch"]]) {
    const v = $(id).value.trim();
    if (v) p.set(key, v);
  }
  return p;
}
async function loadIncidents() {
  const list = $("incidentList");
  try {
    const {incidents} = await api(`/api/v1/incidents?${incidentParams()}`);
    text("incidentResults", `${incidents.length} FINDINGS`);
    list.replaceChildren(...(incidents.length ? incidents.map(incidentCard) : [h("div", {class: "panel"}, empty("No incidents match these filters."))]));
  } catch (err) { list.replaceChildren(errorBox(err.message, loadIncidents)); }
}
function incidentCard(i) {
  return h("article", {class: `incident-card sev-${i.severity}`},
    h("div", {},
      h("div", {class: "incident-title"}, sevPill(i.severity), h("h2", {}, h("button", {class: "link-title", text: i.title, onclick: () => navigate("incident", i.id)}))),
      h("p", {text: i.summary}),
      h("div", {class: "incident-meta"}, h("span", {text: i.rule_id}), h("span", {text: `DEVICES: ${i.affected_hosts.join(", ") || i.host}`}),
        h("span", {text: `SOURCE: ${i.source_ip || "—"}`}), h("span", {text: `EVIDENCE: ${i.event_count}`}), h("span", {text: `LAST: ${fmtTime(i.last_seen)}`}))),
    h("div", {class: "incident-controls"}, statusPill(i.status), confPill(i.confidence), modePill(i.mode),
      h("button", {class: "btn outline-btn small", text: "Investigate ↗", onclick: () => navigate("incident", i.id)})));
}
let incidentTimer;
$("incidentFilters").addEventListener("input", () => { clearTimeout(incidentTimer); incidentTimer = setTimeout(loadIncidents, 250); });
$("incidentFilters").addEventListener("submit", e => { e.preventDefault(); loadIncidents(); });

async function loadIncident(id) {
  const root = $("incidentWorkspace");
  if (!id) { root.replaceChildren(errorBox("No incident selected.")); return; }
  let d;
  try { d = await api(`/api/v1/incidents/${id}`); }
  catch (err) { root.replaceChildren(errorBox(err.message, () => loadIncident(id))); return; }
  const g = d.guidance;
  const statusSelect = h("select", {"aria-label": "Investigation status", disabled: !can("investigate")},
    ...["open", "investigating", "resolved"].map(v => h("option", {value: v, text: v.toUpperCase(), selected: v === d.status})));
  statusSelect.addEventListener("change", async () => {
    const note = statusSelect.value === "resolved" ? await modal({title: "Resolve incident", okText: "Resolve",
      body: [h("p", {text: "Record why this is resolved (e.g. confirmed benign, credential reset). New evidence after resolution opens a new incident."}),
        field("Resolution note", h("textarea", {name: "note", rows: 3, maxlength: 1000, required: true}))]}) : new FormData();
    if (!note) { statusSelect.value = d.status; return; }
    act(statusSelect, () => api(`/api/v1/incidents/${id}/status`, {method: "POST", body: {status: statusSelect.value, note: note.get("note") || ""}}), "Status saved.");
  });
  const exportMd = h("button", {class: "btn outline-btn small", text: "↓ Markdown", hidden: !can("export"), onclick: e => act(e.currentTarget, () => download(`/api/v1/incidents/${id}/report`, `incident-${id}.md`), "Incident report downloaded.")});
  const exportJson = h("button", {class: "btn outline-btn small", text: "↓ JSON", hidden: !can("export"), onclick: e => act(e.currentTarget, () => download(`/api/v1/incidents/${id}/report?format=json`, `incident-${id}.json`), "Incident JSON downloaded.")});
  const exportAnon = h("button", {class: "btn outline-btn small", text: "↓ Pseudonymised", hidden: !can("export"), onclick: e => act(e.currentTarget, () => download(`/api/v1/incidents/${id}/report?pseudonymize=1`, `incident-${id}-anon.md`), "Pseudonymised report downloaded.")});
  const aiEnabled = S.overview?.ai?.enabled;
  const aiButton = h("button", {class: "btn outline-btn small", text: aiEnabled ? "✧ Ask the AI analyst" : "✧ AI analyst (disabled)", disabled: !aiEnabled || !can("ai"),
    title: aiEnabled ? "Sends this incident's evidence to your local Ollama model" : "Set BLACKGUARD_OLLAMA_URL to enable the optional local AI analyst",
    onclick: e => act(e.currentTarget, () => api(`/api/v1/incidents/${id}/ai-summary`, {method: "POST", body: {}}), "AI analysis added to the notes (unverified).")});

  const header = h("div", {class: "panel workspace-head"},
    h("div", {class: "incident-title"}, sevPill(d.severity), confPill(d.confidence), modePill(d.mode), statusPill(d.status)),
    h("h1", {class: "workspace-title", text: d.title}),
    h("p", {class: "lead", text: d.summary}),
    h("div", {class: "incident-meta"}, h("span", {text: `${d.rule_id} · ${d.rule_name}`}), h("span", {text: `FIRST ${fmtTime(d.first_seen)}`}), h("span", {text: `LAST ${fmtTime(d.last_seen)}`}), h("span", {text: `EVIDENCE ${d.event_count}`})),
    h("div", {class: "workspace-actions"}, h("label", {class: "micro gold"}, "STATUS ", statusSelect), exportMd, exportJson, exportAnon, aiButton));

  const facts = h("article", {class: "panel"}, h("div", {class: "micro gold", text: "WHY THIS WAS RAISED"}),
    h("p", {class: "confidence-reason", text: d.confidence_reason}),
    h("dl", {class: "kv"},
      h("dt", {text: "Affected devices"}), h("dd", {}, ...(d.devices.length ? d.devices.map(dev => h("span", {class: "chip", text: dev.inventory ? `${dev.host} (${dev.inventory.identity_confidence})` : `${dev.host} (not in inventory)`})) : ["—"])),
      h("dt", {text: "Source IPs"}), h("dd", {text: d.source_ips.join(", ") || "—"}),
      h("dt", {text: "Accounts"}), h("dd", {text: d.accounts.join(", ") || "—"}),
      h("dt", {text: "MITRE ATT&CK"}), h("dd", {}, ...((d.rule?.mitre || []).map(m => h("a", {class: "chip", href: m.url, target: "_blank", rel: "noopener noreferrer", text: `${m.id} ${m.name}`}))), (d.rule?.mitre || []).length ? null : "—")));

  const steps = h("article", {class: "panel"}, h("div", {class: "micro gold", text: "INVESTIGATION STEPS"}),
    h("ol", {class: "steps"}, ...g.investigation.map(s => h("li", {text: s}))),
    h("div", {class: "micro gold spaced", text: "FALSE-POSITIVE CONSIDERATIONS"}),
    h("ul", {class: "steps"}, ...g.false_positives.map(s => h("li", {text: s}))));

  const response = h("article", {class: "panel response-panel"}, h("div", {class: "micro gold", text: "GUARDIAN RESPONSE · HUMAN-PERFORMED, APPROVAL REQUIRED"}),
    h("p", {class: "hint", text: "Nothing here runs automatically. Propose an action; an administrator approves it after reading its impact; a person performs it and records the outcome."}),
    ...g.recommended.map(r => {
      const existing = d.responses.find(x => x.action_type === r.type && ["proposed", "approved"].includes(x.status));
      return h("div", {class: "response-option"},
        h("div", {}, h("strong", {text: r.title}), r.changes_security ? h("span", {class: "pill warn-pill", text: "CHANGES SECURITY SETTINGS"}) : null,
          h("ol", {}, ...r.steps.map(s => h("li", {text: s}))), h("small", {text: `Impact: ${r.impact}`}), h("small", {text: `Rollback: ${r.rollback}`})),
        existing ? statusPill(existing.status) : h("button", {class: "btn outline-btn small", text: "Propose", hidden: !can("propose_response"),
          onclick: e => act(e.currentTarget, () => api(`/api/v1/incidents/${id}/responses`, {method: "POST", body: {action_type: r.type}}), "Response proposed; awaiting administrator approval.")}));
    }),
    d.responses.length ? h("div", {class: "micro gold spaced", text: "RECORDED ACTIONS"}) : null,
    ...d.responses.map(responseRow));

  const timeline = h("article", {class: "panel"}, h("div", {class: "micro gold", text: `TIMELINE · ${d.timeline.length} ENTRIES`}),
    h("ol", {class: "timeline"}, ...d.timeline.map(t => h("li", {class: `tl-${t.kind}`},
      h("time", {text: fmtTime(t.at)}),
      h("div", {}, t.kind === "event" ? h("button", {class: "link-title", text: t.text, onclick: () => showEvent(t.event_id)}) : h("span", {class: "note-text", text: t.text}),
        h("small", {text: t.kind === "event" ? `${EVENT_TYPES[t.type] || t.type} · ${t.host} · #${t.event_id}${t.mode === "demo" ? " · DEMO" : ""}` : `${t.kind.toUpperCase()} · ${t.author || ""}`}))))));

  const noteBox = h("textarea", {rows: 3, maxlength: 8000, placeholder: "Add an investigation note: what you checked, who you contacted, what you found…", "aria-label": "New note"});
  const notes = h("article", {class: "panel", hidden: !can("investigate")}, h("div", {class: "micro gold", text: "INVESTIGATION NOTES"}), noteBox,
    h("div", {class: "row-actions"}, h("button", {class: "btn gold-btn small", text: "Save note", onclick: e => {
      if (!noteBox.value.trim()) { toast("Write a note first."); return; }
      act(e.currentTarget, () => api(`/api/v1/incidents/${id}/notes`, {method: "POST", body: {body: noteBox.value}}), "Note saved.");
    }})));

  const evidence = h("article", {class: "panel table-panel"}, h("div", {class: "panel-pad micro gold", text: `EVIDENCE · ${d.evidence.length} EVENTS`}),
    h("div", {class: "table-scroll", tabindex: 0, role: "region", "aria-label": "Incident evidence table (scrollable)"}, h("table", {}, h("thead", {}, h("tr", {}, ...["TIME (UTC)", "TYPE", "HOST", "SOURCE IP", "ACCOUNT", "MESSAGE", "ORIGIN"].map(t => h("th", {text: t})))),
      h("tbody", {}, ...d.evidence.map(eventRow)))));

  root.replaceChildren(header, h("div", {class: "content-grid workspace-grid"}, h("div", {class: "stack"}, timeline, evidence), h("div", {class: "stack"}, facts, response, notes, steps)));
}

function responseRow(r) {
  const buttons = [];
  const go = (verb, needNote, ack) => async e => {
    const body = {};
    if (needNote || ack) {
      const form = await modal({title: `${verb[0].toUpperCase()}${verb.slice(1)}: ${r.title}`, okText: verb[0].toUpperCase() + verb.slice(1), danger: verb === "rollback",
        body: [ack ? h("p", {class: "impact", text: `Impact: ${r.impact}`}) : null, ack ? h("p", {text: `Rollback plan: ${r.rollback_plan}`}) : null,
          ack ? field("", h("span", {class: "check"}, h("input", {type: "checkbox", name: "ack", value: "1", required: true}), " I understand the impact and that a person must perform this action.")) : null,
          field(needNote ? "Note (required)" : "Note (optional)", h("textarea", {name: "note", rows: 3, maxlength: 2000, required: !!needNote}))]});
      if (!form) return;
      body.note = form.get("note") || "";
      body.acknowledge_impact = !!form.get("ack");
    }
    act(e.currentTarget, () => api(`/api/v1/responses/${r.id}/${verb}`, {method: "POST", body}), `Action ${verb === "rollback" ? "rolled back" : verb + "d"}.`);
  };
  if (r.status === "proposed" && can("approve_response")) buttons.push(h("button", {class: "btn gold-btn small", text: "Approve…", onclick: go("approve", false, true)}), h("button", {class: "btn outline-btn small", text: "Reject…", onclick: go("reject", true)}));
  if (r.status === "proposed" && can("propose_response")) buttons.push(h("button", {class: "btn outline-btn small", text: "Cancel", onclick: go("cancel")}));
  if (r.status === "approved" && can("approve_response")) buttons.push(h("button", {class: "btn gold-btn small", text: "Record as performed…", onclick: go("complete", true)}));
  if (r.status === "completed" && can("approve_response")) buttons.push(h("button", {class: "btn outline-btn small", text: "Record rollback…", onclick: go("rollback", true)}));
  return h("div", {class: "response-row"},
    h("div", {}, h("strong", {text: `#${r.id} ${r.title}`}), h("small", {text: `Target: ${r.target || "—"} · proposed ${fmtTime(r.proposed_at)}${r.decided_at ? ` · decided ${fmtTime(r.decided_at)}` : ""}`}),
      r.decision_note ? h("small", {text: `Decision: ${r.decision_note}`}) : null, r.result_note ? h("small", {text: `Result: ${r.result_note}`}) : null,
      r.rollback_note ? h("small", {text: `Rollback: ${r.rollback_note}`}) : null),
    h("div", {class: "pill-stack"}, statusPill(r.status), ...buttons));
}

/* ------------------------------------------------------------------ events */
for (const [value, label] of Object.entries(EVENT_TYPES)) $("eventType").append(h("option", {value, text: label}));
const loadingRow = (cols, label = "Loading…") => h("tr", {class: "loading-row"}, h("td", {colspan: cols}, h("span", {class: "spinner", "aria-hidden": "true"}), label));
S.eventItems = [];
S.eventSort = {key: "timestamp", dir: "desc"};
function sortedEvents() {
  const {key, dir} = S.eventSort;
  const factor = dir === "asc" ? 1 : -1;
  return S.eventItems.slice().sort((a, b) => String(a[key] ?? "").localeCompare(String(b[key] ?? ""), undefined, {numeric: true}) * factor || (b.id - a.id));
}
function renderEventRows() {
  const rows = $("eventRows");
  const items = sortedEvents().map(eventRow);
  rows.replaceChildren(...(items.length ? items : [h("tr", {}, h("td", {class: "empty", colspan: 7, text: "No matching events. Widen the time range or clear filters."}))]));
  for (const th of document.querySelectorAll("#eventTable th[aria-sort]")) {
    const key = th.querySelector("button").dataset.sort;
    th.setAttribute("aria-sort", key === S.eventSort.key ? (S.eventSort.dir === "asc" ? "ascending" : "descending") : "none");
  }
}
for (const button of document.querySelectorAll("#eventTable th button")) {
  button.addEventListener("click", () => {
    const key = button.dataset.sort;
    S.eventSort = {key, dir: S.eventSort.key === key && S.eventSort.dir === "desc" ? "asc" : "desc"};
    renderEventRows();
  });
}
$("eventRange").addEventListener("change", () => {
  const custom = $("eventRange").value === "custom";
  for (const el of document.querySelectorAll(".custom-range")) el.hidden = !custom;
  if (!custom) loadEvents(false);
});
function eventRow(e) {
  return h("tr", {class: "clickable", tabindex: 0, onclick: () => showEvent(e.id), onkeydown: ev => { if (ev.key === "Enter") showEvent(e.id); }},
    h("td", {text: fmtTime(e.timestamp)}), h("td", {text: EVENT_TYPES[e.type] || e.type}), h("td", {text: e.host}),
    h("td", {text: e.source_ip || "—"}), h("td", {text: e.actor}), h("td", {text: e.message}), h("td", {}, modePill(e.mode, e.trust)));
}
function toIso(local) { return local ? new Date(local + "Z").toISOString() : ""; }
async function loadEvents(more) {
  const p = new URLSearchParams({limit: "100"});
  for (const [key, id] of [["q", "eventSearch"], ["type", "eventType"], ["mode", "eventMode"], ["host", "eventHost"], ["source_ip", "eventIp"]]) {
    const v = $(id).value.trim();
    if (v) p.set(key, v);
  }
  const range = $("eventRange").value;
  if (range === "custom") {
    if ($("eventSince").value) p.set("since", toIso($("eventSince").value));
    if ($("eventUntil").value) p.set("until", toIso($("eventUntil").value));
  } else if (range) {
    p.set("since", new Date(Date.now() - Number(range) * 60000).toISOString());
  }
  if (more && S.eventCursor) p.set("cursor", S.eventCursor);
  const rows = $("eventRows");
  if (!more) rows.replaceChildren(loadingRow(7, "Loading events…"));
  try {
    const data = await api(`/api/v1/events?${p}`);
    S.eventCursor = data.next_cursor;
    S.eventItems = more ? S.eventItems.concat(data.events) : data.events;
    renderEventRows();
    $("eventMore").hidden = !data.next_cursor;
    text("eventResults", `${S.eventItems.length} SHOWN${data.next_cursor ? " · MORE AVAILABLE" : ""}`);
  } catch (err) {
    rows.replaceChildren(h("tr", {}, h("td", {colspan: 7}, errorBox(err.message, () => loadEvents(false)))));
  }
}
$("eventFilters").addEventListener("submit", e => { e.preventDefault(); loadEvents(false); });
$("eventReset").addEventListener("click", () => {
  $("eventFilters").reset();
  for (const el of document.querySelectorAll(".custom-range")) el.hidden = true;
  loadEvents(false);
});
$("eventMore").addEventListener("click", () => loadEvents(true));
$("eventFileLabel").addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("eventFile").click(); } });
$("eventFile").addEventListener("change", async event => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if (file.size > 250000) { toast("File too large: maximum 250 KB and 500 events per import.", "error"); return; }
  let data;
  try { data = JSON.parse(await file.text()); } catch (err) { toast("That file is not valid JSON.", "error"); return; }
  if (!data || !Array.isArray(data.events)) { toast("Expected a JSON object with an \"events\" array.", "error"); return; }
  act(null, () => api("/api/v1/events/import", {method: "POST", body: {events: data.events}}),
    r => `Imported ${r.ingested} events (${r.duplicates} duplicates skipped, ${r.incidents_created} new incidents).`).then(() => loadEvents(false));
});

async function showEvent(id) {
  try {
    const {event: e, incidents} = await api(`/api/v1/events/${id}`);
    const details = Object.entries(e.details || {});
    openDrawer(`Event #${e.id}`, [
      h("div", {class: "pill-stack"}, modePill(e.mode, e.trust), h("span", {class: "pill", text: TRUST_LABELS[e.trust] || e.trust})),
      h("p", {class: "lead", text: e.message}),
      h("dl", {class: "kv"}, ...[["Type", EVENT_TYPES[e.type] || e.type], ["Event time", fmtTime(e.timestamp)], ["Received", fmtTime(e.received_at)],
        ["Host", e.host], ["Source IP", e.source_ip || "—"], ["Destination", e.dest_ip ? `${e.dest_ip}${e.dest_port !== null ? ":" + e.dest_port : ""}` : "—"],
        ["Account", e.actor], ["Target", e.target || "—"], ["Collector source", e.source], ["Agent", e.agent_id || "—"], ["Unique id", e.uid]]
        .flatMap(([k, v]) => [h("dt", {text: k}), h("dd", {text: v})])),
      details.length ? h("div", {class: "micro gold", text: "PARSED DETAILS"}) : null,
      details.length ? h("dl", {class: "kv"}, ...details.flatMap(([k, v]) => [h("dt", {text: k}), h("dd", {text: String(v)})])) : null,
      h("div", {class: "micro gold", text: "LINKED INCIDENTS"}),
      incidents.length ? h("div", {}, ...incidents.map(i => h("button", {class: "preview-row clickable", onclick: () => { closeDrawer(); navigate("incident", i.id); }},
        h("div", {}, h("strong", {text: i.title}), h("small", {text: `#${i.id} · ${i.status}`})), sevPill(i.severity)))) : empty("Not part of any incident."),
    ]);
  } catch (err) { toast(err.message, "error"); }
}

/* ------------------------------------------------------------------ devices */
async function loadDevices() {
  const list = $("deviceList");
  try {
    const {devices} = await api("/api/v1/devices");
    const filter = $("deviceFilter").value;
    const items = devices.filter(d => !filter || (filter === "unreviewed" && !d.approved) || (filter === "monitored" && d.agent_id) || (filter === "offline" && d.health === "offline"));
    text("deviceResults", `${items.length} OF ${devices.length} DEVICES`);
    list.replaceChildren(...(items.length ? items.map(deviceCard) : [h("div", {class: "panel"}, empty(devices.length ? "No devices match this filter." : "No devices yet. Approved agents add their own device; agents with --inventory-arp or router DHCP syslog report other devices on your network."))]));
  } catch (err) { list.replaceChildren(errorBox(err.message, loadDevices)); }
}
function deviceCard(d) {
  return h("article", {class: `device-card ${d.approved ? "" : "unreviewed"}`},
    h("div", {class: "device-head"}, h("h2", {}, h("button", {class: "link-title", text: d.display_name, onclick: () => showDevice(d.id)})),
      h("span", {class: `state-pill conn-${d.health}`, text: {online: "● ONLINE", offline: "○ AGENT OFFLINE", unmonitored: "UNMONITORED"}[d.health] || String(d.health).toUpperCase()})),
    h("p", {text: `IP ${d.ip_address || "—"} · MAC ${d.mac_address || "—"} · HOST ${d.hostname || "—"}`}),
    h("p", {text: `OS ${d.os || "unknown"} (${d.os_confidence}) · IDENTITY ${d.identity_confidence.replace("_", " ")}`}),
    h("p", {text: `SOURCE ${d.origin.replace("_", " ")} · LAST SEEN ${ago(d.last_seen)}`}),
    d.approved ? null : h("span", {class: "pill warn-pill", text: "NOT YET REVIEWED"}));
}
$("deviceFilter").addEventListener("change", loadDevices);
async function showDevice(id) {
  try {
    const d = await api(`/api/v1/devices/${id}`);
    const name = h("input", {value: d.display_name, maxlength: 80, "aria-label": "Display name"});
    const notes = h("textarea", {rows: 3, maxlength: 2000, "aria-label": "Notes"});
    notes.value = d.notes;
    const known = h("input", {type: "checkbox", checked: !!d.approved});
    const save = h("button", {class: "btn gold-btn small", text: "Save", hidden: !can("manage_agents"), onclick: e => act(e.currentTarget,
      () => api(`/api/v1/devices/${id}`, {method: "POST", body: {display_name: name.value, notes: notes.value, approved: known.checked}}), "Device saved.").then(() => showDevice(id))});
    openDrawer(d.display_name, [
      h("dl", {class: "kv"}, ...[["Hostname", d.hostname || "—"], ["IP address", d.ip_address || "—"], ["MAC address", d.mac_address || "—"],
        ["Operating system", `${d.os || "unknown"} — ${d.os_confidence}`], ["Identity", d.identity_confidence.replace("_", " ")],
        ["Origin", d.origin.replace("_", " ")], ["Agent", d.agent_id || "none"], ["First seen", fmtTime(d.first_seen)], ["Last seen", fmtTime(d.last_seen)]]
        .flatMap(([k, v]) => [h("dt", {text: k}), h("dd", {text: v})])),
      can("manage_agents") ? h("div", {class: "stack-form"}, h("label", {}, "Display name", name), h("label", {}, "Notes", notes),
        h("label", {class: "check"}, known, " Known device (reviewed by me)"), save) : null,
      h("div", {class: "micro gold", text: "ACTIVITY · LAST 30 DAYS"}),
      d.activity.length ? h("ul", {class: "mono-list"}, ...d.activity.map(a => h("li", {text: `${a.day}  ${EVENT_TYPES[a.type] || a.type}: ${a.n}`}))) : empty("No events from this device."),
      h("div", {class: "micro gold", text: "RECENT EVENTS"}),
      d.recent_events.length ? h("div", {}, ...d.recent_events.map(e => h("button", {class: "preview-row clickable", onclick: () => showEvent(e.id)},
        h("div", {}, h("strong", {text: e.message}), h("small", {text: `${fmtTime(e.timestamp)} · ${e.type}`})), modePill(e.mode)))) : empty("None."),
      h("div", {class: "micro gold", text: "OBSERVATION HISTORY (PROVENANCE)"}),
      d.observations.length ? h("ul", {class: "mono-list"}, ...d.observations.map(o => h("li", {text: `${fmtTime(o.observed_at)}  ${o.field}=${o.value}  [${o.confidence} via ${o.source}]`}))) : empty("No observations recorded."),
    ]);
  } catch (err) { toast(err.message, "error"); }
}
$("addDevice").addEventListener("click", async e => {
  const form = await modal({title: "Add a device you own", okText: "Add device", body: [
    h("p", {class: "hint", text: "Manual entries are labelled 'confirmed' because you entered them. This does not install monitoring on the device."}),
    field("Name", h("input", {name: "display_name", required: true, maxlength: 80})), field("Hostname", h("input", {name: "hostname", maxlength: 120})),
    field("IP address", h("input", {name: "ip_address", maxlength: 45})), field("MAC address", h("input", {name: "mac_address", maxlength: 17, placeholder: "aa:bb:cc:dd:ee:ff"})),
    field("Operating system", h("input", {name: "os", maxlength: 80})), field("Notes", h("textarea", {name: "notes", rows: 2, maxlength: 2000}))]});
  if (form) act(e.currentTarget, () => api("/api/v1/devices", {method: "POST", body: Object.fromEntries(form)}), "Device added.");
});

/* ------------------------------------------------------------------ agents */
async function loadAgents() {
  const list = $("agentList");
  try {
    const {agents, invites} = await api("/api/v1/agents");
    list.replaceChildren(...(agents.length ? agents.map(agentCard) : [h("div", {class: "panel guide-panel"},
      h("div", {class: "micro gold", text: "NO AGENTS YET"}), h("h2", {text: "Enroll a computer you control."}),
      h("p", {text: "Choose “Enroll a device” to create a one-time code, run the agent on that computer with the code, then approve it here after checking its fingerprint."}))]));
    if (invites) {
      text("inviteCount", `${invites.filter(i => i.state === "valid").length} VALID`);
      $("inviteList").replaceChildren(...(invites.length ? invites.map(i => h("div", {class: "response-row"},
        h("div", {}, h("strong", {text: i.name}), h("small", {text: `created ${fmtTime(i.created_at)} · expires ${fmtTime(i.expires_at)}${i.agent_id ? " · used by " + i.agent_id : ""}`})),
        h("div", {class: "pill-stack"}, statusPill(i.state), i.state === "valid" ? h("button", {class: "btn outline-btn small", text: "Revoke code",
          onclick: e => act(e.currentTarget, () => api(`/api/v1/agents/invites/${i.id}/revoke`, {method: "POST", body: {}}), "Enrollment code revoked.")}) : null))) : [empty("No enrollment codes created yet.")]));
    }
  } catch (err) { list.replaceChildren(errorBox(err.message, loadAgents)); }
}
function agentCard(a) {
  const hl = a.health || {};
  const sources = hl.sources || [];
  const actions = [];
  if (can("manage_agents")) {
    if (["pending", "suspended"].includes(a.status)) actions.push(h("button", {class: "btn gold-btn small", text: a.status === "pending" ? "Approve…" : "Re-approve identity…", onclick: e => approveAgent(e, a)}));
    if (a.status === "active") {
      actions.push(h("button", {class: "btn outline-btn small", text: a.rotate_requested ? "Rotation pending" : "Rotate credential", disabled: !!a.rotate_requested,
        onclick: e => act(e.currentTarget, () => api(`/api/v1/agents/${a.id}/rotate`, {method: "POST", body: {}}), "Rotation requested; the agent rotates on its next heartbeat.")}));
      actions.push(h("button", {class: "btn outline-btn small", text: "Settings…", onclick: e => agentSettings(e, a)}));
    }
    if (!["revoked"].includes(a.status)) actions.push(h("button", {class: "btn danger-outline small", text: "Revoke…", onclick: e => revokeAgent(e, a)}));
  }
  return h("article", {class: `agent-card status-${a.status} conn-${a.connection}`},
    h("div", {class: "device-head"}, h("div", {}, h("h2", {text: a.name}), h("small", {class: "mono", text: `${a.id} · ${a.hostname || "—"} · ${a.platform || "—"}`})), connPill(a)),
    a.status_reason ? h("p", {class: "warn-text", text: a.status_reason}) : null,
    h("dl", {class: "kv compact"}, ...[
      ["Fingerprint", a.fingerprint_short ? `${a.fingerprint_short}…` : "—"], ["Last contact", `${ago(a.last_contact_at)} from ${a.last_ip || "—"}`],
      ["Agent version", a.agent_version || hl.agent_version || "—"], ["Offline after", `${Math.round(a.offline_after_seconds / 60)} min`],
      ["Buffered (spool)", hl.spool_depth ?? "—"], ["Dropped / rejected", `${hl.dropped_total ?? 0} / ${hl.rejected_total ?? 0}`],
      ["Credential age", a.credential_age_days === null ? "—" : `${a.credential_age_days} days`], ["Last agent error", hl.last_error || "none"],
      ["Device boot time", hl.boot_time ? fmtTime(hl.boot_time) : "not reported"], ["Agent started", hl.agent_started_at ? fmtTime(hl.agent_started_at) : "—"],
      ["Last clean stop", hl.last_stop ? `${hl.last_stop.reason} · ${fmtTime(hl.last_stop.at)}` : "none recorded"],
      ["Server reachable", hl.server_unreachable_since ? `NO — failing since ${fmtTime(hl.server_unreachable_since)}` : "yes"],
    ].flatMap(([k, v]) => [h("dt", {text: k}), h("dd", {text: String(v)})])),
    sources.length ? h("div", {class: "source-list"}, ...sources.map(s => h("div", {class: `source-row ${s.last_error ? "has-error" : ""}`},
      h("span", {class: "mono", text: s.name}), h("small", {text: `${s.events_total} events · last ${ago(s.last_event_at)}${s.last_error ? " · ⚠ " + s.last_error : ""}`})))) : null,
    actions.length ? h("div", {class: "row-actions"}, ...actions) : null);
}
async function approveAgent(e, a) {
  const form = await modal({title: `Approve ${a.name}`, okText: "Approve agent", body: [
    h("p", {text: "On the agent's computer, the enroll command printed a fingerprint. Approve only if it matches what the server received:"}),
    h("p", {class: "fingerprint", text: (a.reported_fingerprint || "").replace(/(.{4})/g, "$1 ").trim()}),
    h("p", {class: "hint", text: `Reported hostname: ${a.hostname} · platform: ${a.platform} · from ${a.last_ip || "unknown IP"}`}),
    field("Type the first 8+ characters of the fingerprint shown on the agent", h("input", {name: "fp", required: true, minlength: 8, autocomplete: "off", spellcheck: "false"}))]});
  if (form) act(e.currentTarget, () => api(`/api/v1/agents/${a.id}/approve`, {method: "POST", body: {fingerprint_confirmation: form.get("fp")}}), "Agent approved. It can now submit events.");
}
async function revokeAgent(e, a) {
  const form = await modal({title: `Revoke ${a.name}?`, okText: "Revoke permanently", danger: true, body: [
    h("p", {text: "The agent's credential stops working immediately and cannot be restored. Its past events are kept. To monitor this machine again, enroll it with a new code."}),
    field("Reason (recorded in the audit log)", h("input", {name: "reason", maxlength: 300}))]});
  if (form) act(e.currentTarget, () => api(`/api/v1/agents/${a.id}/revoke`, {method: "POST", body: {reason: form.get("reason") || ""}}), "Agent revoked.");
}
async function agentSettings(e, a) {
  const form = await modal({title: `${a.name} settings`, okText: "Save", body: [
    field("Display name", h("input", {name: "name", value: a.name, maxlength: 80, required: true})),
    field("Mark offline after (minutes without a heartbeat)", h("input", {name: "offline", type: "number", min: 1, max: 10080, value: Math.round(a.offline_after_seconds / 60), required: true}))]});
  if (form) act(e.currentTarget, () => api(`/api/v1/agents/${a.id}/update`, {method: "POST", body: {name: form.get("name"), offline_after_seconds: Number(form.get("offline")) * 60}}), "Agent settings saved.");
}
$("newInvite").addEventListener("click", async e => {
  const form = await modal({title: "Enroll a device", okText: "Create one-time code", body: [
    h("p", {text: "Creates a single-use code. Only enroll computers you own or are authorised to monitor."}),
    field("Device name", h("input", {name: "name", required: true, maxlength: 80, placeholder: "e.g. Living-room PC"})),
    field("Code valid for (minutes)", h("input", {name: "ttl", type: "number", min: 5, max: 1440, value: 30, required: true}))]});
  if (!form) return;
  const invite = await act(e.currentTarget, () => api("/api/v1/agents/invites", {method: "POST", body: {name: form.get("name"), ttl_minutes: Number(form.get("ttl"))}}));
  if (!invite) return;
  const server = location.origin;
  $("inviteResult").replaceChildren(h("article", {class: "panel guide-panel invite-card"},
    h("div", {class: "micro gold", text: "ONE-TIME ENROLLMENT CODE — SHOWN ONCE"}),
    h("h2", {class: "mono code-display", text: invite.code}),
    h("p", {text: `For “${invite.name}”. Expires ${fmtTime(invite.expires_at)}. On that computer, run:`}),
    h("code", {text: `python3 agents/blackguard_agent.py enroll --server ${server} --code ${invite.code}${server.startsWith("https") ? " --ca-file blackguard.crt" : ""}`}),
    h("p", {text: "Windows (PowerShell, as an administrator):"}),
    h("code", {text: `powershell -NoProfile -ExecutionPolicy Bypass -File .\\agents\\windows\\BlackguardAgent.ps1 -Enroll -Server ${server} -Code ${invite.code}`}),
    h("p", {class: "hint", text: "The agent will appear below as PENDING. Approve it after comparing the fingerprint it prints."}),
    h("button", {class: "btn outline-btn small", text: "Dismiss", onclick: () => $("inviteResult").replaceChildren()})));
});

/* ------------------------------------------------------------------ responses */
async function loadResponses() {
  const list = $("responseList");
  try {
    const status = $("responseFilter").value;
    const {responses} = await api(`/api/v1/responses${status ? "?status=" + status : ""}`);
    text("responseResults", `${responses.length} ACTIONS`);
    list.replaceChildren(...(responses.length ? responses.map(r => h("article", {class: "panel"},
      h("div", {class: "incident-title"}, sevPill(r.incident_severity), h("button", {class: "link-title", text: `Incident #${r.incident_id}: ${r.incident_title}`, onclick: () => navigate("incident", r.incident_id)})),
      responseRow(r), h("small", {class: "hint", text: `Impact: ${r.impact}`}))) : [h("div", {class: "panel"}, empty("No response actions. Propose one from an incident's investigation workspace."))]));
  } catch (err) { list.replaceChildren(errorBox(err.message, loadResponses)); }
}
$("responseFilter").addEventListener("change", loadResponses);

/* ------------------------------------------------------------------ rules */
async function loadRules() {
  const list = $("ruleList");
  try {
    const {rules} = await api("/api/v1/rules");
    list.replaceChildren(...rules.map(ruleCard));
  } catch (err) { list.replaceChildren(errorBox(err.message, loadRules)); }
}
function ruleCard(r) {
  const editable = can("manage_rules");
  const enabled = h("input", {type: "checkbox", checked: r.enabled, disabled: !editable, "aria-label": `Enable ${r.id}`});
  const severity = h("select", {disabled: !editable, "aria-label": "Severity"}, ...["low", "medium", "high", "critical"].map(s => h("option", {value: s, text: s.toUpperCase() + (s === r.default_severity ? " (default)" : ""), selected: s === r.severity})));
  const inputs = r.params.map(p => [p, h("input", {type: "number", min: p.min, max: p.max, value: p.value, disabled: !editable, "aria-label": p.label})]);
  const save = h("button", {class: "btn outline-btn small", text: "Save rule", hidden: !editable, onclick: e => {
    const params = Object.fromEntries(inputs.map(([p, input]) => [p.name, Number(input.value)]));
    act(e.currentTarget, () => api(`/api/v1/rules/${r.id}`, {method: "POST", body: {enabled: enabled.checked, severity: severity.value, params}}), `${r.id} saved. Run a sweep to re-evaluate stored events.`);
  }});
  return h("article", {class: `rule-card ${r.enabled ? "" : "disabled"}`},
    h("div", {class: "rule-top"}, h("span", {class: "micro gold", text: r.id}), h("div", {class: "pill-stack"}, sevPill(r.severity), confPill(r.confidence))),
    h("h2", {text: r.name}), h("p", {text: r.description}),
    h("div", {class: "chip-row"}, ...r.mitre.map(m => h("a", {class: "chip", href: m.url, target: "_blank", rel: "noopener noreferrer", text: `${m.id} ${m.name}`}))),
    h("p", {class: "micro", text: `INCIDENTS: ${r.incidents_open} OPEN / ${r.incidents_total} TOTAL · LAST ${r.last_triggered ? fmtTime(r.last_triggered) : "NEVER"}`}),
    h("div", {class: "rule-controls"}, h("label", {class: "check"}, enabled, " Enabled"), h("label", {}, "Severity ", severity),
      ...inputs.map(([p, input]) => h("label", {}, `${p.label} `, input)), save),
    h("details", {}, h("summary", {class: "micro gold", text: "INVESTIGATION & FALSE POSITIVES"}),
      h("ol", {class: "steps"}, ...r.investigation.map(s => h("li", {text: s}))), h("ul", {class: "steps"}, ...r.false_positives.map(s => h("li", {text: `False positive: ${s}`})))));
}

/* ------------------------------------------------------------------ audit */
async function loadAudit(more) {
  const rows = $("auditRows");
  const p = new URLSearchParams({limit: "100"});
  if ($("auditAction").value.trim()) p.set("action", $("auditAction").value.trim());
  if (more && S.auditBefore) p.set("before", S.auditBefore);
  try {
    const {entries, chain} = await api(`/api/v1/audit?${p}`);
    $("auditChain").textContent = chain.valid ? `✓ CHAIN INTACT · ${chain.checked} ENTRIES` : `⚠ CHAIN BROKEN AT #${chain.broken_at}`;
    $("auditChain").className = `subtle-pill ${chain.valid ? "ok" : "bad"}`;
    S.auditBefore = entries.length ? entries[entries.length - 1].id : null;
    const items = entries.map(a => h("tr", {}, h("td", {text: fmtTime(a.ts)}), h("td", {text: `${a.actor_name || a.actor_type} (${a.actor_type})`}), h("td", {text: a.action}),
      h("td", {text: a.target_type ? `${a.target_type} ${a.target_id}` : "—"}), h("td", {}, h("span", {class: `pill outcome-${a.outcome}`, text: a.outcome.toUpperCase()})),
      h("td", {text: a.ip || "—"}), h("td", {class: "mono small", text: JSON.stringify(a.detail)})));
    if (more) rows.append(...items); else rows.replaceChildren(...(items.length ? items : [h("tr", {}, h("td", {colspan: 7, class: "empty", text: "No entries."}))]));
    $("auditMore").hidden = entries.length < 100;
    text("auditResults", `${rows.children.length} SHOWN`);
  } catch (err) { rows.replaceChildren(h("tr", {}, h("td", {colspan: 7}, errorBox(err.message, () => loadAudit(false))))); }
}
$("auditFilters").addEventListener("submit", e => { e.preventDefault(); loadAudit(false); });
$("auditMore").addEventListener("click", () => loadAudit(true));

/* ------------------------------------------------------------------ settings */
async function loadSettings() {
  try {
    const health = await api("/api/v1/system/health");
    const last = health.last_backup, down = health.last_server_downtime;
    const kv = [["Status", health.status === "ok" ? "OK" : "DEGRADED"],
      ...(health.warnings || []).map(w => [w.level === "critical" ? "⚠ Critical" : "Warning", w.message]),
      ["Last backup", last ? `${last.file} · ${fmtTime(last.at)} · ${last.verified ? "verified" : "VERIFICATION FAILED"}` : "none yet"],
      ["Last server downtime", down ? `${fmtTime(down.from)} → ${fmtTime(down.to)} (${down.minutes} min, ${down.clean ? "clean stop" : "unclean stop"})` : "none recorded"],
      ["Disk free", `${(health.disk_free_bytes / 1073741824).toFixed(1)} GB of ${(health.disk_total_bytes / 1073741824).toFixed(1)} GB`],
      ["Version", health.version], ["Schema version", health.schema_version], ["Uptime", `${Math.floor(health.uptime_seconds / 3600)}h ${Math.floor(health.uptime_seconds % 3600 / 60)}m`],
      ["Database size", `${(health.database_bytes / 1048576).toFixed(1)} MB`], ["TLS", health.tls ? "enabled" : "disabled (loopback only)"], ["Listening on", health.bind],
      ["Legacy v0.4 ingest", health.legacy_ingest_enabled ? "ENABLED — unverified data accepted" : "disabled"], ["Raw log storage", health.store_raw ? "enabled" : "disabled"],
      ["Audit chain", health.audit_chain.valid ? `intact (${health.audit_chain.checked} entries)` : `BROKEN at #${health.audit_chain.broken_at}`],
      ["AI analyst", health.ai.enabled ? `enabled (${health.ai.model}, local)` : "disabled (optional)"],
      ...Object.entries(health.jobs || {}).map(([name, j]) => [`Job: ${name}`, j.last_error ? `⚠ ${j.last_error}` : `ok · ${j.runs} runs · ${ago(j.last_run)}`])];
    $("healthList").replaceChildren(h("dl", {class: "kv"}, ...kv.flatMap(([k, v]) => [h("dt", {text: k}), h("dd", {text: String(v)})])));
    if (can("manage_system")) {
      $("retEvents").value = health.retention.events_days;
      $("retAudit").value = health.retention.audit_days;
      $("retBackups").value = health.retention.backups_keep;
      $("backupList").replaceChildren(...(health.backups || []).slice().reverse().map(b => h("li", {text: `${b.name} · ${(b.bytes / 1048576).toFixed(2)} MB`})));
    }
    if (can("manage_users")) {
      const {users} = await api("/api/v1/users");
      $("userList").replaceChildren(...users.map(u => {
        const role = h("select", {"aria-label": `Role for ${u.username}`}, ...["viewer", "analyst", "admin"].map(r => h("option", {value: r, text: r, selected: r === u.role})));
        role.addEventListener("change", () => act(role, () => api(`/api/v1/users/${u.id}`, {method: "POST", body: {role: role.value}}), "Role updated; that user must sign in again."));
        return h("div", {class: "response-row"}, h("div", {}, h("strong", {text: u.display_name}), h("small", {text: `${u.username} · last sign-in ${u.last_login_at ? ago(u.last_login_at) : "never"}`})),
          h("div", {class: "pill-stack"}, u.disabled ? statusPill("disabled") : null, role,
            h("button", {class: "btn outline-btn small", text: u.disabled ? "Enable" : "Disable", disabled: u.id === S.user.id,
              onclick: e => act(e.currentTarget, () => api(`/api/v1/users/${u.id}`, {method: "POST", body: {disabled: !u.disabled}}), "User updated.")}),
            h("button", {class: "btn outline-btn small", text: "Reset password…", onclick: async e => {
              const form = await modal({title: `New password for ${u.username}`, okText: "Set password", body: [field("New password (12+)", h("input", {name: "pw", type: "password", minlength: 12, required: true, autocomplete: "new-password"}))]});
              if (form) act(e.currentTarget, () => api(`/api/v1/users/${u.id}`, {method: "POST", body: {password: form.get("pw")}}), "Password reset; the user's sessions were signed out.");
            }})));
      }));
    }
  } catch (err) { $("healthList").replaceChildren(errorBox(err.message, loadSettings)); }
}
$("passwordForm").addEventListener("submit", async e => {
  e.preventDefault();
  const result = await act(e.submitter, () => api("/api/v1/auth/password", {method: "POST", body: {current_password: $("pwCurrent").value, new_password: $("pwNew").value}}));
  if (result) { $("passwordForm").reset(); showAuth(result.message); }
});
$("userForm").addEventListener("submit", async e => {
  e.preventDefault();
  const ok = await act(e.submitter, () => api("/api/v1/users", {method: "POST", body: {username: $("newUser").value.trim(), role: $("newRole").value, password: $("newPass").value}}), "User created.");
  if (ok) $("userForm").reset();
});
$("retentionForm").addEventListener("submit", e => {
  e.preventDefault();
  act(e.submitter, () => api("/api/v1/system/retention", {method: "POST", body: {events_days: Number($("retEvents").value), audit_days: Number($("retAudit").value), backups_keep: Number($("retBackups").value)}}), "Retention saved; applied hourly.");
});
$("backupNow").addEventListener("click", e => act(e.currentTarget, () => api("/api/v1/system/backup", {method: "POST", body: {}}), r => `Backup written: ${r.file}`).then(loadSettings));
$("purgeDemo").addEventListener("click", async e => {
  const form = await modal({title: "Remove demo data?", okText: "Remove demo data", danger: true, body: [
    h("p", {text: "Deletes every fictional demo event and demo-only incident. Live and imported data are not touched. This cannot be undone (except by restoring a backup)."}),
    field("Type DELETE DEMO DATA to confirm", h("input", {name: "confirm", required: true, autocomplete: "off"}))]});
  if (form) act(e.currentTarget, () => api("/api/v1/demo/purge", {method: "POST", body: {confirm: form.get("confirm")}}), r => `${r.removed} demo events removed.`);
});

/* ------------------------------------------------------------------ global search */
let searchTimer, searchSeq = 0;
const searchInput = $("globalSearch"), searchBox = $("searchResults");
function closeSearch() {
  searchBox.hidden = true;
  searchInput.setAttribute("aria-expanded", "false");
  searchInput.removeAttribute("aria-activedescendant");
}
function searchOption(id, label, detail, onPick, pill) {
  return h("div", {class: "search-option", role: "option", id, tabindex: -1, "aria-selected": "false",
    onclick: () => { closeSearch(); searchInput.value = ""; onPick(); }}, h("div", {}, h("strong", {text: label}), h("small", {text: detail})), pill || null);
}
async function runSearch(query) {
  const seq = ++searchSeq;
  if (query.length < 2) { closeSearch(); return; }
  try {
    const q = encodeURIComponent(query);
    const lower = query.toLowerCase();
    const [incidents, events, devices, agents] = await Promise.all([
      api(`/api/v1/incidents?status=&q=${q}`), api(`/api/v1/events?limit=5&q=${q}`), api("/api/v1/devices"), api("/api/v1/agents")]);
    if (seq !== searchSeq) return;
    const options = [];
    const group = (title, items) => { if (items.length) options.push(h("div", {class: "search-group", role: "presentation", text: title}), ...items); };
    group("INCIDENTS", incidents.incidents.slice(0, 5).map((i, n) => searchOption(`sr-i${n}`, i.title, `${i.rule_id} · ${i.affected_hosts.join(", ")} · ${i.status}`, () => navigate("incident", i.id), sevPill(i.severity))));
    group("EVENTS", events.events.map((e, n) => searchOption(`sr-e${n}`, e.message, `${e.host} · ${fmtTime(e.timestamp)}`, () => showEvent(e.id), modePill(e.mode, e.trust))));
    const match = item => Object.values(item).some(v => typeof v === "string" && v.toLowerCase().includes(lower));
    group("DEVICES", devices.devices.filter(match).slice(0, 4).map((d, n) => searchOption(`sr-d${n}`, d.display_name, `${d.ip_address || "—"} · ${d.identity_confidence.replace("_", " ")}`, () => showDevice(d.id))));
    group("AGENTS", agents.agents.filter(match).slice(0, 4).map((a, n) => searchOption(`sr-a${n}`, a.name, `${a.id} · ${a.connection}`, () => navigate("agents"))));
    options.push(searchOption("sr-all", `Search all events for “${query}”`, "Opens the event ledger with this search", () => {
      navigate("events");
      $("eventSearch").value = query;
      loadEvents(false);
    }));
    searchBox.replaceChildren(...options);
    searchBox.hidden = false;
    searchInput.setAttribute("aria-expanded", "true");
  } catch (err) {
    if (seq !== searchSeq) return;
    searchBox.replaceChildren(h("div", {class: "search-group", role: "presentation", text: `Search failed: ${err.message}`}));
    searchBox.hidden = false;
  }
}
searchInput.addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => runSearch(searchInput.value.trim()), 200); });
searchInput.addEventListener("keydown", event => {
  const options = [...searchBox.querySelectorAll(".search-option")];
  const current = options.findIndex(o => o.getAttribute("aria-selected") === "true");
  if (event.key === "Escape") { closeSearch(); return; }
  if (!options.length || searchBox.hidden) return;
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    const next = (current + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
    options.forEach((o, n) => o.setAttribute("aria-selected", String(n === next)));
    searchInput.setAttribute("aria-activedescendant", options[next].id);
    options[next].scrollIntoView({block: "nearest"});
  } else if (event.key === "Enter") {
    event.preventDefault();
    (options[current] || options[options.length - 1]).click();
  }
});
document.addEventListener("click", event => { if (!event.target.closest(".global-search")) closeSearch(); });
document.addEventListener("keydown", event => {
  const typing = event.target.closest("input, textarea, select, [contenteditable]");
  if (event.key === "/" && !typing && S.user && $("modal").open !== true) { event.preventDefault(); searchInput.focus(); }
});

/* ------------------------------------------------------------------ start */
function clock() { text("clock", `${new Date().toLocaleTimeString("en-GB", {timeZone: "UTC", hour: "2-digit", minute: "2-digit"})} UTC`); }
clock();
setInterval(clock, 30000);
bootstrap();
