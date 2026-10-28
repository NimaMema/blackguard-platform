"use strict";
/* BLACKGUARD static demo API.
 *
 * Replaces window.fetch for /api/v1/* so the real dashboard (app.js) runs with no backend.
 * Responses come from demo-data.js: a snapshot of the real server's API after it processed
 * a synthetic household. Investigation actions (status, notes, responses, rule tuning) work
 * in memory and are lost on reload. Actions that need a real server (enrollment, imports,
 * backups, user management) return a clear explanation instead of pretending to succeed.
 */
(function () {
  const snap = window.BLACKGUARD_DEMO;
  if (!snap) return;
  const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/;
  // Shift every timestamp by whole hours so the synthetic day ends "now" and hourly buckets stay aligned.
  const shift = Math.max(0, Math.floor((Date.now() - Date.parse(snap.generated_at)) / 3600000)) * 3600000;
  const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "+00:00");
  function retime(value) {
    if (typeof value === "string") return ISO.test(value) ? iso(Date.parse(value) + shift) : value;
    if (Array.isArray(value)) return value.map(retime);
    if (value && typeof value === "object") {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = retime(v);
      return out;
    }
    return value;
  }
  const R = retime(snap.routes);
  const nowIso = () => iso(Date.now());
  let revision = 1;
  let nextId = 900000;
  const UNAVAILABLE = "Not available in the static demo: this action needs a running BLACKGUARD server. Install it locally in a minute (see the README) to try it.";

  const json = (data, status = 200) => new Response(JSON.stringify(data), {status, headers: {"Content-Type": "application/json"}});
  const fail = (status, error) => json({error}, status);
  const file = (text, name, type) => new Response(text, {status: 200, headers: {"Content-Type": type, "Content-Disposition": `attachment; filename="${name}"`}});

  const incidents = () => R["/api/v1/incidents"].incidents;
  const detail = id => R.incident_detail[String(id)];
  const actor = () => R["/api/v1/auth/me"].user;

  function syncIncident(id) {
    const d = detail(id);
    const row = incidents().find(i => i.id === Number(id));
    if (d && row) Object.assign(row, {status: d.status, updated_at: d.updated_at});
    refreshOverview();
  }
  function refreshOverview() {
    const o = R["/api/v1/overview"], all = incidents();
    const active = all.filter(i => i.status !== "resolved");
    const sev = {critical: 0, high: 0, medium: 0, low: 0};
    active.forEach(i => { sev[i.severity] += 1; });
    o.stats.active_by_severity = sev;
    o.stats.incidents_active = active.length;
    o.stats.incidents_by_status = {open: all.filter(i => i.status === "open").length, investigating: all.filter(i => i.status === "investigating").length,
      resolved: all.filter(i => i.status === "resolved").length};
    o.posture = sev.critical ? "ELEVATED" : sev.high ? "WATCHFUL" : sev.medium ? "GUARDED" : "STABLE";
    const order = {critical: 4, high: 3, medium: 2, low: 1};
    o.incidents = active.slice().sort((a, b) => order[b.severity] - order[a.severity] || b.last_seen.localeCompare(a.last_seen)).slice(0, 6);
    o.stats.responses_pending = R["/api/v1/responses"].responses.filter(r => r.status === "proposed").length;
    revision += 1;
  }
  function note(id, body, kind = "note") {
    const d = detail(id);
    const n = {id: nextId++, incident_id: Number(id), author_name: kind === "note" ? actor().username : "BLACKGUARD", kind, body, meta: {}, created_at: nowIso()};
    d.notes.push(n);
    d.timeline.push({at: n.created_at, kind, text: body, author: n.author_name});
    d.updated_at = n.created_at;
  }
  function audit(action, target) {
    R["/api/v1/audit"].entries.unshift({id: nextId++, ts: nowIso(), actor_type: "user", actor_id: String(actor().id), actor_name: actor().username,
      action, target_type: target[0], target_id: String(target[1]), outcome: "success", ip: "demo", detail: {demo: true}});
  }

  function searchEvents(params) {
    let items = R.events.slice();
    const q = (params.get("q") || "").toLowerCase();
    for (const key of ["type", "mode", "host", "source_ip", "agent_id"]) {
      const value = params.get(key);
      if (value) items = items.filter(e => String(e[key]) === value);
    }
    if (params.get("since")) items = items.filter(e => Date.parse(e.timestamp) >= Date.parse(params.get("since")));
    if (params.get("until")) items = items.filter(e => Date.parse(e.timestamp) <= Date.parse(params.get("until")));
    if (q) items = items.filter(e => ["message", "actor", "host", "source_ip", "target", "type"].some(k => String(e[k] || "").toLowerCase().includes(q)));
    items.sort((a, b) => b.timestamp.localeCompare(a.timestamp) || b.id - a.id);
    const offset = Number((params.get("cursor") || "0").replace("offset:", "")) || 0;
    const limit = Math.min(Number(params.get("limit")) || 100, 500);
    const page = items.slice(offset, offset + limit);
    return {events: page, next_cursor: offset + limit < items.length ? `offset:${offset + limit}` : null};
  }

  function filterIncidents(params) {
    let items = incidents().slice();
    const status = params.get("status"), severity = params.get("severity"), mode = params.get("mode"), q = (params.get("q") || "").toLowerCase();
    if (status === "active") items = items.filter(i => i.status !== "resolved");
    else if (status) items = items.filter(i => i.status === status);
    if (severity) items = items.filter(i => i.severity === severity);
    if (mode) items = items.filter(i => i.mode === mode);
    if (q) items = items.filter(i => [i.title, i.summary, i.host, i.source_ip, i.rule_id, i.affected_hosts.join(" ")].some(v => String(v || "").toLowerCase().includes(q)));
    const order = {critical: 4, high: 3, medium: 2, low: 1};
    return items.sort((a, b) => (a.status === "resolved") - (b.status === "resolved") || order[b.severity] - order[a.severity] || b.last_seen.localeCompare(a.last_seen));
  }

  const TRANSITIONS = {approve: ["proposed", "approved"], reject: ["proposed", "rejected"], cancel: ["proposed", "cancelled"],
    complete: ["approved", "completed"], rollback: ["completed", "rolled_back"]};

  async function handle(method, url, body) {
    const path = url.pathname, params = url.searchParams;
    let m;
    if (method === "GET") {
      if (path === "/api/v1/revision") return json({revision});
      if (path === "/api/v1/events") return json(searchEvents(params));
      if ((m = path.match(/^\/api\/v1\/events\/(\d+)$/))) {
        const event = R.events.find(e => e.id === Number(m[1]));
        if (!event) return fail(404, "Event not found (the demo includes the 500 most recent synthetic events).");
        const linked = Object.values(R.incident_detail).filter(d => d.evidence.some(e => e.id === event.id))
          .map(d => ({id: d.id, title: d.title, severity: d.severity, status: d.status}));
        return json({event, incidents: linked});
      }
      if (path === "/api/v1/incidents") return json({incidents: filterIncidents(params)});
      if ((m = path.match(/^\/api\/v1\/incidents\/(\d+)\/report$/))) {
        return params.get("format") === "json" ? file(JSON.stringify({incident: detail(m[1])}, null, 2), `BLACKGUARD-demo-incident-${m[1]}.json`, "application/json")
          : file(R.incident_report[m[1]] || "", `BLACKGUARD-demo-incident-${m[1]}.md`, "text/markdown");
      }
      if ((m = path.match(/^\/api\/v1\/incidents\/(\d+)$/))) return detail(m[1]) ? json(detail(m[1])) : fail(404, "Incident not found");
      if (path === "/api/v1/report") return file(R.report, "BLACKGUARD-demo-report.md", "text/markdown");
      if ((m = path.match(/^\/api\/v1\/devices\/(\d+)$/))) return R.device_detail[m[1]] ? json(R.device_detail[m[1]]) : fail(404, "Device not found");
      if (path === "/api/v1/responses") {
        const status = params.get("status");
        const data = R["/api/v1/responses"];
        return json({...data, responses: status ? data.responses.filter(r => r.status === status) : data.responses});
      }
      if (R[path]) return json(R[path]);
      return fail(404, "Not found");
    }
    if (path === "/api/v1/auth/logout") {
      setTimeout(() => location.reload(), 1200);
      return json({ok: true});
    }
    if (path === "/api/v1/detect") return json({created: 0, updated: 0});
    if ((m = path.match(/^\/api\/v1\/incidents\/(\d+)\/status$/))) {
      const d = detail(m[1]);
      if (!d) return fail(404, "Incident not found");
      if (!["open", "investigating", "resolved"].includes(body.status)) return fail(400, "Invalid incident status");
      if (d.status !== body.status) {
        note(m[1], `Status changed from ${d.status} to ${body.status}.${body.note ? " Reason: " + body.note : ""}`, "system");
        d.status = body.status;
        audit("incident.status", ["incident", m[1]]);
        syncIncident(m[1]);
      }
      return json({updated: true});
    }
    if ((m = path.match(/^\/api\/v1\/incidents\/(\d+)\/notes$/))) {
      if (!body.body || !String(body.body).trim()) return fail(400, "Note must be 1–8000 characters");
      note(m[1], String(body.body).slice(0, 8000));
      audit("incident.note", ["incident", m[1]]);
      refreshOverview();
      return json({id: nextId}, 201);
    }
    if ((m = path.match(/^\/api\/v1\/incidents\/(\d+)\/responses$/))) {
      const d = detail(m[1]);
      const spec = (R["/api/v1/responses"].catalog || {})[body.action_type];
      if (!d || !spec) return fail(400, "Unknown response action");
      if (d.responses.some(r => r.action_type === body.action_type && ["proposed", "approved"].includes(r.status))) {
        return fail(400, "This action is already proposed or approved for the incident");
      }
      const action = {id: nextId++, incident_id: d.id, action_type: body.action_type, integration: "manual", title: spec.title, impact: spec.impact,
        rollback_plan: spec.rollback, target: d.host, status: "proposed", proposed_by: actor().id, proposed_at: nowIso(), decision_note: "",
        result_note: "", rollback_note: "", incident_title: d.title, incident_severity: d.severity, steps: spec.steps};
      d.responses.unshift(action);
      R["/api/v1/responses"].responses.unshift(action);
      note(m[1], `Response '${spec.title}' proposed.`, "system");
      audit("response.propose", ["response", action.id]);
      refreshOverview();
      return json({id: action.id}, 201);
    }
    if ((m = path.match(/^\/api\/v1\/responses\/(\d+)\/(approve|reject|complete|rollback|cancel)$/))) {
      const action = R["/api/v1/responses"].responses.find(r => r.id === Number(m[1]));
      if (!action) return fail(404, "Response action not found");
      const [from, to] = TRANSITIONS[m[2]];
      if (action.status !== from) return fail(400, `Cannot ${m[2]} an action that is ${action.status}`);
      if (m[2] === "approve" && !body.acknowledge_impact) return fail(400, "Approval requires acknowledging the stated impact");
      if (["complete", "rollback", "reject"].includes(m[2]) && !String(body.note || "").trim()) return fail(400, "Describe what was done (or why it was rejected) in the note");
      action.status = to;
      const field = {approve: "decision_note", reject: "decision_note", cancel: "decision_note", complete: "result_note", rollback: "rollback_note"}[m[2]];
      action[field] = body.note || "";
      if (["approve", "reject", "cancel"].includes(m[2])) action.decided_at = nowIso();
      const d = detail(action.incident_id);
      const copy = d.responses.find(r => r.id === action.id);
      if (copy && copy !== action) Object.assign(copy, action);
      note(action.incident_id, `Response '${action.title}' ${to.replace("_", " ")}.${body.note ? " Note: " + body.note : ""}`, "system");
      audit(`response.${m[2]}`, ["response", action.id]);
      refreshOverview();
      return json({responses: d.responses});
    }
    if ((m = path.match(/^\/api\/v1\/rules\/([A-Z0-9-]+)$/))) {
      const rule = R["/api/v1/rules"].rules.find(r => r.id === m[1]);
      if (!rule) return fail(404, "Unknown rule");
      if (typeof body.enabled === "boolean") rule.enabled = body.enabled;
      if (body.severity) rule.severity = body.severity;
      for (const p of rule.params) {
        const value = body.params && body.params[p.name];
        if (value === undefined) continue;
        if (!Number.isInteger(value) || value < p.min || value > p.max) return fail(400, `${p.label} must be a whole number from ${p.min} to ${p.max}`);
        p.value = value;
      }
      audit("rule.update", ["rule", rule.id]);
      revision += 1;
      return json({rule});
    }
    if ((m = path.match(/^\/api\/v1\/devices\/(\d+)$/))) {
      const d = R.device_detail[m[1]];
      if (!d) return fail(404, "Device not found");
      if (body.display_name) d.display_name = String(body.display_name).slice(0, 80);
      if (typeof body.notes === "string") d.notes = body.notes.slice(0, 2000);
      if (typeof body.approved === "boolean") d.approved = body.approved ? 1 : 0;
      const row = R["/api/v1/devices"].devices.find(x => x.id === d.id);
      if (row) Object.assign(row, {display_name: d.display_name, notes: d.notes, approved: d.approved});
      revision += 1;
      return json(d);
    }
    if (/\/ai-summary$/.test(path)) return fail(503, "The optional local AI analyst is disabled in this demo (it needs your own Ollama server).");
    return fail(501, UNAVAILABLE);
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init = {}) {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    if (!url.pathname.startsWith("/api/") && !/\/api\/v1\//.test(url.pathname)) return realFetch(input, init);
    const path = url.pathname.slice(url.pathname.indexOf("/api/"));
    const target = new URL(path + url.search, location.origin);
    let body = {};
    try { body = init.body ? JSON.parse(init.body) : {}; } catch (err) { return fail(400, "Malformed JSON"); }
    await new Promise(resolve => setTimeout(resolve, 60 + Math.random() * 90)); // realistic, but quick
    return handle((init.method || "GET").toUpperCase(), target, body);
  };
  // Visitors land on the data, not on the first-run checklist (which belongs to a real installation).
  try { localStorage.setItem("bg-onboarding-hidden", "1"); } catch (err) { /* storage unavailable */ }
  window.BLACKGUARD_DEMO_MODE = true;
})();
