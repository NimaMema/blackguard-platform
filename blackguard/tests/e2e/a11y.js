// Accessibility checks with axe-core (WCAG 2.0/2.1/2.2 A and AA rules).
// axe is injected with page.evaluate (DevTools protocol), so the page's strict CSP stays enforced.
"use strict";
const fs = require("fs");

let source = null;
function axeSource() {
  if (source === null) source = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
  return source;
}

async function checkA11y(page, label, problems, {include = "body", exclude = []} = {}) {
  await page.evaluate(axeSource());
  const result = await page.evaluate(async ({include, exclude}) => {
    const run = await window.axe.run({include: [include], exclude: exclude.map(s => [s])}, {
      runOnly: {type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]},
      resultTypes: ["violations"],
    });
    return run.violations.map(v => ({id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.slice(0, 3).map(n => n.target.join(" "))}));
  }, {include, exclude});
  for (const v of result) {
    if (v.impact === "serious" || v.impact === "critical") problems.push(`[a11y ${label}] ${v.id} (${v.impact}): ${v.help} → ${v.nodes.join(" | ")}`);
  }
  return result;
}

module.exports = {checkA11y};
