# BLACKGUARD showcase site

A static, self-contained product page and **zero-install interactive demo**. No backend, no external
resources, no tracking; strict Content-Security-Policy (`connect-src 'none'`).

| Path | What it is |
| --- | --- |
| `index.html` | Landing page: overview, capabilities, screenshots, architecture, security design, honest maturity |
| `demo/` | The real dashboard (`app.js`, `style.css` copied from `blackguard/web/`) + `demo-api.js` (in-browser API) + `demo-data.js` (generated snapshot) |
| `assets/` | Shield, styles, screenshots, social card source and preview image |

All data in the demo is **synthetic**: a fictional household processed by the real BLACKGUARD engine
(`blackguard/scripts/build_showcase.py`). Addresses are RFC 5737 documentation ranges or generic private ranges.

## Preview locally

```bash
python3 -m http.server -d showcase 8080      # then open http://127.0.0.1:8080
```

## Rebuild after dashboard changes

```bash
cd blackguard
python3 scripts/build_showcase.py            # refresh demo snapshot + copies of the dashboard
node scripts/capture_showcase.js             # screenshots, social images, walkthrough video (Playwright)
node tests/e2e/showcase.e2e.js               # verify (needs playwright + axe-core)
```

## Publishing (requires the owner's approval)

The folder can be served by any static host, e.g. GitHub Pages ("Deploy from a branch", folder `/showcase`)
**after** a public repository exists. GitHub Pages on a private repository requires a paid plan and would still
publish the site publicly. Nothing has been published.
