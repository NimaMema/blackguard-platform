# Licensing, dependencies and decisions that affect commercial use

*This is engineering guidance, not legal advice. Consult a lawyer before forming a company or changing licences.*

## Current state

| Item | Licence | Distributed with BLACKGUARD? |
| --- | --- | --- |
| BLACKGUARD source code | MIT (`LICENSE`) | Yes |
| Python standard library (runtime) | PSF licence | No (part of Python) |
| Shield artwork, UI design, documentation, screenshots | Original work in this repository, covered by the repository licence | Yes |
| Playwright (browser tests) | Apache-2.0 | No: installed in CI only |
| axe-core (accessibility tests) | MPL-2.0 | No: installed in CI only; never bundled into the app or showcase |
| bandit (static analysis in CI) | Apache-2.0 | No |
| GitHub Actions (`actions/checkout`, `setup-python`, `setup-node`, `upload-artifact`) | MIT | No |
| Fonts | None bundled; system font stacks only | — |

The server and Python agent have **no third-party runtime dependencies**. The showcase site loads nothing from external hosts.

## Owner decisions (current)

- **Licence:** MIT for the initial open-source release (decided by the creator, Nima Memarahari).
- **Brand:** "BLACKGUARD" is the intended product and company name; trademark clearance is pending (see below).

## Decisions to flag for the commercial horizon

1. **MIT is permissive and irrevocable for released code.** Anyone, including competitors, may use, modify and sell anything released under MIT, without sharing changes. You can still build a business on top: open-core, hosted service, support or enterprise add-ons under a different licence. Code released under MIT stays MIT, though. **Decided:** MIT for the initial release. Later code (for example enterprise modules) can use a different licence. Options to consider then:
   - **Apache-2.0:** still permissive, and adds an explicit patent grant and patent-retaliation clause. Often preferred by companies.
   - **AGPL-3.0:** copyleft that also covers network use, so hosted competitors must share their changes. Some enterprises avoid it.
   - **Open-core:** an MIT or Apache core plus proprietary enterprise modules in a separate repository.
2. **Contributions.** Once outside contributors send code, relicensing needs their agreement. If future dual-licensing or relicensing is possible, adopt a **CLA** or the **DCO** (`Signed-off-by`) *before* accepting external pull requests. `CONTRIBUTING.md` currently asks for DCO sign-off as a lightweight default.
3. **The name.** A software licence does not protect a brand. "Blackguard" is also an ordinary English word (meaning a scoundrel). Do a trademark search and consider registering the name and logo before investing in the brand. Other projects or companies may already use similar names.
4. **Third-party test tooling** is not distributed, so its licences impose no obligations on BLACKGUARD users. If a future release bundles any third-party code (charting libraries, fonts, a web framework), add it to the table above with its licence and notice requirements.
5. **Threat-intelligence data.** Any future integration with external feeds (IP reputation, MITRE data in bulk) must have its own licence reviewed. MITRE ATT&CK technique IDs and names are referenced under MITRE's terms of use, which permit this with attribution.
