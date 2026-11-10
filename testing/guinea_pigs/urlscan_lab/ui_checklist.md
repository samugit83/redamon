# urlscan lab: UI checklist (plan "Final UI", §11 U-02 to U-05, M-03)

Ticked by hand, signed in with `UI_LOGIN_USERNAME` / `UI_LOGIN_PASSWORD` from the
repository `.env` (read by name, never pasted anywhere). Use only the lab projects
(`uslab-<run>-<date>`). "MCP" means `get_recon_settings` read back after the save;
"net" is the save's `PUT /api/projects/<id>` seen in the browser's network panel.
Screenshots go to `generated/ui/` (git-ignored with the rest of `generated/`).

The texts below are the plan's; a difference in the UI is a FAIL of U-02 unless the
plan was changed on purpose. U-02 is automated by
`testing/e2e/tests/urlscanLabSettings.spec.ts` (run it once without a urlscan key and
once in run B's window); its screenshots land in `generated/ui/`.

## URLScan.io Enrichment section (U-02)

| Check | Result | Screenshot |
| --- | --- | --- |
| Description reads "Passive OSINT enrichment using URLScan.io historical scan data. Discovers subdomains, IPs, ASN info, TLS certificates, server technologies and screenshots, and checks the visits it downloads for leaks, exposed files and problem pages - all without touching the target directly." | [ ] | |
| Info box, no urlscan key in Global Settings: "No API key: urlscan returns only the last 30 days of visits, 100 per search, without urlscan's verdicts; RedAmon reads at most 1,000. Add a key in Global Settings to reach older visits, where the rare leaks are." | [ ] | |
| Info box, key set (run B's `lab-key`): "URLScan API key configured. How far back you can see depends on your urlscan plan." | [ ] | |
| URLScan off hides everything under the description (Max Results, searches, every switch) | [ ] | |
| Max Results: hint "Values above 10,000 are capped; without a key RedAmon reads at most 1,000."; a cleared field shows and saves 10,000 (not 50,000); an old project holding 50,000 still saves | [ ] | |
| Max urlscan searches per scan: default 60; bounds 1-1,000 refused outside by the form and by MCP; description as in the plan | [ ] | |
| Outbound Redirects: default **off**; hint "+1 urlscan search per domain"; flip/save/reload; MCP and net agree | [ ] | |
| Leak Detection sub-section: the line "Links containing tokens or passwords are never opened by RedAmon." is information, not a toggle | [ ] | |
| Leaked One-Time Links, Secrets in URLs: default on; flip/save/reload; MCP and net agree | [ ] | |
| Exposed Files: Sensitive Files and Pages, Documents Opened by Direct Link: default on; flip/save/reload | [ ] | |
| Sensitive Files info line with Route Exposure **off**: "Turn on Route Exposure to check whether they are still online."; with Route Exposure **on**: "Route Exposure will check whether they are still online." (the item-3 table's text; the plan's Final UI mockup paraphrases it) | [ ] | |
| Problem Pages: Takeover Pages, Problem Pages from Titles and Certificates: default on; flip/save/reload | [ ] | |
| Takeover Pages info line with Subdomain Takeover **off**: "Subdomain Takeover is off: these hosts get only the DNS and live-page check."; **on**: "These hosts are added to Subdomain Takeover's list." | [ ] | |
| No "(item n)" tag is visible anywhere | [ ] | |
| Console clean (no error or React warning from the section) | [ ] | |

## Origin Discovery section (U-02)

| Check | Result | Screenshot |
| --- | --- | --- |
| Source Groups lists a 4th switch "urlscan history and file fingerprint", default on, with the plan's description | [ ] | |
| URLScan off: the switch is greyed out, " Disabled while URLScan is off." is appended, the saved value is kept (turn URLScan on again: the old value is back) | [ ] | |
| Key line, no key: "No urlscan key: only the last 30 days. Add a key in Global Settings to reach older addresses."; key set: "urlscan key set." | [ ] | |
| httpx off: the section shows "httpx is off: in a full scan no host is known to be behind a CDN, so Origin Discovery finds nothing. Partial recon still works on hosts you enter by hand."; the module itself is not greyed out | [ ] | |

## Security Checks section (U-02)

| Check | Result | Screenshot |
| --- | --- | --- |
| A new group "Page Content" after the existing groups, text "Checks the live page titles, server names and certificates httpx and tlsx already collected. No extra requests." | [ ] | |
| Its 8 switches, default on, with the plan's labels and descriptions: Open Consoles Without Login, Debug Pages, Unfinished Installers, Development Servers, Directory Listings, Defaced Pages, Takeover Error Pages, Test or Default Certificates | [ ] | |
| The section toggle off switches all of them off; each flips/saves/reloads on its own; MCP and net agree | [ ] | |

## Red Zone (U-03, on the A project after run A; T's tab after run T)

U-03 to U-05 are automated by `testing/e2e/tests/urlscanLabRedZone.spec.ts` (`URLSCAN_LAB_RUN=A-p2`, then `URLSCAN_LAB_RUN=T` for the Takeover tab): it reads each tab's route and the page, takes its expected numbers from the project's own graph (MCP `query_graph`), and saves a screenshot per tab in `generated/ui/`.

| Check | Result | Screenshot |
| --- | --- | --- |
| Takeover tab lists `takeover_page_seen` (run T: brokenapp-cname, gone) and `takeover_error_page` with their source | [ ] | |
| Web initial access lists the open console (jupyter) and the installer (install) | [ ] | |
| DNS drift lists `app.uslab.test` -> `192.88.97.98` as history, not as current DNS | [ ] | |
| Secrets tab shows the urlscan Secrets labelled "urlscan history": the Secret cell shows `••••` and the last four characters, the copy button copies the whole value, and the Source URL opens the full link with the value in it. No planted value is visible whole anywhere on the page (compare against `generated/token_hashes.json` by length only, never paste a value) | [ ] | |
| The badges light for the new findings and clear on opening | [ ] | |
| Findings read "seen in a public urlscan scan on DATE", never "vulnerable" | [ ] | |

## Partial recon window (U-04, on the A project after run A)

| Check | Result | Screenshot |
| --- | --- | --- |
| Nuclei: the graph-input count excludes the quarantined endpoints (`/reset`, `/password/reset/{token}`, `/invite/{token}`, `/unsubscribe`, `/api/data`, `/x`, `/auth/magic/{token}`, `/shell.php`) | [ ] | |
| RouteExposure: the same | [ ] | |
| Httpx: the IP count excludes `192.88.97.98` | [ ] | |
| The counts use the tools' own filters: no quarantined endpoint (Nuclei, Route Exposure), only addresses reached through current DNS, an edge with no source (Httpx); the plan asks no new modal text | [ ] | |

## Current-DNS readers (U-05, on the A project after run A)

| Check | Result | Screenshot |
| --- | --- | --- |
| Graph overview, attack surface, kill chain, shared infrastructure: `192.88.97.98` is not counted as a current address | [ ] | |
| The report (if a report narratives model is configured) does not list `.98` as an address of `app.uslab.test` | [ ] | |

## Agent chat (M-03, on the A project)

| Check | Result | Screenshot |
| --- | --- | --- |
| "show the leaked one-time links" returns I2-01's findings (auth password_reset x2, app invite, auth login_link), masked | [ ] | |
| The agent never requests a quarantined URL while answering (hit logs of the lab stay at 0 for the planted paths) | [ ] | |
