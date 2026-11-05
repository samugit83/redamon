# ZAP Ajax Spider lab

End-to-end target for the ZAP Ajax Spider in the resource-enumeration phase
(`recon/helpers/resource_enum/zap_ajax_spider_helpers.py`): what only a browser
can discover, and the limits that keep a browser crawl from running away. IP
mode over MCP on its own bridge, `192.88.95.0/24`; no host port is published.

| Host | Serves | Exercises |
|---|---|---|
| `192.88.95.10` (`spa`) | an app shell whose `app.js` assembles every route at runtime: `/api/v1/session` on load, `/api/v1/items?page=2`, `/api/v1/preferences` and `/api/v1/reports/export?format=csv` behind buttons, `/help` as a navigation | browser-only discovery: no complete path is in the HTML or the JS, so katana and jsluice cannot see these and ZAP must |
| `192.88.95.11` (`catchall`) | every path is a 200 echoing the path; the page links `/docs/getting-started`, `/docs/api` and `/search/%3Cimg%20src%3Dx%3E` | the reflected-payload filter: katana finds the payload link, and with endpoint seeding it must not become a ZAP seed |
| `192.88.95.12` (`spa-b`) | the same app as `.10` | the seed cap: with `zapAjaxSpiderMaxSeeds: 2` the round-robin gives `.10` and `.11` their base URLs, and `.12` is left uncrawled and reported as skipped |

## Run

The stack must run a build with the ZAP Ajax Spider memory and seed-cap
settings (`zapAjaxSpiderMaxSeeds`) and a docker broker whose
`BROKER_TOOL_MEM_BYTES` is at least `3g`.

```bash
docker compose up -d
python3 e2e_zap_ajax.py        # full recon over MCP, then every check below; exit 0 = all pass
./verify_timeout_kill.sh       # the timeout path against real Docker
docker compose down
```

`e2e_zap_ajax.py` creates a new `internal` project on the three hosts with port
scan (80), httpx, katana and the ZAP Ajax Spider (`base_urls_and_endpoints`,
1-minute crawls, cap 2, parallelism 2, **3 browsers requested**). Everything
else is off. The recon log goes to `_out/recon.log`.

| Check | Passes when |
|---|---|
| memory and heap | every `redamon-zap-ajax-*` container ran with `--memory` 3 GiB and `-Xmx1264m` (one browser) |
| no exit 137 | no ZAP container died out of memory |
| no leftover ZAP container | none exists after the run |
| log: seed cap | `Capping seeds at 2 (N dropped, 1 host(s) left uncrawled)` |
| log: payload path dropped | `Skipping N seed URL(s) carrying a reflected payload inside the path` |
| log: browsers reduced | `3 browsers do not fit a 3.00 GiB container beside the JVM; using 1` |
| browser-only routes on .10 | at least three of the five routes above are `Endpoint` nodes of `.10` |
| capped-out .12 | none of those routes is an `Endpoint` of `.12` |

`verify_timeout_kill.sh` runs one seed through the recon image and the broker,
as a scan does, with the per-seed timeout forced to 45 s. The helper must kill
the container by name, and no `redamon-zap-ajax-*` container may remain.

A ZAP container needs about 3 GiB while it crawls; the run starts two at once.
