# Guinea Pigs

Deliberately vulnerable, self-contained Docker targets for **end-to-end validation**
of RedAmon recon/scan modules against realistic, real-world behaviour (not mocks).

Each subdirectory is one module's validation harness with its own `docker-compose.yml`
and a README mapping every endpoint to the exact pipeline step it exercises.

| Harness | Validates | Run |
|---|---|---|
| [`web-cache-poisoning/`](web-cache-poisoning/) | `recon/cache_scan` (WCP module): cache oracle, cache-buster isolation, reflected + differential confirmation, framework packs, scoring, negative controls | `cd web-cache-poisoning && docker compose up -d --build` |
| [`supply_chain_target/`](supply_chain_target/) | Supply-Chain recon (L2): both harvest paths (technologies + source-map mining), scoped/nested/hostile package names, version-preferring dedup, `source_files[:100]` cap, offline OSV verdicts (MAL vs CVE), `Package`/`MalPackageFinding` MERGE + `DEPENDS_ON` anchoring | `cd supply_chain_target && docker compose up -d --build` |
| [`proxy_brain_target/`](proxy_brain_target/) | Agent `proxy_brain` / `redamon.*`: IDOR/BOLA, SQLi (boolean/error/UNION), reflected XSS, JWT weak-secret role-forge (flag), race/limit-overrun, open redirect, CORS, command injection — one endpoint per manual technique, on `pentest-net` as `pbtarget:5000` | `cd proxy_brain_target && docker compose up -d --build` |

> `supply_chain_target` binds `192.88.99.10` on its own bridge rather than
> `127.0.0.1`: L2's JS fetch is Python and enforces an SSRF guard that rejects
> every non-routable address. See its README for why that prefix.

> ⚠️ These targets are intentionally vulnerable. Run them only on a local/trusted
> Docker host and never expose their ports to an untrusted network.
