# AI Surface Recon — Lab Fixture

Three single-purpose AI containers that exercise every lap-1 AI surface recon hook.

## What it tests

| Service | Port | Hook it exercises | Expected graph result |
|---|---|---|---|
| Ollama | `:11434` | `port_scan` AI port catalogue | `Technology(name='ollama', category='ai-runtime')` linked to the Service via `:USES_TECHNOLOGY {detected_by:'naabu-ai-port'}` |
| Open WebUI | `:8080` | `http_probe` title regex (`<title>Open WebUI</title>`) | `BaseURL.is_ai_framework_detected=true` + `Technology(name='open-webui', category='ai-frontend')` linked via `:USES_TECHNOLOGY {detected_by:'httpx-ai-title'}` |
| Chroma | `:8000` | `port_scan` disambiguate guard (must NOT auto-promote) | No `Technology(category='ai-vector-db')` from port_scan alone — deferred to Phase 15 chat-shape probes |

When `Service.ai_runtime_version` is set by `nmap_scan` (if Nmap is enabled and the runtime announces itself in `product`/`version`), an additional row appears on the Ollama Service.

The DNS hint (`Subdomain.ai_service_hint`) is **not** triggered by this lab — it requires DNS records pointing at AI vendor domains (anthropic, openai, replicate, …). Test the DNS path separately by configuring a project whose target domain has SPF/TXT records mentioning one of those vendors.

## Bring the lab up

```bash
cd agentic/labs/ai-surface
docker compose -f docker-compose.override.yml up -d
```

Pull-and-start takes 3–5 minutes (Ollama image ~1GB, Open WebUI ~3GB, Chroma ~200MB). Once healthy:

```bash
docker compose -f docker-compose.override.yml ps
# All three should be "running (healthy)".

curl -s http://127.0.0.1:11434/         # Ollama: "Ollama is running"
curl -sI http://127.0.0.1:8080/ | head  # Open WebUI: 200 OK
curl -s http://127.0.0.1:8000/api/v1/heartbeat | head  # Chroma: {"nanosecond heartbeat":...}
```

(Optional) Pull a tiny model so Ollama exposes itself meaningfully under nmap:

```bash
docker exec ai-lab-ollama ollama pull tinydolphin
```

## Run a scan against the lab

The lab binds all three services to **host loopback (127.0.0.1)** with `network_mode: host`, so the recon container — also running `network_mode: host` — reaches them via `127.0.0.1`. To scan:

1. Create a RedAmon project. **`targetIps`**: `127.0.0.1`. **`ipMode`**: `true`. Enable Naabu + httpx (Nmap is optional but helpful for `ai_runtime_version`).
2. Either disable the **hard guardrail** for loopback or use a public-DNS shim domain that points at `127.0.0.1`. The hard guardrail at [recon_orchestrator/hard_guardrail.py](../../../recon_orchestrator/hard_guardrail.py) is intentionally strict — make sure the lab target is allowed before triggering a full scan.
3. Trigger the scan from the webapp UI, or through the webapp's API while signed in
   (`POST http://localhost:3000/api/recon/<project_id>/start` with your session cookie).
   Do not call the orchestrator (`:8010`) directly: every start there needs the
   `X-Orchestrator-Key` and the scan's job credential, which only the webapp mints, so a
   hand-written start is refused (401 without the key, 403 `job_credential_missing`
   without the credential).

## Verify the graph state

After the scan completes (`completed_at` set), run the verification script:

```bash
python3 agentic/labs/ai-surface/verify_lab_graph_state.py --project-id <project_id> --user-id <user_id>
```

The script connects to the running Neo4j at `bolt://localhost:7687` and runs the three plan queries from [internal/ADVERSARIAL_AI/AI_SURFACE_RECON.md §16.4](../../../internal/ADVERSARIAL_AI/AI_SURFACE_RECON.md):

1. AI Technology rollup (Ollama, Open WebUI; Chroma intentionally absent — disambiguate=True on port 8000).
2. BaseURL with `is_ai_framework_detected = true` (Open WebUI).
3. The catch-all `any(k IN keys(n) WHERE k STARTS WITH 'ai_' OR k STARTS WITH 'is_ai_')`.

## Toggle smoke

After the first scan succeeds:

1. In the webapp project settings, flip `portScanAiPortCatalogEnabled` OFF.
2. Run partial recon (Naabu only) again.
3. Re-run the verification script with `--expect-port-ai-empty`.

Repeat for `domainReconAiTxtHintEnabled` and `httpProbeAiHeaderScanEnabled`. Each toggle's "off" path must produce zero new AI annotations of that type — that's the §11.1 invariant.

## Tear down

```bash
docker compose -f docker-compose.override.yml down -v
```

The `-v` flag also drops the named volumes (Ollama models, Open WebUI data, Chroma index) so the next bring-up starts clean.

## Limits this lap does NOT cover

The lab is intentionally minimal for **lap 1**. Phase 15 (central `ai_surface_recon` module) will add MCP stub, LangServe stub, JS bundle stub, real chat-shape probes, and OpenAPI/`/v1/models` discovery. Until then, port 8000/8080 ambiguity is deliberately preserved — the disambiguate guard test depends on it.
