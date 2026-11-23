# Client-Side Desync — Guinea Pig (end-to-end validation target)

A **single-tier** CL.0 target for the client-side desync leg of the RedAmon
`http_request_smuggling` agent skill (class 4). There is **no reverse proxy**: the
BROWSER reuses one keep-alive TCP connection, so a request smuggled in a POST body
poisons the browser's OWN next navigation.

```
   browser ──(one reused keep-alive connection)──▶  server :9100 (5000)
     1. POST /beacon  (body = "GET /admin HTTP/1.1...")   server answers 204 WITHOUT reading body (CL.0)
     2. GET /  (navigation on the SAME connection)        server serves the queued GET /admin -> /admin page
```

## The idea
`POST /beacon` is a fire-and-forget telemetry endpoint that answers **without reading
the request body** (CL.0). When a page `fetch()`-POSTs to it with a raw `GET /admin`
in the body and then navigates to `/` on the reused connection, the server parses the
leftover body as the next request and the navigation receives the `/admin` page. Only a
**browser-legal** vector works here (a `fetch`/form POST) — header-obfuscation desync
tricks do not, because a browser will not emit them.

## Endpoints

| URL | Result |
| --- | --- |
| `GET /` | landing page (no flag) — the normal navigation result |
| `GET /admin` | the flag — what a *poisoned* navigation returns instead of `/` |
| `POST /beacon` | 204, **without reading the body** (CL.0) |
| `GET /attack` | a self-contained attacker page (browser manual repro) |

Flag: `REDAMON_HRS{client_side_desync_browser_conn_reuse}`

## Run / verify

```bash
docker compose up -d --build
# manual: open http://localhost:9100/attack -> it ends up on /admin (the flag)
# automated (needs Playwright + Chromium; run inside your Kali sandbox, found with
# `docker ps --filter label=redamon.sandbox=1`, with cs-guinea-server connected to its
# network: ../README.md#reaching-a-lab-from-a-kali-sandbox):
docker cp tests/verify_clientside.py <kali>:/tmp/ && \
  docker exec <kali> python3 /tmp/verify_clientside.py http://cs-guinea-server:5000
```

The verify drives Chromium with `--disable-http2` (so the reused connection is h1
keep-alive), baselines `/`, `fetch`-POSTs the smuggled `GET /admin` to `/beacon`, then
navigates to `/` and confirms the navigation returns the `/admin` flag.

## Point RedAmon at it

```bash
docker network connect redamon-network cs-guinea-server
```

Create a project with **target = `http://cs-guinea-server:5000`**, enable the **HTTP
Request Smuggling / Desync** skill, ensure the capture proxy is OFF (default), and ask
the agent to prove a client-side desync with `execute_playwright`. The skill's
client-side step is injected only when `execute_playwright` is allowed and capture is
off; it uses the sync Playwright API and the connection-reuse (CDP `connectionId`)
proof, and never `redamon.browser`.

## Files

| File | Role |
| --- | --- |
| `server/app.py` | single-tier CL.0 server (POST /beacon ignores the body); serves the flag at /admin |
| `docker-compose.yml` | server on `:9100` |
| `tests/verify_clientside.py` | Playwright self-check: fetch-POST poison + reused-connection navigation |
