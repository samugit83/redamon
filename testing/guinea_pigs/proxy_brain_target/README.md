# proxy_brain guinea pig

A deliberately vulnerable Flask app for **end-to-end validation of the agent's
`proxy_brain` / `redamon.*` capabilities** against realistic behaviour.

> ⚠️ Intentionally insecure. Local/trusted Docker host only. Never expose it.

## Run

```bash
cd testing/guinea_pigs/proxy_brain_target
docker compose up -d --build
```

It joins `redamon_pentest-net`, so the kali-sandbox (agent tools) and the capture
proxy reach it at **`http://pbtarget:5000/`**. It is also on the host at
`http://127.0.0.1:9009/` for manual curling.

## Endpoint → proxy_brain technique map

| Endpoint | Vuln | Manual section |
|---|---|---|
| `GET /api/invoice/<id>` | IDOR/BOLA — any invoice, no owner check | `authz` |
| `GET /api/product?id=1` | SQLi — sqlite string-concat (boolean/error/UNION); `secret_note` is the loot | `sqli`, `intruder` |
| `GET /search?q=` | reflected XSS — `q` echoed unescaped | `injection` |
| `GET /dom#name=` | DOM XSS — client JS writes `location.hash` into `innerHTML`; curl sees inert HTML, only a real browser fires it | `browser` |
| `GET /portal` (+ `/api/portal-data`) | SPA — the secret (`internal-portal-key-7F3A9C`) is injected by client JS after a `fetch`; curl only sees the `Loading…` shell | `browser` |
| `GET /account` (+ `POST /api/update-email`) | JS-minted anti-CSRF token computed in client JS, never in the raw HTML; read it in the browser (`eval`), then hand it to `replay` | `browser`, `flows` |
| `POST /api/login` + `GET /api/admin` | JWT weak secret (`secret123`); `/api/admin` trusts `role` → forge `role:admin` for the **FLAG** | `jwt` |
| `POST /redeem` `{"coupon":"FREESHIP"}` | race — single-use coupon, widened window; >1 grant = win | `race` |
| `GET /go?next=` | open redirect | `injection` |
| `GET /ping?host=` | command injection — in-band shell output (`host=x;id`) | `cmdi` |
| any request with `Origin:` | CORS — reflects Origin + `Access-Control-Allow-Credentials: true` | `cors` |

The JWT flag is `FLAG{pr0xy_brain_jwt_r0le_forge}` — retrievable only by forging an
admin token with the weak secret and calling `/api/admin`.

## Prerequisites for a real proxy_brain run

`proxy_brain` works over **captured** traffic and replays through the **capture
proxy**, so before the prompts:

1. **TrafficMind ON** — Global Settings: `captureProxyEnabled = true`; on the
   project: `captureProxyEnabled = true`; scope `both`.
2. **Relax the egress guard for the lab** — the target sits on a private Docker IP,
   which the guard blocks by default. Set **Global Settings → TrafficMind → Egress
   guard → block private = OFF** (`captureEgressBlockPrivate = false`). The other
   guards stay on; RedAmon's own service IPs remain blocked regardless.
3. **Project target scope** includes `pbtarget:5000` (or `pbtarget`).
4. **Agent phase = exploitation** (active `proxy_brain` sends are exploitation-only).

Each prompt first has the agent probe the target (that traffic is captured), then
drives `proxy_brain` over the corpus.

## The 5 validation prompts

Paste one per agent chat session (target `http://pbtarget:5000`).

**1 — IDOR/BOLA sweep**
> Crawl http://pbtarget:5000 with httpx/curl so its requests are captured, then use
> proxy_brain: read the manual, map the captured endpoints, and run an access-control
> sweep over /api/invoice — replay each invoice id and any you can reach without being
> the owner is an IDOR. Report every customer's data you can read and the exact requests.

**2 — Blind/error SQL injection extraction**
> Probe http://pbtarget:5000/api/product?id=1 so it's captured, then use proxy_brain to
> confirm SQL injection with a grep-extract oracle and extract the hidden `secret_note`
> for every product (UNION or boolean bisection). Show the payloads and the extracted values.

**3 — JWT role forge → capture the flag**
> Log in at http://pbtarget:5000/api/login (capture it), then use proxy_brain: read the
> jwt section of the manual, take the captured token, brute the weak signing secret, forge
> a token with role=admin, replay it against /api/admin, and return the FLAG.

**4 — Reflected XSS confirmation**
> Hit http://pbtarget:5000/search?q=test so it's captured, then use proxy_brain to confirm
> reflected XSS: replay with a unique marker payload and prove it lands unescaped in the
> response body. Record it as a finding with the proving request.

**5 — Race condition (limit overrun)**
> Send one POST to http://pbtarget:5000/redeem with {"coupon":"FREESHIP"} so it's captured,
> then use proxy_brain's concurrent batch to fire ~20 redemptions at once. The coupon is
> single-use — if more than one is granted, that's a race-condition/limit-overrun bug.
> Report how many succeeded.

## Teardown

```bash
docker compose down
```
