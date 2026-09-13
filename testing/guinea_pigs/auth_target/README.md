# auth_target — Authenticated Session Recording guinea pig

Validates the **AuthProfile + operator recording** feature end to end against real
HTTP behaviour: a real login form, a real `Set-Cookie`, and a post-login surface
that is genuinely unreachable without the session.

```bash
cd testing/guinea_pigs/auth_target && docker compose up -d --build
curl -s http://127.0.0.1:9010/healthz
```

Loopback-published on `127.0.0.1:9010`; on `pentest-net` it answers to several
aliases so the scope rules are testable for real.

The in-container port is **also** 9010, and it must stay that way. Recon tools
run with `--net=host`, so they resolve the aliases to `127.0.0.1` and hit the
published port — but every HTTP tool is routed through the capture proxy, which
sits on `pentest-net` and re-resolves the alias to the container IP. With a
`9010:5000` mapping the two views disagree: the host-side port scan reports the
service up while the proxy dials a closed port, so every crawl request 502s and
the pipeline reports an empty crawl with no error.

## Why the aliases matter

| Alias | In scope? | Proves |
|---|---|---|
| `authpig.test` | yes (apex) | the apex entry of the default scope |
| `app.authpig.test`, `api.authpig.test`, `cdn.authpig.test` | yes | the `*.root` widening — these are **discovered** subdomains, absent from `SUBDOMAIN_LIST`. An apex-only default scope silently left every authenticated scan logged-out |
| `outsider.example-evil.test` | **no** | the session must never be attached cross-origin |

`api.*` and `cdn.*` deliberately issue a **different cookie name** than `app.*`,
so cross-host cookie-name union in `mergeMaterial` is observable rather than
assumed.

## The two surfaces

The point of this target is the asymmetry between them.

**Anonymous** (`PUBLIC-*` markers): `/`, `/public/about`, `/public/pricing`, `/login`.

**Post-login** (`AUTHONLY-*` markers): `/dashboard`, `/account/profile`,
`/account/settings`, `/orders`, `/orders/<id>`, `/admin/users`,
`/admin/audit-log`, `/reports/quarterly`, `/api/v1/me`, `/api/v1/orders`.

Every post-login page 302s to `/login` when anonymous, and they are linked **only
from inside `/dashboard`**, which itself requires the cookie. A crawler without
the session therefore cannot discover them at all — which is exactly what makes
"authenticated crawling finds more" a measurable claim instead of an assertion.

## Endpoint map

| Endpoint | Exercises |
|---|---|
| `GET /login`, `POST /login` | recording flow: hidden CSRF field + `Set-Cookie` |
| `GET /whoami` | echoes which auth headers arrived; also asserts `X-Redamon-Ctx` never leaks to the target |
| `POST /auth/token`, `GET /auth/bearer` | `bearer` mode |
| `GET /auth/basic` | `basic` mode (401 + `WWW-Authenticate`) |
| `GET /auth/apikey` | `apikey` mode (`X-API-Key`) |
| `GET /auth/header` | `header` mode (`X-Auth-Token`) |
| `GET /edge/huge-cookie` | >8192-byte cookie: extractor must DROP, never truncate |
| `GET /edge/evil-cookie` | cookie carrying hakrawler's `;;` join delimiter |
| `GET /edge/multi-cookie` | two `Set-Cookie` headers merged by name |
| `GET /edge/csrf-header` | `X-CSRF-Token` capture into `extraHeaders` |

Credentials are deliberately trivial: `operator` / `hunter2`, CSRF
`csrf-authpig-789`, API key `apikey-authpig-123`, custom token
`xauth-authpig-456`.

## Validation

Recon-side, using RedAmon's own builder (not a reimplementation):

```bash
docker run --rm --network redamon_pentest-net \
  -v "$PWD":/repo -w /repo \
  -e PYTHONPATH=/repo/recon:/repo:/repo/scanners/capture_proxy \
  --entrypoint python redamon-recon:latest \
  testing/guinea_pigs/auth_target/validate_auth_recording.py
```

UI/recording side (real browser, real stack):

```bash
cd testing/e2e && npx playwright test tests/authRecording.spec.ts
```

> ⚠️ Intentionally vulnerable. Local/trusted Docker host only; never expose 9010.
