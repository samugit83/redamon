# Authenticated Recon Login Flows Implementation Plan

> **Do not execute:** The underlying hosted-recorder design was superseded by
> `../specs/2026-08-24-chrome-recorder-authenticated-recon-design.md`. A new
> implementation plan must be written after that specification is reviewed.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record simple username/password login flows inside RedAmon and replay explicitly selected identities as origin-scoped authenticated sessions for recon tools.

**Architecture:** Project-owned profiles and tool selections live in Postgres, while target credentials follow the repository's existing masked-plaintext convention. The orchestrator launches isolated Playwright/noVNC browser workers for recording and scan preparation; workers write versioned session artifacts to run-private storage. Recon validates each artifact and uses focused adapters to supply browser state, scoped cookies, approved headers, and authenticated URL seeds to compatible tools.

**Tech Stack:** Next.js 16, React 19, TypeScript, Prisma 6/Postgres, Python 3.11, FastAPI orchestrator, Playwright/Chromium, noVNC/websockify, Docker Compose, mitmproxy, Vitest, pytest through RedAmon's Docker gate.

## Global Constraints

- Version one supports simple username/password form login only; MFA, CAPTCHA, magic links, federated SSO, arbitrary recorder JavaScript, and automatic role comparison are out of scope.
- Multiple named profiles are allowed, but a tool uses only profile IDs explicitly selected in that tool's configuration.
- Credentials are masked but not encrypted at rest and this limitation must be stated in the UI and documentation.
- Credential values must never enter project exports, presets, logs, command arguments, environment variables, recon output, Neo4j, or retained TrafficMind data.
- Authentication selected for a tool must never silently fall back to unauthenticated execution.
- Browser workers are target-facing, have no trusted RedAmon network, and use the existing capture proxy and egress guard.
- Cookie and header delivery requires both profile-origin allowlisting and normal cookie domain/path/TLS/expiry matching.
- Never run host `pytest`; use `./redamon.sh test unit` or the repository's per-file Docker mechanism.
- Invoke `redamon-testing` before editing tests, `project-settings-cascade` before adding settings/defaults, `orchestrator-container-spawn` before changing worker spawn security, `traffic-capture` before capture changes, and `recon-tool-integration` before recon execution-group/tool wiring.

---

## File and interface map

New focused units:

- `webapp/src/lib/authProfiles.ts`: shared profile/action/assertion validation, masks, tool-key registry.
- `webapp/src/app/api/projects/[id]/auth-profiles/**`: tenant-scoped profile CRUD and credential mutation.
- `webapp/src/app/api/projects/[id]/auth-tool-selections/route.ts`: tenant-scoped tool/profile mapping.
- `webapp/src/app/api/internal/auth-profiles/[profileId]/resolve/route.ts`: scanner-key-protected runtime resolution.
- `services/auth_browser/`: target-facing recorder/replay worker, Playwright controller, noVNC desktop, and artifact writer.
- `recon/helpers/auth_sessions.py`: artifact schema, URL/cookie matching, cache, and one-refresh coordinator.
- `recon/helpers/auth_adapters.py`: pure adapter functions that return native tool inputs.
- `webapp/src/components/projects/ProjectForm/auth/`: profile manager, recorder modal, and reusable tool multiselect.

Stable cross-task interfaces:

```ts
type AuthToolKey = 'katana' | 'zap_ajax' | 'hakrawler' | 'nuclei' | 'ffuf' | 'arjun' | 'kiterunner'

type AuthReplayAction =
  | { type: 'navigate'; url: string }
  | { type: 'click'; selector: string }
  | { type: 'fill_literal'; selector: string; value: string }
  | { type: 'fill_variable'; selector: string; variable: string }
  | { type: 'select'; selector: string; value: string }
  | { type: 'wait_visible'; selector: string; timeoutMs: number }
  | { type: 'submit'; selector: string }

type AuthSuccessAssertion =
  | { type: 'url'; pattern: string }
  | { type: 'visible'; selector: string }
```

```python
@dataclass(frozen=True)
class AuthSessionArtifact:
    schema_version: int
    user_id: str
    project_id: str
    run_id: str
    profile_id: str
    allowed_origins: tuple[str, ...]
    created_at: str
    expires_at: str
    final_url: str
    success_assertions_passed: bool
    browser_storage_state: dict
    cookie_jar: tuple[dict, ...]
    approved_headers: tuple[dict, ...]
    observed_urls: tuple[str, ...]
    observed_api_requests: tuple[dict, ...]
```

---

### Task 1: Persist profiles, credentials, and per-tool selections

**Files:**
- Modify: `webapp/prisma/schema.prisma`
- Create: `webapp/src/lib/authProfiles.ts`
- Create: `webapp/src/lib/authProfiles.test.ts`
- Create: `webapp/src/app/api/projects/[id]/auth-profiles/route.ts`
- Create: `webapp/src/app/api/projects/[id]/auth-profiles/[profileId]/route.ts`
- Create: `webapp/src/app/api/projects/[id]/auth-profiles/[profileId]/credentials/route.ts`
- Create: `webapp/src/app/api/projects/[id]/auth-profiles/authProfilesRoute.test.ts`
- Create: `webapp/src/app/api/projects/[id]/auth-tool-selections/route.ts`
- Create: `webapp/src/app/api/projects/[id]/auth-tool-selections/route.test.ts`
- Modify: `webapp/src/app/api/projects/[id]/export/route.ts`
- Modify: `webapp/src/app/api/projects/[id]/export/route.test.ts`

**Interfaces:**
- Consumes: authenticated user/project ownership helpers already used by neighboring project subresource routes.
- Produces: `AUTH_TOOL_KEYS`, `validateProfileInput()`, `maskCredentialPresence()`, CRUD JSON, and `{ selections: Record<AuthToolKey, string[]> }`.

- [ ] **Step 1: Write failing validation and API tests**

Cover rejection of arbitrary actions, missing assertions, non-HTTP start URLs, duplicate/non-origin allowlist entries, foreign-project access, masked credential reads, mask-as-unchanged updates, profile deletion cascading to selections, disabled profiles in selections, and export exclusion. Use canaries `login-user-canary` and `login-password-canary` and assert neither appears in serialized responses or exports.

```ts
expect(validateProfileInput({
  name: 'member', startUrl: 'https://app.test/login',
  allowedOrigins: ['https://app.test'],
  actions: [{ type: 'fill_variable', selector: '#password', variable: 'PASSWORD' }],
  assertions: [{ type: 'url', pattern: '/account' }],
})).toMatchObject({ ok: true })
```

- [ ] **Step 2: Run the focused tests and confirm red**

Run in the webapp container:

```bash
cd webapp && npm run test -- src/lib/authProfiles.test.ts src/app/api/projects/[id]/auth-profiles/authProfilesRoute.test.ts src/app/api/projects/[id]/auth-tool-selections/route.test.ts
```

Expected: FAIL because the models, validators, and routes do not exist.

- [ ] **Step 3: Add the Prisma models and pure validators**

Add `AuthProfile`, `AuthProfileCredential`, and `AuthToolSelection`. Use `onDelete: Cascade`, unique `(projectId, name)`, unique `(profileId, variable)`, and unique `(projectId, toolKey)`. Store actions, assertions, allowed origins, and extraction rules as JSON. Keep credentials in the credential relation, never the profile JSON.

```prisma
model AuthProfileCredential {
  id        String      @id @default(cuid())
  profileId String      @map("profile_id")
  profile   AuthProfile @relation(fields: [profileId], references: [id], onDelete: Cascade)
  variable  String
  value     String
  @@unique([profileId, variable])
  @@map("auth_profile_credentials")
}
```

- [ ] **Step 4: Implement tenant-scoped CRUD and selection routes**

Every query must join through `{ id: projectId, userId: session.user.id }`. Profile GET responses return `{ variable, configured: true }`; no route returns `value`. Validate selected profile IDs belong to the same project and are enabled. Update export code with an explicit regression assertion that neither auth relation is serialized.

- [ ] **Step 5: Apply Prisma and run focused tests**

```bash
docker compose exec webapp npx prisma db push
docker compose exec webapp npx prisma generate
cd webapp && npm run test -- src/lib/authProfiles.test.ts src/app/api/projects/[id]/auth-profiles/authProfilesRoute.test.ts src/app/api/projects/[id]/auth-tool-selections/route.test.ts src/app/api/projects/[id]/export/route.test.ts
```

Expected: all named Vitest files PASS.

- [ ] **Step 6: Commit**

```bash
git add webapp/prisma/schema.prisma webapp/src/lib/authProfiles.ts webapp/src/lib/authProfiles.test.ts webapp/src/app/api/projects
git commit -m "feat(auth): add recon login profiles"
```

### Task 2: Add the isolated browser-worker image and replay engine

**Files:**
- Create: `services/auth_browser/AGENTS.md`
- Create: `services/auth_browser/Dockerfile`
- Create: `services/auth_browser/requirements.txt`
- Create: `services/auth_browser/entrypoint.sh`
- Create: `services/auth_browser/worker.py`
- Create: `services/auth_browser/actions.py`
- Create: `services/auth_browser/artifact.py`
- Create: `services/auth_browser/recorder.js`
- Create: `services/auth_browser/tests/test_actions.py`
- Create: `services/auth_browser/tests/test_artifact.py`
- Modify: `docker-compose.yml`
- Modify: `redamon.sh`

**Interfaces:**
- Consumes: a read-only `/run/auth/input.json` containing resolved profile data and credential variables.
- Produces: atomic `/run/auth/events.jsonl`, `/run/auth/status.json`, and schema-version-1 `/run/auth/session.json`; exposes noVNC on worker port `6080` only through orchestrator proxying.

- [ ] **Step 1: Write failing action and artifact tests**

Test the exact action allowlist, bounds (`100` steps, `10` redirects, `30_000` ms per wait, `180_000` ms total), fresh-context assertion failure, credential-variable substitution, allowed-origin enforcement, same-origin observation filtering, cookie attribute preservation, and absence of credential canaries from artifacts/events/status.

```python
def test_password_fill_uses_variable_without_serializing_value():
    step = compile_action({"type": "fill_variable", "selector": "#password", "variable": "PASSWORD"})
    assert step.variable == "PASSWORD"
    assert "login-password-canary" not in repr(step)
```

- [ ] **Step 2: Run through the Docker gate and confirm red**

Add an `auth_browser` test section to `redamon.sh`, then run:

```bash
./redamon.sh test unit
```

Expected: FAIL because the image/unit modules are not implemented.

- [ ] **Step 3: Build the replay engine**

Use Playwright Chromium in a fresh context. Validate input before launch, substitute variables only at `page.fill`, capture request method/URL without request bodies, collect storage state after assertions pass, normalize cookies, and use `os.replace()` for status/artifact writes. Inject `recorder.js` with `context.add_init_script()`; it emits selector/action metadata but never input values.

- [ ] **Step 4: Add the interactive desktop**

Run Chromium under Xvfb, x11vnc, and websockify/noVNC. Bind worker listeners to the container interface but publish no host port. Require a random session token in the noVNC WebSocket path and status polling requests. The worker image joins only the target-facing network when spawned.

- [ ] **Step 5: Verify unit tests and image build**

```bash
docker compose build auth-browser
./redamon.sh test unit
```

Expected: build succeeds and the `auth_browser` section is PASS with no skips.

- [ ] **Step 6: Commit**

```bash
git add services/auth_browser docker-compose.yml redamon.sh
git commit -m "feat(auth): add isolated login replay worker"
```

### Task 3: Add recorder lifecycle APIs to the orchestrator

**Files:**
- Modify: `recon_orchestrator/api.py`
- Modify: `recon_orchestrator/container_manager.py`
- Create: `recon_orchestrator/auth_browser_manager.py`
- Create: `recon_orchestrator/tests/test_auth_browser_manager.py`
- Create: `recon_orchestrator/tests/test_auth_browser_api.py`
- Modify: `docker-compose.yml`

**Interfaces:**
- Consumes: `POST /auth-browser/sessions` with project/profile/mode and internal authorization.
- Produces: start/status/events/stop endpoints and ticketed WebSocket forwarding for noVNC; `prepare_profile(project_id, profile_id, run_id) -> AuthPreparationResult`.

- [ ] **Step 1: Write failing manager/API tests**

Assert user/project/profile identifiers are syntactically bounded, worker names are deterministic and injection-safe, session tickets expire, input files are mode `0600`, work directories are under `/tmp/redamon/auth/<session-id>`, workers join only `pentest-net`, have `cap_drop: ALL`, `no-new-privileges`, PID/memory limits, and are always removed on stop/expiry.

- [ ] **Step 2: Run the isolated orchestrator tests and confirm red**

```bash
./redamon.sh test unit
```

Expected: the two new test files FAIL on missing manager/routes.

- [ ] **Step 3: Implement lifecycle and proxying**

Create one manager responsible for validated paths, ticket issuance, Docker spawn, status/event reads, noVNC byte forwarding, cleanup, and one replay refresh. Obtain profile material from the webapp internal resolve endpoint, write it once to `input.json`, and never place it in Docker environment or command arguments.

- [ ] **Step 4: Wire compose configuration**

Add `AUTH_BROWSER_IMAGE`, memory/PID/timeout settings to the orchestrator `environment:` block, because `.env` alone is inert. Add the image to build/install/update handling without defining a permanently running auth-browser service.

- [ ] **Step 5: Run focused and full orchestrator tests**

```bash
./redamon.sh test unit
```

Expected: all orchestrator unit files PASS.

- [ ] **Step 6: Commit**

```bash
git add recon_orchestrator docker-compose.yml redamon.sh
git commit -m "feat(auth): orchestrate login browser sessions"
```

### Task 4: Build the in-app profile manager and recorder UI

**Files:**
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthProfilesSection.tsx`
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthProfileEditor.tsx`
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthRecorderModal.tsx`
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthProfileSelect.tsx`
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthProfiles.module.css`
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthProfilesSection.test.tsx`
- Create: `webapp/src/components/projects/ProjectForm/auth/AuthRecorderModal.test.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/ProjectForm.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/sections/KatanaSection.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/sections/ZapAjaxSpiderSection.tsx`

**Interfaces:**
- Consumes: Tasks 1 and 3 APIs.
- Produces: project profile CRUD, noVNC iframe session, recorded-step review, assertion editor, credential mutation, and reusable per-tool selector.

- [ ] **Step 1: Write failing component tests**

Test multiple profiles, plaintext-at-rest warning copy, credential masks, required assertion validation, foreign-origin confirmation via `useAlertModal`, recorder start/stop cleanup, server-event rendering without values, disabled profile behavior, and the execution multiplier for multiple selections.

- [ ] **Step 2: Run focused Vitest files and confirm red**

```bash
cd webapp && npm run test -- src/components/projects/ProjectForm/auth/AuthProfilesSection.test.tsx src/components/projects/ProjectForm/auth/AuthRecorderModal.test.tsx
```

Expected: FAIL because the components are absent.

- [ ] **Step 3: Implement profile and recorder components**

Keep API state outside `ProjectFormData`; authentication profiles are relational resources and must not enter presets/project exports. Render noVNC through the orchestrator ticket URL. Poll sanitized events/status, allow inspection of the constrained step list, and save only after at least one assertion exists and verification replay succeeds.

- [ ] **Step 4: Add first tool selectors**

Add `AuthProfileSelect toolKey="katana"` and `toolKey="zap_ajax"` beneath the tools' enable controls. Selection writes through the dedicated route, not generic project updates.

- [ ] **Step 5: Verify UI**

```bash
cd webapp && npm run test -- src/components/projects/ProjectForm/auth/AuthProfilesSection.test.tsx src/components/projects/ProjectForm/auth/AuthRecorderModal.test.tsx
cd webapp && npm run type-check && npm run lint
```

Expected: tests, type-check, and lint PASS.

- [ ] **Step 6: Commit**

```bash
git add webapp/src/components/projects/ProjectForm
git commit -m "feat(auth): add login flow recorder UI"
```

### Task 5: Resolve profiles securely at scan start

**Files:**
- Create: `webapp/src/app/api/internal/auth-profiles/[profileId]/resolve/route.ts`
- Create: `webapp/src/app/api/internal/auth-profiles/[profileId]/resolve/route.test.ts`
- Modify: `webapp/src/lib/startFullScan.ts`
- Modify: `webapp/src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx`
- Modify: `recon_orchestrator/api.py`
- Modify: `recon_orchestrator/container_manager.py`
- Modify: `recon_orchestrator/tests/test_scan_mode_passthrough.py`

**Interfaces:**
- Consumes: `{ projectId, profileId, runId }` plus `X-Internal-Key` or `X-Scanner-Key` and current scan ownership.
- Produces: resolved worker input only for profiles selected by at least one requested tool; recon env receives non-secret `AUTH_PROFILE_SELECTIONS_JSON` and `AUTH_SESSION_DIR` only.

- [ ] **Step 1: Write failing authorization and passthrough tests**

Assert unknown/disabled/unselected/foreign-project profiles return 404, browser inputs include credentials only on the internal response, no secret enters Docker `environment`, partial recon resolves only the selected tool, and full recon deduplicates profiles across tools.

- [ ] **Step 2: Run focused tests and confirm red**

```bash
cd webapp && npm run test -- src/app/api/internal/auth-profiles/[profileId]/resolve/route.test.ts
./redamon.sh test unit
```

Expected: new assertions FAIL.

- [ ] **Step 3: Implement resolution and non-secret scan configuration**

The webapp validates the scanner/internal key and database selection before returning the profile. The orchestrator prepares artifacts before spawning recon. Pass only selections and artifact directory to recon; scrub preparation errors to profile ID plus error code.

- [ ] **Step 4: Verify**

Run the two commands from Step 2. Expected: PASS and credential canaries absent from captured container kwargs.

- [ ] **Step 5: Commit**

```bash
git add webapp/src/app/api/internal/auth-profiles webapp/src/lib/startFullScan.ts webapp/src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx recon_orchestrator
git commit -m "feat(auth): prepare selected profiles for recon"
```

### Task 6: Implement the session contract and Katana vertical slice

**Files:**
- Create: `recon/helpers/auth_sessions.py`
- Create: `recon/helpers/auth_adapters.py`
- Create: `recon/tests/test_auth_sessions.py`
- Create: `recon/tests/test_auth_adapters.py`
- Modify: `recon/helpers/resource_enum/katana_helpers.py`
- Modify: `recon/main_recon_modules/resource_enum.py`
- Modify: `recon/tests/test_katana_dind_paths.py`

**Interfaces:**
- Consumes: schema-version-1 artifacts and `AUTH_PROFILE_SELECTIONS_JSON`.
- Produces: `load_artifact(profile_id, run_id)`, `cookies_for_url(artifact, url)`, `katana_invocation(artifact, seeds)`, and profile-attributed resource-enum results.

- [ ] **Step 1: Write failing contract and adapter tests**

Test schema/tenant/run/expiry/assertion rejection; host-only versus domain cookies; path boundary (`/app` must not match `/apple`); Secure cookies only over HTTPS; allowlist enforcement; forbidden approved headers; same-origin seed dedupe; and command construction with exactly one Cookie header plus existing TrafficMind header.

```python
invocation = katana_invocation(artifact, ["https://app.test/"])
assert invocation.seeds == ("https://app.test/", "https://app.test/account")
assert "Cookie: sid=session-canary" in invocation.headers
```

- [ ] **Step 2: Run recon tests through the Docker gate and confirm red**

```bash
./redamon.sh test unit
```

Expected: new files fail on missing functions.

- [ ] **Step 3: Implement pure session validation and adapters**

Use `urllib.parse`, `ipaddress`, `http.cookiejar` semantics, frozen dataclasses, and explicit forbidden-header sets. Never log artifact contents. Return immutable adapter results.

- [ ] **Step 4: Split Katana execution per selected profile**

Keep the existing no-profile call unchanged. For each selected profile, invoke Katana separately with adapted seeds/headers, merge endpoint data while stamping `auth_profile_id` in source metadata, and report `authenticated_execution_skipped` when preparation failed. Do not fall back to the old call for an explicitly selected profile.

- [ ] **Step 5: Verify recon tests**

```bash
./redamon.sh test unit
```

Expected: recon section PASS, including command assertions.

- [ ] **Step 6: Commit**

```bash
git add recon/helpers/auth_sessions.py recon/helpers/auth_adapters.py recon/helpers/resource_enum/katana_helpers.py recon/main_recon_modules/resource_enum.py recon/tests
git commit -m "feat(recon): crawl with selected auth profiles"
```

### Task 7: Add the browser-consumer vertical slice for ZAP Ajax Spider

**Files:**
- Modify: `recon/helpers/auth_adapters.py`
- Modify: `recon/helpers/resource_enum/zap_ajax_spider_helpers.py`
- Modify: `recon/main_recon_modules/resource_enum.py`
- Modify: `recon/tests/test_zap_ajax_spider.py`
- Modify: `recon/tests/test_auth_adapters.py`

**Interfaces:**
- Consumes: `AuthSessionArtifact.browser_storage_state` and authenticated seeds.
- Produces: `zap_context_bundle(artifact, directory) -> ZapAuthBundle` and profile-attributed ZAP results.

- [ ] **Step 1: Write failing ZAP bundle tests**

Assert exported browser state is written mode `0600`, only the selected profile's cookies/local storage appear, seed URLs remain allowlisted, worker mounts are read-only, and bundle paths are not exposed in recon result JSON.

- [ ] **Step 2: Run focused recon section and confirm red**

```bash
./redamon.sh test unit
```

Expected: new ZAP adapter assertions FAIL.

- [ ] **Step 3: Implement ZAP session import**

Create a temporary ZAP bootstrap script/context that imports cookies and approved headers before Ajax Spider starts. If the current ZAP API cannot import origin local storage, launch its browser with the Playwright-prepared profile directory and document the exact supported subset in the adapter result. Never downgrade to headers while claiming full browser state.

- [ ] **Step 4: Execute ZAP once per profile and verify**

Run `./redamon.sh test unit`. Expected: PASS with distinct profile metadata and cleanup assertions.

- [ ] **Step 5: Commit**

```bash
git add recon/helpers/auth_adapters.py recon/helpers/resource_enum/zap_ajax_spider_helpers.py recon/main_recon_modules/resource_enum.py recon/tests
git commit -m "feat(recon): import auth sessions into ajax discovery"
```

### Task 8: Harden TrafficMind redaction and add profile attribution

**Files:**
- Modify: `scanners/capture_proxy/redamon_ctx.py`
- Modify: `recon/helpers/proxy_routing.py`
- Modify: `scanners/capture_proxy/capture_lib.py`
- Modify: `scanners/capture_proxy/ingest_worker.py`
- Modify: `scanners/capture_proxy/tests/test_redamon_ctx.py`
- Modify: `scanners/capture_proxy/tests/test_capture_lib.py`
- Modify: `scanners/capture_proxy/tests/test_ingest.py`
- Modify: `webapp/prisma/schema.prisma`
- Modify: `webapp/src/app/traffic/page.tsx`
- Modify: `docs/readmes/README.TRAFFIC.md`

**Interfaces:**
- Consumes: signed context claims `phase='auth-bootstrap'` and `auth_profile_id`.
- Produces: persisted non-secret attribution and irreversible structured redaction before spool/body storage.

- [ ] **Step 1: Write failing redaction and attribution tests**

Use canaries in JSON, URL-encoded, multipart, and text login bodies; `Cookie`, `Set-Cookie`, and `Authorization`; offload-sized bodies; rejected records; and recorder event metadata. Assert no canary exists in spool JSON, blob files, database params, or UI API responses while method/path/status and sanitized parameter names remain.

- [ ] **Step 2: Run capture tests and confirm red**

```bash
./redamon.sh test unit
```

Expected: body redaction/profile-claim assertions FAIL.

- [ ] **Step 3: Extend signed context and redact before persistence**

Add `auth_profile_id` to the claim allowlist and database column. Redaction must occur before inline/offload/meta routing, hashing, or spool serialization. For known login requests, preserve field names but replace values with `[REDACTED]`; for unparseable credential-bearing content, store metadata only.

- [ ] **Step 4: Surface attribution and verify**

Show profile name/ID as a Traffic filter/badge without exposing credentials. Run Prisma push/generate, capture tests, and focused Traffic UI tests.

- [ ] **Step 5: Commit**

```bash
git add scanners/capture_proxy webapp/prisma/schema.prisma webapp/src/app/traffic docs/readmes/README.TRAFFIC.md
git commit -m "feat(traffic): redact and attribute authenticated sessions"
```

### Task 9: Add remaining CLI adapters and configuration selectors

**Files:**
- Modify: `recon/helpers/auth_adapters.py`
- Modify: `recon/helpers/resource_enum/hakrawler_helpers.py`
- Modify: `recon/helpers/resource_enum/ffuf_helpers.py`
- Modify: `recon/helpers/resource_enum/arjun_helpers.py`
- Modify: `recon/helpers/resource_enum/kiterunner_helpers.py`
- Modify: `recon/main_recon_modules/vuln_scan.py`
- Modify: `recon/tests/test_auth_adapters.py`
- Modify: `recon/tests/test_hakrawler_jsluice.py`
- Modify: `recon/tests/test_ffuf.py`
- Modify: `recon/tests/test_arjun.py`
- Modify: `recon/tests/test_nuclei_two_pass.py`
- Modify: `webapp/src/components/projects/ProjectForm/sections/HakrawlerSection.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/sections/FfufSection.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/sections/ArjunSection.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/sections/KiterunnerSection.tsx`
- Modify: `webapp/src/components/projects/ProjectForm/sections/NucleiSection.tsx`

**Interfaces:**
- Consumes: the stable artifact contract and `AuthProfileSelect`.
- Produces: one origin-scoped, profile-attributed execution per selected profile for each declared-compatible tool.

- [ ] **Step 1: Add table-driven failing adapter tests**

For every tool, assert its exact native proxy/header/cookie flags, target seeds, forbidden headers, profile isolation, and behavior when authentication preparation fails. Also assert an unsupported tool cannot acquire a selection through the API.

- [ ] **Step 2: Run recon and focused UI tests and confirm red**

```bash
./redamon.sh test unit
cd webapp && npm run test -- src/components/projects/ProjectForm/auth/AuthProfilesSection.test.tsx
```

Expected: new compatibility cases FAIL.

- [ ] **Step 3: Implement each adapter and selector**

Keep conversion pure in `auth_adapters.py`; wrappers only translate adapter output into commands. Preserve each tool's existing capture-proxy flags. Add UI selectors only after the corresponding command test proves safe origin filtering and attribution.

- [ ] **Step 4: Verify and commit**

Run the commands from Step 2, plus type-check and lint. Expected: PASS.

```bash
git add recon webapp/src/components/projects/ProjectForm/sections webapp/src/components/projects/ProjectForm/auth
git commit -m "feat(recon): authenticate compatible web scanners"
```

### Task 10: Implement one-refresh coordination and cleanup

**Files:**
- Modify: `recon/helpers/auth_sessions.py`
- Modify: `recon/main_recon_modules/resource_enum.py`
- Modify: `recon/main_recon_modules/vuln_scan.py`
- Modify: `recon_orchestrator/auth_browser_manager.py`
- Create: `recon/tests/test_auth_session_refresh.py`
- Modify: `recon_orchestrator/tests/test_auth_browser_manager.py`

**Interfaces:**
- Consumes: tool result classified as `auth_stale`, `auth_failed`, or ordinary result.
- Produces: `run_with_auth_refresh(profile_id, operation) -> AuthRunResult`, capped at one replay and one safe restart.

- [ ] **Step 1: Write failing state-machine tests**

Test no refresh on ordinary 401 findings, one refresh on an adapter-defined stale signal, atomic artifact replacement, no second refresh, cancellation cleanup, worker crash cleanup, and explicit `authenticated_execution_skipped` after final failure.

- [ ] **Step 2: Run recon/orchestrator tests and confirm red**

```bash
./redamon.sh test unit
```

Expected: refresh-state assertions FAIL.

- [ ] **Step 3: Implement the bounded coordinator**

Use explicit enum states and a per-profile lock. Restart only idempotent discovery invocations; do not automatically replay active vulnerability requests. Always unlink superseded artifacts and close worker containers in `finally` blocks.

- [ ] **Step 4: Verify and commit**

Run Step 2 commands. Expected: PASS.

```bash
git add recon/helpers/auth_sessions.py recon/main_recon_modules recon/tests/test_auth_session_refresh.py recon_orchestrator/auth_browser_manager.py recon_orchestrator/tests/test_auth_browser_manager.py
git commit -m "feat(auth): refresh stale recon sessions once"
```

### Task 11: Add the authenticated guinea-pig and end-to-end regression

**Files:**
- Create: `testing/guinea_pigs/authenticated_webapp/` (minimal app, Dockerfile, fixtures)
- Modify: `testing/guinea_pigs/docker-compose.yml`
- Create: `testing/e2e/authenticated_recon.spec.ts`
- Create: `tests/authenticated_recon_secret_audit_test.sh`
- Modify: `docs/readmes/README.RECON.md`
- Modify: `docs/readmes/README.TESTING.md`

**Interfaces:**
- Consumes: the complete profile recorder/preparation/tool flow.
- Produces: repeatable proof that two identities expose different authenticated endpoints without retained secret canaries.

- [ ] **Step 1: Create the failing end-to-end test**

The guinea pig exposes `/login`, `/account`, `/api/member`, and `/api/admin`; `member` cannot access the admin endpoint. The Playwright test creates two profiles through the UI, verifies them, selects both for Katana, starts recon, and asserts endpoint/profile attribution. The shell audit searches Postgres capture rows, body blobs, recon output, logs, exports, and graph properties for both credential canaries and fails on any match.

- [ ] **Step 2: Run the E2E test and confirm red**

```bash
./redamon.sh test all
```

Expected: authenticated E2E fails until stack wiring and cleanup are complete; no test may fake-skip with a return.

- [ ] **Step 3: Complete stack wiring and documentation**

Add the guinea pig only to the testing profile, document recorder workflow, compatible tools, plaintext-at-rest warning, session refresh, and troubleshooting states. Ensure all live prerequisites use real pytest/Playwright skip semantics when absent.

- [ ] **Step 4: Run final verification**

```bash
./redamon.sh test unit
./redamon.sh test all
cd webapp && npm run type-check && npm run lint
docker compose build auth-browser webapp recon-orchestrator
```

Expected: unit gate 100% green, integration suite green with explicit prerequisite skips only, type-check/lint clean, and all three images build.

- [ ] **Step 5: Inspect retained data for secrets**

Run `tests/authenticated_recon_secret_audit_test.sh` against the completed E2E run. Expected: exit `0`, with every storage class reporting zero credential-canary matches.

- [ ] **Step 6: Commit**

```bash
git add testing tests/authenticated_recon_secret_audit_test.sh docs/readmes/README.RECON.md docs/readmes/README.TESTING.md
git commit -m "test(auth): cover authenticated recon end to end"
```

## Final review gate

- Confirm every selected tool produces distinct `auth_profile_id` attribution.
- Confirm no profile selection changes the unauthenticated path.
- Confirm explicitly authenticated failures never fall back silently.
- Confirm the auth-browser worker has no trusted-network attachment.
- Confirm credential canaries are absent from every persistent/exported surface.
- Confirm unrelated worktree changes are not staged or committed.
- Invoke `superpowers:requesting-code-review`, address findings with `superpowers:receiving-code-review`, then use `superpowers:verification-before-completion` before claiming implementation complete.
