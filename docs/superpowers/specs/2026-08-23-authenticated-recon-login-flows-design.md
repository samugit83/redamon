# Authenticated Recon Login Flows

> **Superseded:** This hosted-recorder design was replaced by
> `2026-08-24-chrome-recorder-authenticated-recon-design.md`, which uses uploaded
> Chrome DevTools Recorder JSON and a simpler version-one scope.

**Date:** 2026-08-23

**Status:** Approved design
**Scope:** Simple username/password form login, multiple project profiles, and explicit per-tool use

## Problem

The recon pipeline discovers public application routes but cannot reliably reach pages and API endpoints that appear only after login. RedAmon needs a repeatable way for an operator to demonstrate a login flow once, validate that it can be replayed, and make the resulting authenticated state available to selected recon tools without mixing identities or leaking credentials.

RedAmon already has relevant foundations: browser-driven ZAP discovery, Playwright-capable agent execution, short-lived recon containers, TrafficMind capture and replay, and explicit per-tool project settings. The new feature should build on those boundaries rather than introduce a credential-injecting network proxy.

## Goals

- Record a simple username/password login interactively inside the RedAmon application.
- Store multiple named login flows per project, with one identity per flow.
- Require an explicit post-login success assertion.
- Replay only the profiles explicitly selected in each compatible tool's configuration.
- Produce one normalized session artifact and translate it through tool-specific adapters.
- Feed authenticated state and newly observed same-origin URLs into discovery without merging identities.
- Preserve existing unauthenticated behavior when no profile is selected.
- Attribute authenticated executions, traffic, endpoints, and findings to the profile used.

## Non-goals

Version one does not support MFA, CAPTCHA, magic links, federated SSO, arbitrary recorder JavaScript, automatic comparison of roles, permanent cookie storage, or implicit authentication of every HTTP tool. It does not automatically convert arbitrary local-storage values into authorization headers. Encryption at rest for target credentials is deferred.

## Chosen approach

RedAmon will use a normalized, run-scoped authenticated-session artifact with a dedicated adapter for every compatible tool.

Alternatives considered:

1. Flat cookie/header injection was rejected because it loses cookie scope, expiry, browser storage, and safe origin filtering.
2. A profile-specific credential-injecting proxy was rejected for version one because it would create a sensitive, stateful egress service and complicate the existing capture-proxy trust boundary.

## Domain model

Each project can own multiple named authentication profiles. A profile contains:

- Stable ID, project ownership, name, and optional description.
- Login start URL.
- Explicit allowed origins, initially derived from the login URL.
- A constrained ordered list of replay actions.
- Stored credential variables used by those actions.
- One or more required success assertions.
- Optional, explicit token-to-header extraction rules.
- Session timeout and one-refresh policy.
- Enabled state and timestamps.

Credential values are stored separately from ordinary profile configuration so profile reads, exports, and presets cannot include them accidentally. In version one they follow RedAmon's existing Postgres credential convention: plaintext database strings whose values are masked by application APIs. The product must describe them as masked, not encrypted at rest.

Tool configuration stores a list of selected authentication profile IDs. Selection is explicit per tool. Selecting multiple profiles creates distinct tool executions; it never creates a combined session.

## Recorder experience

The project configuration gains an **Authentication Profiles** section. Creating or editing a profile opens an isolated browser session rendered through the RedAmon UI and navigates to the configured login URL.

The recorder emits only a constrained action vocabulary:

- Navigate to an allowed URL.
- Click an element.
- Fill a non-secret literal.
- Fill a credential variable.
- Select an option.
- Wait for a bounded condition.
- Submit a form.

Arbitrary JavaScript and unrestricted network operations are not recordable. The recorder enforces maximum steps, redirects, per-step timeout, and overall duration.

Username and password input values never become literal action values. The operator associates those inputs with variables such as `USERNAME` and `PASSWORD`; only the variable reference is stored in the replay action. Credential read APIs return presence/masked state, never stored values. Supplying the existing mask during an update means "leave unchanged."

Before saving a profile, RedAmon replays it in a fresh browser context. The profile is valid only when every configured success assertion passes. Supported assertions in version one are a URL pattern and a visible element selector; either or both may be configured, and at least one is required.

Redirects to an origin outside the profile allowlist pause or fail recording until the operator explicitly adds that origin.

## Runtime architecture

Authentication is a preparation stage for selected web tools, not a global recon phase.

For each distinct selected profile in a scan, an authentication coordinator:

1. Resolves the profile under the current user and project.
2. Creates an isolated browser context.
3. Supplies credential variables to the runner through a private runtime file, never process arguments or ordinary settings JSON.
4. Replays the recorded actions through the TrafficMind proxy and existing egress guard.
5. Evaluates the required success assertions.
6. Emits a normalized session artifact on success.
7. Makes that artifact available only to tool executions that selected the profile.

Authentication runs once per profile per scan and is reused until its declared expiry or a detected authentication failure. Concurrent consumers must treat the artifact as immutable. A refresh produces a replacement artifact atomically.

The artifact is stored in a run-private directory readable only by the recon runtime user. It is deleted when the scan completes, fails, is cancelled, or is garbage-collected after an abnormal termination. Live cookies are not persisted as project configuration.

## Session artifact contract

The versioned artifact contains:

```text
schema_version
user_id
project_id
run_id
profile_id
allowed_origins
created_at
expires_at
final_url
success_assertions_passed
browser_storage_state
cookie_jar
approved_headers
observed_urls
observed_api_requests
```

The artifact is strictly schema-validated and written atomically. Its identity fields must match the consuming run and selected profile.

### Browser storage state

Browser-capable tools receive the complete browser storage state, including origin-scoped local storage and cookies. A browser consumer imports it into a fresh context; browser contexts are never shared across profiles.

### Cookie jar

The normalized cookie jar retains name, value, domain, path, expiry, `Secure`, `HttpOnly`, and `SameSite`. Before each invocation, the adapter selects cookies using normal destination host, path, TLS, and expiry rules. It must also require the destination origin to be in the profile allowlist.

### Approved headers

Only headers produced by an explicit profile extraction rule are eligible. The adapter must never propagate `Host`, content length, connection-specific headers, capture context headers, or incidental browser fingerprint headers. Local-storage tokens are not promoted automatically; an operator must define how a value maps to a header such as `Authorization`.

### URLs and API observations

The final authenticated URL and same-origin pages observed during login become authenticated crawl seeds. Observed API requests contribute method and normalized URL as discovery evidence and as scanner inputs where the consumer supports them. Request bodies are not automatically replayed. Foreign-origin observations are excluded unless that origin was explicitly allowed.

## Tool adapters

Every adapter accepts the tool configuration, profile metadata, and validated session artifact, then returns only the native inputs supported by that tool.

- Playwright-backed discovery and compatible ZAP browser execution receive browser storage state and authenticated seeds.
- Katana and Hakrawler receive authenticated seeds plus origin-filtered cookies and approved headers.
- Nuclei receives origin-filtered cookies and approved headers plus authenticated endpoint inputs.
- ffuf, Arjun, and Kiterunner receive origin-filtered cookies and approved headers where their native invocation supports them.
- JS and API analysis receive observed URLs/endpoints; credentials are included only if the module adopts the shared authenticated HTTP-client contract.
- Passive and non-HTTP tools do not expose authentication-profile selection.

An adapter must not claim compatibility unless its credential path can enforce origin scoping. Unsupported combinations are disabled in the UI and rejected server-side.

For multiple selected profiles, the pipeline executes the tool separately for each profile and records `auth_profile_id` on its result metadata. Findings and captured traffic use the stable ID; the UI resolves the current display name. Data from different profiles may be merged into the overall attack-surface graph only while retaining profile-level provenance.

## Pipeline data flow

```text
tool configuration selects profiles
    -> authenticate each distinct profile
    -> validate success and emit session artifact
    -> add authenticated URL/API seeds
    -> adapt artifact to each tool's native inputs
    -> execute once per selected profile
    -> capture and persist sanitized, profile-attributed results
```

No selected profiles means the current unauthenticated execution path remains unchanged.

## TrafficMind integration

Login replay and downstream authenticated requests pass through the current capture proxy and egress guard. Login traffic is tagged with an `auth-bootstrap` phase and the non-secret `auth_profile_id`.

Existing sensitive-header redaction is insufficient for login bodies. Before persistence, TrafficMind must also redact configured credential values, password-like form fields, extracted tokens, cookies, `Set-Cookie`, and authorization values. Retained login records may include URL, method, status, timing, sanitized parameter names, and passive signals. Secret-bearing values must not remain recoverable in inline bodies, offloaded bodies, spool files, logs, or rejected records.

The target-facing capture proxy must not receive stored project credentials as configuration. It only observes already-issued browser requests and continues to hold no database credential or signing key.

## Credential handling

Version one deliberately follows the repository's current masked-plaintext Postgres pattern.

- Only credential-specific mutation endpoints accept new values.
- Normal profile endpoints expose presence or a fixed mask, not plaintext or ciphertext.
- Stored credentials are excluded by construction from project serialization, exports, presets, recon settings, and downloadable result bundles.
- Credential resolution requires authenticated user ownership and matching project/profile IDs.
- Plaintext is materialized only while creating the private runtime credential file and inside the isolated runner.
- Runtime files are restrictively permissioned and removed after use.
- Logs and exceptions use variable names and profile IDs, never values.

Anyone with direct database access can read these target credentials. This limitation must be documented, and the schema boundary should permit a later migration to encrypted values without changing profile or replay contracts.

## Isolation and safety

The browser runner is target-facing and must not gain access to RedAmon's trusted application network. Its outbound requests use the existing egress guard, including the permanent denylist for RedAmon service addresses. The profile allowlist is an additional constraint, not a replacement for the egress guard.

Before releasing any authentication material, an adapter verifies:

- Current user, project, run, and selected profile match the artifact.
- Authentication assertions passed.
- The artifact has not expired.
- The destination origin is allowed.
- Cookie matching rules permit each cookie.
- Every non-cookie authentication header has an explicit extraction rule.

No credential or session material may appear in command-line arguments or environment variables.

## Failure behavior

Authentication is isolated by profile and tool:

- Replay errors or failed assertions mark that profile unavailable and record a sanitized diagnostic.
- A stale-session signal permits one login replay and, when safe, one restart of that profile's tool execution.
- A second authentication failure stops that profile/tool combination.
- One profile failure does not stop other profiles or unauthenticated tools.
- A tool explicitly configured for authentication never silently falls back to unauthenticated execution. It reports **authenticated execution skipped**.
- Authentication preparation must remain failure-soft for the overall recon pipeline.

## UI behavior

Compatible tool sections gain an **Authentication profiles** multiselect. Disabled or invalid profiles cannot be selected. Selecting more than one profile shows the execution multiplier because each selection creates another active tool run.

Scan status and results distinguish:

- Authentication preparing.
- Authentication verified.
- Authenticated tool execution.
- Authentication refresh.
- Authenticated execution skipped.

The UI displays profile names but transports and persists stable profile IDs for attribution.

## Testing and acceptance criteria

All Python validation runs inside the repository's Docker test gate; host `pytest` is prohibited. Webapp tests use the repository's containerized workflow.

Unit and integration coverage must prove:

- Recorder serialization replaces credential values with variables.
- A fresh-context replay passes and fails against the configured assertion correctly.
- Cookie attributes survive normalization and destination filtering.
- Browser consumers receive storage state while CLI consumers receive only supported material.
- Same-origin observed URLs become seeds and foreign origins do not.
- Multiple profiles create independent, attributed executions with no state merging.
- Unselected profiles have no effect.
- Explicit authentication never silently falls back.
- At most one refresh occurs after a stale-session signal.
- Profile and runtime-artifact access is tenant- and project-scoped.
- Runtime artifacts are deleted after success, failure, cancellation, and cleanup.
- Credential values are absent from GET responses, exports, presets, arguments, environment, logs, recon output, graph writes, TrafficMind storage, and rejected spool records.
- Existing scans are behaviorally unchanged when no profile is selected.

An end-to-end guinea-pig application will expose public and authenticated-only routes. The test uses at least two profiles, runs a compatible crawler separately with each, confirms discovery and profile attribution of protected endpoints, and scans retained artifacts for the credential canaries.

## Rollout boundaries

Compatibility should be added tool by tool. A tool becomes selectable only after its adapter, origin filtering, redaction behavior, and profile attribution are covered. The first vertical slice should include the recorder, one browser consumer, and one CLI crawler; subsequent adapters reuse the stable artifact contract.

The design does not require every recon tool to become authentication-aware in the first release. It requires unsupported state to be explicit and safe.
