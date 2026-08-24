# Chrome Recorder Authenticated Recon

**Date:** 2026-08-24
**Status:** Approved design
**Scope:** Upload-only Chrome DevTools Recorder flows, run-scoped authenticated sessions, and capability-based recon-tool adapters

This specification supersedes `2026-08-23-authenticated-recon-login-flows-design.md` and its implementation plan. The earlier design assumed an interactive recorder hosted by RedAmon; version one now accepts uploaded Chrome DevTools Recorder JSON only.

## Problem

RedAmon's recon pipeline discovers public application routes but cannot reliably reach pages and APIs exposed only after login. An operator can already record a working login with Chrome DevTools Recorder and export it. RedAmon needs to replay several such recordings against applications under the configured target domain, turn each resulting browser session into reusable authentication material, and make that material available to explicitly selected recon tools without mixing identities.

Authentication is not universally portable. Browsers can preserve cookies, origin storage, refresh behavior, and application JavaScript, while CLI tools usually accept only cookies or static headers. The design must cover ordinary cookie and stable bearer-token applications while treating dynamic or request-signed authentication as browser-only.

## Goals

- Accept multiple named Chrome DevTools Recorder JSON uploads per project.
- Replay every flow independently in an isolated Chromium context.
- Use a user-provided final URL pattern as the authentication success condition.
- Restrict active replay and authenticated discovery to the configured target domain and its subdomains.
- Produce an immutable, run-scoped authenticated-session artifact per successful flow.
- Feed browser state, scoped cookies, stable origin-bound headers, and authenticated endpoint seeds to compatible tools.
- Fan a tool out separately for every selected flow and, when required, every destination origin.
- Merge discoveries into existing graph resources while retaining authentication-flow provenance.
- Preserve current unauthenticated behavior when no flow is selected.
- Keep failures isolated by flow and tool.

## Non-goals

Version one does not include:

- A recorder hosted inside RedAmon.
- External identity providers, federated SSO, MFA, CAPTCHA, magic links, or device approval.
- Arbitrary Recorder JavaScript or custom extension steps.
- Portable CLI support for rotating tokens, per-request signing, complex CSRF, browser fingerprinting, or service-worker authentication.
- Automatic session refresh or mid-tool restart.
- Automatic role comparison or a claim that an endpoint requires authentication.
- Encryption at rest for uploaded Recorder JSON.
- Authentication adapters for every HTTP tool.

## Chosen approach

RedAmon uses a normalized, run-scoped session artifact with capability-based adapters and a browser fallback.

Alternatives considered:

1. Browser-only discovery preserves the most authentication behavior but cannot authenticate existing CLI recon tools.
2. A session-injecting proxy minimizes tool integration but creates a sensitive, stateful credential authority and complicates TrafficMind's capture-only trust boundary.
3. The chosen hybrid replays once, exports a validated artifact, gives every tool only the authentication forms it supports, and keeps unsupported dynamic authentication in the browser.

## Domain model and configuration

A project owns multiple named authentication flows. Each flow contains:

```text
AuthenticationFlow
├── stable ID
├── user and project ownership
├── display name
├── uploaded Recorder JSON
├── login/start URL
├── expected final URL pattern
├── enabled state
└── timestamps
```

The uploaded JSON is stored as plaintext Postgres JSONB. It may contain credentials, so it is excluded from logs, generated presets, Neo4j, recon result bundles, and ordinary project serialization. A dedicated authenticated API handles upload, replacement, and intentional retrieval.

The recon workflow gains a standalone **Authenticate Web Sessions** step containing one or more flows. Compatible downstream tools store a list of selected flow IDs. A flow is replayed once per scan and shared immutably by its selected consumers.

Selecting several flows for one tool creates separate executions. Authentication state from different flows is never combined.

## Target-domain scope

The configured project target domain is the automatic scope boundary. An allowed hostname is either the target itself or a subdomain separated by a DNS label boundary.

For a target of `example.test`:

- `example.test`, `portal.example.test`, and `api.example.test` are allowed.
- `fakeexample.test` and `example.test.attacker.invalid` are rejected.

Hosts are lowercased, IDNs are canonicalized, and trailing dots are removed before comparison. Scheme and port do not affect domain membership, although normal cookie security rules still apply.

Scope is enforced before replay for recorded navigations, the login URL, and the expected final URL. It is enforced again during replay for top-level navigation, form submission, XHR, `fetch`, iframe navigation, and WebSocket destinations.

Passive third-party scripts, styles, images, and fonts may load so applications using CDNs continue to function. They do not become recon targets and never receive RedAmon-injected authentication. Unrelated external identity-provider navigation remains unsupported in version one.

Every outbound connection also passes the existing resolved-IP egress guard. Domain membership is not a replacement for DNS-rebinding, internal-network, or RedAmon-service protections.

## Replay lifecycle

For each referenced flow, the authentication coordinator:

1. Resolves the flow under the current user and project.
2. Validates the Recorder schema, supported action vocabulary, size, step count, URLs, and time limits.
3. Creates a fresh isolated Chromium context.
4. Replays the declarative actions through TrafficMind and the existing egress guard.
5. Observes target-domain network activity through Chromium's network instrumentation.
6. Waits for the top-level browser URL to match the configured final URL pattern.
7. Allows a short bounded settling interval for the authenticated page's initial API activity.
8. Extracts browser and portable HTTP authentication state.
9. Atomically writes the run-scoped artifact and registers it by flow ID.

Arbitrary JavaScript and unsupported custom Recorder steps fail validation.

### Final URL matching

The success condition is operator-defined rather than inferred from page content. Matching includes scheme, canonical hostname, port, and path. Query strings and fragments are ignored by default because they commonly contain transient state. Trailing slashes are normalized. A bounded path wildcard supports destinations such as `https://portal.example.test/users/*/home`.

If the final URL does not match before the configured timeout, the flow fails and produces no reusable artifact.

## Session artifact contract

The immutable, versioned artifact contains:

```text
schema_version
user_id
project_id
run_id
flow_id
target_domain
created_at
expires_at
matched_final_url
browser_storage
cookie_jar
origin_headers
observed_urls
observed_requests
capabilities
```

It is written atomically to a run-private directory readable only by the recon runtime. Identity fields must match the consuming user, project, run, and selected flow.

### Browser storage

Browser consumers receive complete origin-grouped browser state, including cookies and the local or session storage needed by the replayed application. A consumer imports the state into a fresh context; browser contexts are never shared between flows.

### Cookie jar

Cookies retain name, value, domain, host-only status, path, expiry, `Secure`, `HttpOnly`, and `SameSite`. Before a tool invocation, the adapter selects cookies using destination host, path, TLS, and expiry rules. It also requires the destination to remain within the target domain.

### Stable headers

The worker observes outgoing target requests after and around the successful final navigation. Stable `Authorization`, API-key, and recognized token headers are stored only in the artifact and bound to the exact origin where they were observed. They are not promoted across sibling subdomains.

The adapter never forwards `Host`, content-length, connection-specific headers, capture-context headers, or incidental browser fingerprint headers. Authentication that varies per request is marked browser-only rather than generalized unsafely.

### Observed requests and seeds

The final authenticated URL and observed target-domain pages become crawl seeds. XHR, `fetch`, GraphQL, and WebSocket handshakes contribute method, normalized URL, content type, parameter names, and request-template structure. Live secret values remain in the artifact; persisted results retain only non-secret metadata and flow attribution.

The artifact advertises capabilities such as:

```text
browser_state: true
cookie_auth: true
stable_header_auth: true
complex_dynamic_auth: false
```

## Tool adapters and execution fan-out

Every adapter accepts tool capabilities, flow metadata, and a validated artifact. It returns only native inputs supported by that tool.

Conceptually:

```text
materialize_auth(flow_id, destination_url, tool_capabilities)
    → authenticated seeds
    → destination-matching cookies
    → exact-origin stable headers
    → supported captured request templates
```

Before releasing authentication material, the adapter verifies artifact identity, expiry, target-domain membership, cookie matching rules, header origin, and declared consumer capability.

A selected tool runs once per flow. Because many CLI tools accept only one global header set, an adapter also splits execution by origin when necessary:

```text
Katana × Customer Portal × portal.example.test
Katana × Customer Portal × api.example.test
Katana × Admin Console × admin.example.test
Katana × Admin Console × api.example.test
```

Each execution receives only seeds and authentication belonging to that origin. A bounded fan-out guard limits the number of flow/origin executions. Only target-domain origins actually observed by the flow are eligible.

Compatibility categories are explicit:

- Browser-capable consumers receive browser state and seeds.
- Cookie-capable consumers receive destination-filtered cookies.
- Static-header-capable consumers receive exact-origin stable headers.
- Request-template-capable consumers receive captured request structure and its run-private authentication context.
- Dynamic or request-signed authentication remains browser-only.

An incompatible selection reports **authenticated execution skipped** with a non-secret reason. It never silently falls back to an unauthenticated execution. When no flow is selected, the existing unauthenticated path is unchanged.

## Version-one consumers

The first vertical slice proves both browser extraction and non-browser reuse:

- The replay worker and TrafficMind capture contribute initial authenticated URLs and API observations.
- Katana is the first general-purpose CLI crawler adapter.
- Existing JS analysis consumes target URLs and scripts discovered during replay and authenticated crawling.
- TrafficMind request replay can use captured authenticated request templates.
- Nuclei, ffuf, Arjun, and other adapters are added incrementally after the shared contract is proven.

## TrafficMind integration

Login replay and downstream authenticated requests pass through TrafficMind and retain the non-secret flow ID. Suggested phases are `auth-bootstrap` and `authenticated-crawl`.

Header redaction alone is insufficient for login traffic. Before persistence, TrafficMind must redact configured credential values, password-like form fields, cookies, `Set-Cookie`, authorization values, extracted tokens, and token-bearing bodies. Secret values must not remain recoverable in inline bodies, offloaded bodies, spool files, logs, or rejected records.

The capture proxy remains an observer and egress guard. It does not receive stored Recorder JSON or become a credential-injecting proxy.

## Graph model

Neo4j stores topology and non-secret provenance, never Recorder JSON, cookies, tokens, or browser storage.

A tenant-scoped entity node represents the reusable flow metadata:

```text
(:AuthFlow {
    id,
    user_id,
    project_id,
    name,
    login_origin
})
```

Its merge key is `{id, user_id, project_id}`. Existing resources retain their established tenant-scoped identities:

- `Subdomain`: name plus tenant.
- `BaseURL`: normalized origin plus tenant.
- `Endpoint`: method, path, BaseURL, plus tenant.

A successful final-URL match creates:

```text
(AuthFlow)-[:AUTHENTICATES_TO]->(BaseURL)
```

Authenticated observations create:

```text
(AuthFlow)-[:DISCOVERED_WITH_AUTH]->(BaseURL)
(AuthFlow)-[:DISCOVERED_WITH_AUTH]->(Endpoint)
```

These relationships express provenance, not a claim that the resource requires authentication. Relationship metadata retains `first_seen_at`, `last_seen_at`, `first_seen_run_id`, `last_seen_run_id`, and the discovering tool where relevant.

Resources are placed according to their own URL. An API observed while browsing `portal.example.test` but hosted at `api.example.test` is attached to the API subdomain and BaseURL. The `AuthFlow` relationship records which session exposed it.

If several flows discover the same endpoint, the endpoint is merged once and each flow gets its own provenance relationship. Graph writes reuse the existing `Subdomain`, `BaseURL`, and `Endpoint` nodes and include `user_id` and `project_id` in every entity merge.

Introducing `AuthFlow`, its relationships, or properties requires synchronized updates to the canonical graph schema, the text-to-Cypher prompt, and graph visualization colors.

## Failure handling

Each flow progresses independently through `pending`, `validating`, `replaying`, `final_url_matched`, and `artifact_ready`. Terminal failures include `invalid_recording`, `out_of_scope`, `replay_failed`, `final_url_not_reached`, `artifact_failed`, and `expired`.

Diagnostics identify the flow, failed step, URL, timeout, or unsupported action without including credentials, request bodies, cookies, or tokens.

- One failed flow does not stop successful flows or unauthenticated pipeline stages.
- Tools selected for a failed flow report **authenticated execution skipped**.
- An explicitly authenticated execution never silently falls back.
- Version one replays each flow once per scan and does not perform mid-tool refresh.
- Known cookie or JWT expiries may shorten the artifact's configured maximum lifetime.
- An expired artifact is rejected before a dependent tool starts.
- A `403` is not treated automatically as session expiry.

Authentication should execute close to its dependent tools rather than at the beginning of a long-running scan.

## Cleanup

Artifacts and generated tool configuration files are removed after normal completion, replay or tool failure, cancellation, and pipeline interruption. A periodic garbage collector removes artifacts belonging to inactive or abandoned runs. Cleanup diagnostics contain only run and flow IDs.

## UI behavior

The project workflow configuration exposes an **Authenticate Web Sessions** step. Operators can add, replace, disable, or remove named Recorder uploads and configure each flow's login URL and expected final URL pattern.

Compatible tools expose an authentication-flow multiselect. Selecting several flows explains that the tool will run once per flow and may split further by origin. Unsupported tools expose no authentication selector.

Status distinguishes flow preparation from tool execution:

- Authentication validating.
- Authentication replaying.
- Final URL matched.
- Session artifact ready.
- Authenticated tool execution.
- Authenticated execution skipped.

The UI displays names but transports stable IDs. It reports artifact capabilities without exposing live values.

## Testing and acceptance criteria

All Python validation runs inside RedAmon's Docker test gate; host `pytest` is prohibited. Webapp validation uses the repository's containerized Vitest, type-check, and lint workflow. Fixtures contain synthetic local target data only.

Unit and integration coverage must prove:

- Valid Recorder JSON is accepted and invalid, oversized, or unsupported input is rejected.
- Recorder navigation and final URLs obey exact DNS-label target matching.
- Lookalike domains and runtime out-of-scope active requests are rejected.
- Each flow receives a fresh browser context.
- A final-URL match succeeds and a mismatch fails only that flow.
- Cookie scope attributes survive extraction and destination filtering.
- Stable headers remain bound to the exact observed origin.
- Browser state and portable authentication never cross flows.
- Katana fans out separately by flow and origin.
- Unsupported authentication produces an explicit skip without fallback.
- Selecting no flows leaves existing scan behavior unchanged.
- Shared discoveries merge to one `BaseURL` or `Endpoint`.
- Separate `AuthFlow` relationships retain provenance.
- API resources attach to their actual subdomain rather than the calling frontend.
- Credentials and live session values are absent from logs, Neo4j, normal recon output, TrafficMind persistence, rejected spool records, command arguments, and environment variables.
- Runtime artifacts are removed after success, failure, cancellation, interruption, and abandoned-run cleanup.

An end-to-end guinea-pig target uses synthetic `portal`, `admin`, and `api` subdomains. Two Recorder flows discover a shared endpoint, while one discovers an additional protected endpoint. The test confirms independent sessions, Katana fan-out, correct graph merging and attachment, profile provenance, failure isolation, and absence of credential canaries from retained artifacts.

## Rollout boundary

The first implementation plan should deliver the upload/configuration path, isolated Chromium replay, final-URL verification, artifact registry, TrafficMind tagging and redaction, graph provenance, and one Katana adapter. Additional adapters reuse the stable contract and become selectable only after their origin isolation and secret-handling behavior are covered.
