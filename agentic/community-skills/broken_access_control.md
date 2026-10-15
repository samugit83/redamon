# Broken Access Control Attack Skill

Systematic access-control audit that maps an application's privilege boundaries and then probes them along every dimension: vertical escalation (reaching higher-role functions), horizontal escalation (reaching peer users' data), forced browsing to unlinked and hidden resources, multi-step process and workflow-state bypass, and client-side-only or referer/location-based enforcement. Use this skill to drive a structured access-control engagement and to route individual findings to the dedicated object-level, function-level, and mass-assignment skills.

## When to Classify Here

Pick this skill when the task is a broad access-control assessment or when the right specialized skill is not yet obvious, including:

- "Audit this app for broken access control across all roles."
- "Map the privilege boundaries and find where a normal user reaches admin features."
- "Can a low-privilege user force-browse to the hidden reporting pages?"
- "Is the checkout step enforced, or can I skip straight to the confirmation state?"
- "The menu hides admin links client-side, is the enforcement actually server-side?"
- "Compare what role A and role B can reach and report every gap."

Keywords: broken access control, access control, authorization, privilege escalation, vertical escalation, horizontal escalation, forced browsing, forced browse, hidden endpoints, workflow bypass, process-step bypass, state bypass, role-based access control, RBAC, least privilege, referer-based access control, client-side enforcement, multi-step flow, admin function exposure.

### Disjoint from neighbouring skills

- vs. `idor_bola_exploitation` (community, @samugit83): that is the dedicated object-level playbook (two-identity swap across REST/GraphQL/batch/job/storage). When a specific finding is "I can read/modify another user's object by its reference", route it there. This skill owns the broad audit and the boundary mapping that discovers such references.
- vs. `bfla_exploitation` (community, @samugit83): that is the dedicated function-level playbook (vertical privilege escalation, transport drift, gateway header trust). When a finding is "a low-role user can invoke a high-role function", route it there. This skill decides that routing.
- vs. `mass_assignment` (community, @samugit83): when the access-control gap is "I can set a privileged field on an object I do own", route it there.
- vs. `auth_session_attacks` (community): that covers authentication and sessions (who you are proven to be). This skill assumes the user is already authenticated and asks what they can reach. A logout that does not invalidate a session is `auth_session_attacks`; an authenticated user reaching an admin page is this skill.
- vs. `api_testing` (community): `api_testing` runs a quick BOLA/403 check as part of an API sweep; this skill runs the thorough access-control audit and hands specific findings to the dedicated skills.
- vs. `cve_exploit` (built-in): a named authorization-bypass CVE in a specific product belongs to `cve_exploit` when the user gives the CVE ID.

## Tools

- `query_graph` to inventory every Endpoint and Parameter for the host, grouped by apparent privilege (public, user, admin, internal), which seeds the boundary map.
- `execute_httpx` to probe discovered and guessed endpoints and read status codes and auth headers at scale.
- `execute_ffuf` for forced browsing: enumerate unlinked paths, admin consoles, backup and debug routes, and ID-bearing resources.
- `execute_curl` for role-comparison requests and single-shot boundary probes.
- `execute_code` for the two-identity differential harness (replay every discovered request as each role and diff the outcomes) and for multi-step workflow automation.
- `execute_playwright` to capture the authenticated UI as each role, reveal client-side-hidden controls, and confirm whether hidden actions are enforced server-side.
- `kali_shell` for `jq` and any one-off processing of the captured request matrix.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, build the boundary map from recorded history. `redamon.sitemap()` lists every observed endpoint; `redamon.query({...})` aggregates the status matrix per path. The core technique is role replay: capture the full set of requests while browsing as a high-privilege role, then `redamon.replay` each one carrying a low-privilege identity's cookies and diff the result with `redamon.diff`. `redamon.params()` highlights object-reference parameters to route to the object-level skill. Where the proxy stops: client-side-hidden controls and UI-gated actions need `execute_playwright` to reveal, and forced browsing for never-observed paths needs `execute_ffuf`.

## Workflow

Three phases. Phase 1 is non-destructive: enumerate the full surface and build an explicit privilege-boundary map with at least two identities. Phase 2 probes each boundary dimension and routes concrete findings to the dedicated skills. Phase 3 scopes the impact. The whole skill is read-and-compare oriented; avoid destructive state changes and prefer idempotent GETs when mapping.

### Phase 1: Surface Enumeration and Boundary Mapping (Informational)

1. **Inventory the surface via `query_graph`**: ask "list all Endpoints and Parameters for the target host" and tag each as apparently public, user-level, admin-level, or internal based on path and naming.

2. **Establish at least two identities**: a low-privilege account and, where available, a peer low-privilege account (for horizontal tests) and a high-privilege account (to learn the admin surface). Capture a session for each. If only one role is available, note the limitation and focus on forced browsing and client-side-enforcement checks.

3. **Forced browsing for unlinked resources** with `execute_ffuf`:
   ```
   -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,201,301,302,401,403
   -u https://target.tld/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403
   ```
   Catalog admin consoles, debug/backup routes, API docs, and ID-bearing resources that are not linked from the user UI.

4. **Capture the high-role surface with `execute_playwright`** (when a high-role account exists): browse the admin area and record every action and endpoint it calls. These become the vertical-escalation test set. Also note controls that are merely hidden in the DOM for the low role.

5. **Build the boundary map**: a table of {endpoint, method, required role as observed, object-reference params}. This is the artifact the whole engagement is measured against.

Once the surface is enumerated, at least a low-privilege identity is in hand, and the privilege-boundary map is built, **request transition to exploitation phase**.

### Phase 2: Exploitation

Probe each boundary dimension against the Phase 1 map. Route concrete findings to the dedicated skills. Every track ends with a Validation step.

#### 2.A Vertical escalation (low role reaching high-role functions)

Replay each admin-surface request (from Phase 1 step 4) carrying the low-privilege identity. Use the differential harness:
```
execute_code> language="python", code: """
import requests
low={'Cookie':'session=<LOW>'}
tests=[('GET','/admin/users'),('POST','/admin/users/1/promote'),('GET','/admin/config')]
for m,p in tests:
    r=requests.request(m,'https://target.tld'+p,headers=low,timeout=10,verify=False,allow_redirects=False)
    print(m,p,r.status_code,len(r.content))   # 200 on an admin route as a low user = vertical BAC
"""
```
A high-role function reachable by the low role is a Broken Function Level Authorization finding: route the deep exploitation to `bfla_exploitation`. Validation: the privileged response returned for the low-privilege identity.

#### 2.B Horizontal escalation (peer-user data)

For each endpoint with an object-reference parameter, request another user's reference as the low-privilege (or peer) identity. A peer's object returned is a Broken Object Level Authorization finding: route the two-identity confirmation and depth to `idor_bola_exploitation`. If the gap is setting a privileged field on your own object, route to `mass_assignment`. Validation: cross-user data returned or modified, confirmed with the second identity.

#### 2.C Forced browsing and hidden-resource access

Request the unlinked resources catalogued in Phase 1 step 3 as each role. A sensitive resource served without the expected role (an export, a backup, a debug endpoint, another tenant's file) is broken access control even without an ID to tamper. Validation: the sensitive content returned for an identity that should not reach it.

#### 2.D Multi-step process and workflow-state bypass

Where a flow enforces an order (cart to payment to confirmation, or request to approval to fulfillment), attempt to invoke a later step directly, replay a step out of order, or reach a state-changing endpoint without completing the gating step:
```
execute_curl> -X POST https://target.tld/checkout/confirm -H "Cookie: session=<LOW>" -d '{"orderId":"<own_order>"}'
```
Validation: a later state reached or a gated action performed without completing the required prior step.

#### 2.E Client-side-only and header-based enforcement

1. **Client-side hiding**: invoke a DOM-hidden control's underlying request directly; if the server honors it, enforcement was UI-only.
2. **Referer/location trust**: some apps gate access on `Referer` or a geo/IP header. Send the request without, or with a forged, `Referer`/location header and check whether access changes.
3. Validation: the action succeeds server-side despite the client-side gate, or access flips based on a spoofable header.

### Phase 3: Post-Exploitation

Scope the audit result precisely and reversibly.

1. **Quantify the boundary gaps**: against the Phase 1 map, mark every endpoint where the observed required role did not match the enforced role, by dimension.
2. **Classify and route each finding**: object-level to `idor_bola_exploitation`, function-level to `bfla_exploitation`, privileged-field to `mass_assignment`; keep forced-browsing, workflow-bypass, and client-side-enforcement findings here.
3. **Capture minimal proof** per finding: one privileged response per boundary gap, tied to the specific low-privilege identity, with reversible or read-only actions preferred.
4. **Chain hand-off**: an admin function reached may enable further compromise (user management, config) that belongs to the matching exploitation skill.

## Reporting Guidelines

Each finding must include:

- **Dimension**: vertical escalation, horizontal escalation, forced browsing, workflow-state bypass, or client-side/header enforcement.
- **Endpoint**: URL, method, the role that should be required, and the identity that reached it.
- **Boundary map excerpt**: the observed-versus-enforced role mismatch for the affected endpoint.
- **Working exploit**: the copy-paste request (and differential-harness output) reproducing the gap as the under-privileged identity.
- **Proof**: the privileged response, cross-user data, hidden resource, or out-of-order state reached, tied to a specific identity.
- **Routing note**: whether the finding was handed to `idor_bola_exploitation`, `bfla_exploitation`, or `mass_assignment` for deeper exploitation.
- **Impact**: data exposure, privilege escalation, or business-process abuse.
- **CVSS**: scaled to the function or data exposed and the privilege required to reach it.
- **Remediation**: deny-by-default server-side authorization on every endpoint and object, enforce role and ownership checks independently of the UI, and never rely on hidden links, client-side gating, or spoofable headers.
- **References**: OWASP Top 10 A01:2021 Broken Access Control, the OWASP Authorization cheatsheet, PortSwigger access-control labs.

## Important Notes

- **Boundary map first.** The highest-value artifact is the explicit {endpoint, required role, enforced role} table from Phase 1. Every finding is a mismatch in that table, which keeps the audit complete and the report defensible.
- **Two identities make the proof.** A 200 on `/admin` is only a finding if the account used should not be admin. Always confirm the ownership or role boundary with a second, under-privileged identity before reporting.
- **Prefer read-only and reversible probes.** Access-control mapping should not change state where avoidable. For state-changing endpoints, use your own objects and clearly labeled test data, and undo anything created.
- **Engagement scope.** Enumerate and prove, but do not mass-harvest other users' data through a discovered horizontal gap; pull a single redacted proof and report the pattern.
- **Route, do not duplicate.** When a finding is cleanly object-level, function-level, or mass-assignment, hand the deep exploitation to the dedicated skill rather than re-deriving it here.
- **OOB-blocked environments.** This skill relies on inline differential responses, so it works without any out-of-band callback.
- **CVE handoff.** A named authorization-bypass CVE in a specific product belongs to `cve_exploit` when the user gives the CVE ID.
- **No em dashes** anywhere in artifacts that flow into the report. Use hyphens.
