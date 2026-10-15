# HTTP Request Smuggling Attack Skill

Workflow for HTTP request smuggling and connection desync: detect and confirm CL.TE, TE.CL, TE.TE, and CL.CL discrepancies between a front-end proxy and a back-end server, exploit HTTP/2 to HTTP/1.1 downgrade desync (H2.CL, H2.TE) and request tunneling, and chain a confirmed desync to victim request hijacking, cache poisoning, and security-control bypass. Use this skill when a target sits behind a proxy, CDN, or load balancer and you want to desynchronize how the two ends parse request boundaries.

## When to Classify Here

Pick this skill when the request is about desynchronizing request parsing across a proxy chain, including:

- "Test this CDN-fronted app for HTTP request smuggling."
- "Confirm a CL.TE desync and poison the response queue."
- "The target speaks HTTP/2, check for H2.CL downgrade smuggling."
- "Chain the desync to steal another user's request."
- "Use the smuggling primitive to bypass the front-end access control on /admin."
- "Turn the desync into a web cache poisoning attack."

Keywords: HTTP request smuggling, request smuggling, desync, connection desync, CL.TE, TE.CL, TE.TE, CL.CL, Content-Length, Transfer-Encoding, chunked, HTTP/2 downgrade, H2.CL, H2.TE, request tunneling, response queue poisoning, request hijacking, cache poisoning, front-end back-end discrepancy, smuggler, h2csmuggler, Turbo Intruder.

### Disjoint from neighbouring skills

- vs. `web_cache_poisoning` (chat skill / other): cache poisoning via unkeyed inputs (headers, parameters) that a single server reflects into a cached response is its own class. This skill covers cache poisoning only as a downstream effect of a confirmed request-boundary desync across a proxy chain. If there is no desync and the issue is an unkeyed header reflected into cache, that is standalone cache poisoning, not smuggling.
- vs. `host_header_injection` / `open_redirect` (other): those abuse a single server's handling of a header or redirect; smuggling specifically exploits the disagreement between two servers about where one request ends and the next begins.
- vs. `api_testing` (community): a 403 bypass via routing headers (`X-Original-URL`) on one server is an `api_testing` check. Bypassing a front-end control by smuggling a request past it to the back-end is this skill.
- vs. `ssrf_exploitation` / SSRF (other): request tunneling through a smuggling primitive can reach internal endpoints, but the entry primitive is a desync. Pure SSRF via a URL-fetching parameter stays with the SSRF handling.
- vs. `cve_exploit` (built-in): a named smuggling CVE in a specific proxy or server version belongs to `cve_exploit` when the user gives the CVE ID.

## Tools

- `query_graph` to inventory Endpoints and Technology nodes, especially front-end infrastructure (CDN, reverse proxy, load balancer) and back-end server signatures for the host.
- `execute_httpx` to fingerprint the server chain, detect HTTP/2 support, and read `Via`, `Server`, and `X-Cache` headers that reveal the proxy topology.
- `execute_curl` for baseline timing measurements and for firing crafted raw requests (via `--data-binary` with explicit headers) where exact bytes matter.
- `execute_code` for byte-precise socket-level probes: Python with a raw `socket` or `h2` client is the reliable way to send conflicting Content-Length and Transfer-Encoding and to time the back-end delay oracle.
- `kali_shell` for `smuggler.py`, `h2csmuggler`, and `interactsh-client` when confirming blind desync via an out-of-band callback.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, source the topology and a baseline request from recorded history. `redamon.grep` finds `Via`, `X-Cache`, and `Server` headers that expose the proxy chain; `redamon.replay` re-fires a captured POST so you can measure its baseline latency before introducing a desync. Where the proxy stops: request smuggling needs byte-exact control and raw socket behavior that a replay abstraction cannot provide, so the actual desync probes run through `execute_code` (raw socket / h2) and `kali_shell` tooling; use the captured traffic only to pick the right endpoint and baseline.

## Workflow

Three phases. Phase 1 is non-destructive: fingerprint the proxy chain, pick a safe timing probe, and confirm a parsing discrepancy with the differential-response and timing oracles. Phase 2 weaponizes a confirmed desync. Phase 3 scopes impact. Smuggling is intrusive by nature: it can affect other users' traffic, so Phase 1 uses only self-targeting timing probes, and Phase 2/3 require explicit authorization (see Important Notes). If out-of-band callbacks are forbidden, rely on the timing and differential-response oracles rather than OAST confirmation.

### Phase 1: Detection and Confirmation (Informational)

1. **Map the proxy chain via `query_graph`**: ask "list Technology and Endpoint nodes for the target host that indicate a CDN, reverse proxy, or load balancer, and any back-end server signatures". A front-end and back-end from different vendors is the classic desync precondition.

2. **Fingerprint the chain and protocol with `execute_httpx`**:
   ```
   -u https://target.tld -sc -title -server -td -silent -j -include-response-header
   ```
   Note HTTP/2 support, `Via`, `Server`, and `X-Cache`. Pick a POST-capable endpoint that tolerates a body (a search or form handler) as the probe target.

3. **Run the timing-based detection probes** (self-targeting, non-destructive). A CL.TE desync shows a delay when the back-end waits for a chunk that never completes; a TE.CL desync shows a delay on the reverse shape. Use `execute_code` for byte-exact control:
   ```
   execute_code> language="python", code: """
   import socket, ssl, time
   host='target.tld'
   # CL.TE timing probe: front-end uses Content-Length, back-end uses Transfer-Encoding
   req=(
     'POST /search HTTP/1.1\\r\\n'
     f'Host: {host}\\r\\n'
     'Content-Type: application/x-www-form-urlencoded\\r\\n'
     'Transfer-Encoding: chunked\\r\\n'
     'Content-Length: 4\\r\\n\\r\\n'
     '1\\r\\nA\\r\\nX'          # back-end (TE) waits for the next chunk -> delay
   )
   ctx=ssl.create_default_context()
   s=ctx.wrap_socket(socket.create_connection((host,443)),server_hostname=host)
   t=time.time(); s.sendall(req.encode())
   try: s.settimeout(10); s.recv(4096)
   except socket.timeout: pass
   print('elapsed', round(time.time()-t,2))   # ~>5s indicates CL.TE
   s.close()
   """
   ```
   Reverse the header precedence for the TE.CL probe. Baseline a normal request first so the delay is meaningful.

4. **Confirm with the differential-response (two-request) oracle** only after a timing hit, and only when authorized, because this stage can affect the next request on the connection. Send a crafted request that leaves a prefix in the back-end buffer, then a normal follow-up request, and observe whether the follow-up gets an anomalous response (for example a 404/405 for a valid path) that proves the prefix was prepended.

5. **HTTP/2 downgrade check**: if the front-end speaks H2 but downgrades to H1 to the back-end, test H2.CL and H2.TE by injecting conflicting length semantics in the H2 request (duplicate headers, an explicit `content-length` that disagrees with the body). Use `kali_shell` with `h2csmuggler` for the H2C upgrade variant.

6. **Automated triage** with `smuggler.py` to classify the mutation that works, then reproduce it manually for a clean proof:
   ```
   kali_shell> python3 smuggler.py -u https://target.tld/search
   ```

Once a parsing discrepancy is confirmed with a timing hit and the responsible desync shape (CL.TE, TE.CL, TE.TE, H2.CL, or H2.TE) is identified, **request transition to exploitation phase**.

### Phase 2: Exploitation

Weaponize the confirmed desync with the minimum impact needed to prove it. Every track ends with a Validation step. These steps can affect other users; run them only on an authorized, low-traffic target or a dedicated test environment (see Important Notes).

#### 2.A Front-end control bypass

Smuggle a request to a path the front-end blocks (for example `/admin`) inside the body of a request to an allowed path, so the back-end processes the smuggled line after the front-end has already authorized the outer request. Validate with the privileged response returned for the smuggled path.

#### 2.B Response queue poisoning / request hijacking

Use the desync to leave a partial request in the back-end buffer so the next client's request is appended to the attacker's prefix, causing that victim request (and its headers, including session cookies) to be captured in the attacker's response. Confirm on a self-test connection first. Validation: capture a benign marker from your own second connection before claiming cross-user impact, and only demonstrate real victim capture with explicit authorization.

#### 2.C Cache poisoning via desync

Chain the desync so a malicious response is stored by the front-end cache against a legitimate URL key, serving it to subsequent visitors. Validate against a dedicated test path with a unique marker; never poison a high-traffic production key.

#### 2.D Request tunneling to internal endpoints

When the front-end multiplexes connections, tunnel a request to a back-end-only virtual host or internal path. Validation: an internal-only response returned through the tunneled request.

### Phase 3: Post-Exploitation

Scope the impact precisely and reversibly.

1. **Quantify blast radius**: which front-end controls are bypassable, which cache keys are poisonable, and whether cross-user request capture is reproducible.
2. **Capture minimal proof**: one smuggled privileged response, one poisoned test-path cache entry with a unique marker, or one self-captured request prefix. Do not run sustained queue poisoning against live traffic.
3. **Clean up**: purge any poisoned cache entry you created (request the clean URL enough times to evict, or coordinate a cache purge), and close desync-affected connections.
4. **Chain hand-off**: a bypassed control reaching an admin function hands off to `broken_access_control`; a tunneled internal endpoint that fetches URLs hands off to the SSRF handling.

## Reporting Guidelines

Each finding must include:

- **Desync shape**: CL.TE, TE.CL, TE.TE, CL.CL, H2.CL, or H2.TE, with the front-end and back-end signatures involved.
- **Endpoint**: the probe URL and method, and the proxy chain topology (`Via`/`Server`/`X-Cache`).
- **Detection evidence**: the baseline latency versus the timing-probe latency, plus the differential-response proof.
- **Working exploit**: the exact byte sequence (headers and body, with CRLFs shown) that reproduces the desync, delivered via `execute_code` or the tool command.
- **Demonstrated impact**: front-end control bypass, request hijacking, cache poisoning, or internal tunneling, with the specific proof artifact.
- **CVSS**: typically 9.x when it yields cross-user request capture or control bypass, adjusted for preconditions.
- **Remediation**: normalize or reject ambiguous requests at the front-end, use HTTP/2 end-to-end (no downgrade), reject requests with both Content-Length and Transfer-Encoding, and ensure front-end and back-end agree on parsing.
- **References**: James Kettle "HTTP Desync Attacks" and "HTTP/2: The Sequel is Always Worse", PortSwigger request smuggling labs, the `smuggler.py` and `h2csmuggler` documentation.

## Important Notes

- **This attack affects other users by design.** Response queue poisoning and cache poisoning can serve attacker content to, or capture requests from, real visitors. Phase 2 and Phase 3 require explicit written authorization and should target a low-traffic window or a dedicated test environment. Phase 1 timing probes are self-contained and safe.
- **Confirm before you weaponize.** A single timing anomaly can be a fluke (network jitter, keep-alive quirks). Baseline, repeat the probe, and corroborate with the differential-response oracle before claiming a desync.
- **Byte precision matters.** Smuggling depends on exact CRLFs, header casing, and length values. Libraries that normalize requests will hide the bug, which is why the probes use raw sockets and `--data-binary`, not high-level HTTP helpers.
- **Clean up poisoned caches.** Any cache entry you poison for proof must be evicted or purged afterward. Track the exact key you touched.
- **OOB-blocked environments.** If an external collector is forbidden, rely on the timing and differential-response oracles; do not depend on OAST to confirm.
- **CVE handoff.** A named smuggling CVE in a specific proxy or server version belongs to `cve_exploit` when the user gives the CVE ID. This skill stays on discovery and manual weaponization.
- **No em dashes** anywhere in artifacts that flow into the report. Use hyphens.
