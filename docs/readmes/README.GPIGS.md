# Guinea Pigs - Vulnerable Test Servers

Intentionally vulnerable servers for security testing and exploitation practice.

> **WARNING**: These are intentionally vulnerable systems. Deploy only in isolated environments for authorized testing.

---

## Available Guinea Pigs

Every folder in `testing/guinea_pigs/`. Its own index, [testing/guinea_pigs/README.md](../../testing/guinea_pigs/README.md),
adds each lab's run command and address; `tests/test_guinea_pigs_index.py` fails when a lab
has no row there.

| Folder | What it is | What it validates |
|--------|------------|-------------------|
| `apache_2.4.49` | Apache 2.4.49 (CVE-2021-41773, CVE-2021-42013) | Path traversal + RCE |
| `apache_2.4.25` | Apache 2.4.25 (CVE-2017-3167, CVE-2017-3169) | Auth bypass + NULL pointer dereference |
| `node_serialize_1.0.0` | Node.js + node-serialize 0.0.4 (CVE-2017-5941) | Deserialization RCE |
| `dvws-node` | DVWS-Node, a modern vulnerable Node.js app, plus CVE Lab containers | Many web vulnerability classes and Metasploit-exploitable CVEs |
| `php2shell_upload_progress` | PHP target for the session upload-progress use-after-free its README names | The agent's exploitation phase end to end |
| `fp_regression_target` | IP-mode recon target, driven over MCP | The false-positive filters drop the noise and keep the real findings |
| `nested_wildcard_lab` | Self-contained DNS + web lab | Domain-batch scope groups: nested wildcards, scan roots below the org domain |
| `ip_hostnames_lab` | Self-contained DNS + web lab on `192.88.98.0/24`: a shared host with SNI vhosts and two PTR names, a no-PTR host, names that resolve to an outsider, a CDN-like edge, a urlscan stub, a private target, and an outsider that must receive nothing | The four Hostnames on target IPs modes of an IP project, over MCP and partial recon; needs the lab host DNS setup of its index |
| `supply_chain_target` | Deterministic HTTP target | Every branch of the L2 supply-chain harvest, each once, with a known outcome |
| `serialized_target` | App that leaks serialized objects | `recon/serialized_scan` and the agent's `deserialization` skill |
| `route_exposure_lab` | Four services: an app with open internal, admin and debug routes and exposed files (and, for v2 and v3, a Spring and Laravel fingerprint, an actuator route catalog, a client-side admin router, a credentialed CORS reflection, a cacheable logged-in profile and a disguised login wall), its twin, a hostile host (connection resets, a zlib bomb behind `.git`, a false Ignition, a `*` CORS route), and an outsider that must receive nothing | `recon/route_exposure`, its Jev hooks, and the agent's route-exposure parts in `access_control`, `path_traversal` and `rce` |
| `web-cache-poisoning` | Real nginx shared cache in front of a vulnerable origin | The web cache poisoning module (`recon/cache_scan`) |
| `waf-bypass` | Signature WAF edge in front of an origin also reachable by IP | WAF bypass via direct origin access (taxonomy class 13) |
| `proxy_brain_target` | Vulnerable Flask app | The agent's `proxy_brain` / `redamon.*` capabilities |
| `http-request-smuggling` | CL.TE two-tier HTTP stack | The `http_request_smuggling` skill end to end |
| `http-desync-cl0` | CL.0 two-tier HTTP stack | That skill's CL.0 / 0.CL leg (class 2) |
| `http-desync-h2` | HTTP/2 downgrade target | That skill's HTTP/2 downgrade leg (class 3) |
| `http-desync-clientside` | Single-tier CL.0 target, no reverse proxy | That skill's client-side desync leg (class 4) |
| `http-desync-expect` | Expect / obfuscation target | That skill's Expect / obfuscation leg (class 5) |
| `skiller_sqli_csrf` | Flask app with a blind SQL injection behind a single-use form token | The Skiller plugin flow; `PROMPT.txt` is the task sent to the agent |
| `skiller_nosql_login` | MongoDB-backed login | The Skiller plugin flow against NoSQL operator injection; `PROMPT.txt` as above |

Every folder except the two `skiller_*` ones has its own `README.md` with deployment and
test steps; those two carry a `docker-compose.yml` and the prompt. Beside the folders:
`skiller_job.sh`, `skiller_progress.sh`, `skiller_wait.sh` and `skiller_verify_override.sh`
(helpers that read a Skiller run's state), and `triage_truth.yaml`, the ground truth
`tooling/scripts/triage_eval.py` scores the Priority Board ranking against.

---

## EC2 Info

| Setting | Value |
|---------|-------|
| **IP** | 15.160.68.117 |
| **URL** | https://gpigs.devergolabs.com |
| **Port** | 8080 |
| **Health Check** | `/health` |
