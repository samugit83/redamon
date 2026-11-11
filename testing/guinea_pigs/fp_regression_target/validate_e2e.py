"""End-to-end assertions for the false-positive lab, run entirely over MCP.

Run after e2e_fp.py:   python3 validate_e2e.py <projectId>
The HTTP-layer project (e2e_fp.py --http-layer): python3 validate_e2e.py <projectId> --http-layer
The passive-CVE project (e2e_fp.py --passive-cves), after each of its runs:
    python3 validate_e2e.py <projectId> --passive-cves baseline|partial|unscanned|off

N-01, a run with no JS input keeps the earlier js_recon findings, takes a second
run: `--js-count` prints the count, then switch resource_enum off, rerun, and
`--js-count-equals <n>` asserts it is unchanged (README.md, "Running the proof").

The JS-coverage project (e2e_fp.py --js-coverage): `--js-coverage first` after
its first run (prints JS_BULK_COUNT=<n>), then rerun it with a low
jsReconMaxFiles and .20's /js/app.min.js hidden, and `--js-coverage capped <n>`.

The vhost-naming / tlsx CDN-tag project (e2e_fp.py --vhost-origin):
`--vhost-origin`.

The plan-09 per-host coverage projects: `--coverage stamps` on the
e2e_fp.py --coverage project (writes the linked CVEs to
coverage_cve_snapshot.json), `--coverage import <thatProjectId>` on its
exported-then-imported copy, `--coverage clean` on the --coverage-clean
project, and `--coverage lost` on it once its graph nodes are deleted.

Plan 10A, disposition, on the main project after its Priority Board run:
`--disposition before`, then e2e_fp.py --disposition-decide <id>, then
`--disposition decided`. Each prints CANDIDATES=<n>, the count the report's
candidate total must equal. These read through list_findings as well.

Plan 10B, the stored disposition, after a v3.10 Priority Board run:
`--disposition-stored before` and, after the decide step, `--disposition-stored
decided` on the main project; `--disposition-stored http-layer` on the plan-03
project. Each prints BLOCKERS=<the candidates per stored blocker>.

Plan 11, IP attribution: `--ip-ownership` on the e2e_fp.py --ip-ownership
project, `--ip-ownership-stealth <recon.log>` on its stealth twin (the log
e2e_fp.py --log wrote), `--ip-ownership-nwlab` on the domain-mode project over
the nested-wildcard lab (e2e_fp.py --ip-ownership-nwlab).

Audit cases (e2e_fp.py prints RUN_START=<UTC time> for the access-log checks):
`--roe <runStart>` (R-3) on the --roe project, then `--roe-window` (R-32: a
window that excludes now refuses the start; it restores the one containing
now); `--r29 <runStart>`; `--r43 <runStart> <recon.log>`; `--nuclei-throttle
<recon.log | nuclei.jsonl>` (R-19: the recon log e2e_fp.py --log wrote echoes
every line of the run's nuclei_detection.jsonl); `--redis
open|delay|auth` after each run of the --redis project (R-24). `--roe` and
`--roe-window` also write project settings over MCP; every other check reads.

Every check is read-only Cypher through query_graph (tenant-scoped by the
server) and prints PASS / FAIL with what the graph actually holds. Exit 0 only
when every assertion holds. Case ids match README.md.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mcp_client as mcp  # noqa: E402

USAGE = ("usage: validate_e2e.py <projectId> [--js-count | --js-count-equals <n> | --http-layer"
         " | --passive-cves baseline|partial|unscanned|off | --js-coverage first | --js-coverage capped <n>"
         " | --vhost-origin | --coverage stamps|clean|lost | --coverage import <originalProjectId>"
         " | --disposition before|decided | --disposition-stored before|decided|http-layer"
         " | --ip-ownership | --ip-ownership-stealth <recon.log>"
         " | --ip-ownership-nwlab | --roe <runStart> | --roe-window | --r29 <runStart>"
         " | --r43 <runStart> <recon.log> | --nuclei-throttle <recon.log> | --redis open|delay|auth"
         " | --probefail baseline|stall|httpx|healthy <runStart> [recon.log] | --secchk <runStart>"
         " | --redis-nohttp open <runStart> | --redis-nohttp rerun <findingId> | --redis-nohttp auth"
         " | --fanout <recon.log> | --r14 <runStart> [recon.log] | --r14js <runStart> <recon.log>"
         " | --graphql-rate <runStart> | --graphql-cop stealth|ran|dos-off <runStart> [recon.log]"
         " | --vhost-drop <runStart> <recon.log> | --cache stall|open <runStart> [recon.log]"
         " | --epai snapshot <file> | --epai compare <file> <excludedHost> | --userinput <toolId>"
         " | --upload-sink <fileName>]")
if len(sys.argv) not in (2, 3, 4, 5, 6):
    sys.exit(USAGE)
P = sys.argv[1]
NET = "192.88.94"
APEX = "fplab.test"
results = []


def q(cypher):
    out, err = mcp.call("query_graph", {"projectId": P, "cypher": cypher})
    if err or not isinstance(out, dict):
        raise RuntimeError(f"query failed: {json.dumps(out)[:500]}")
    return out.get("records", [])


def check(case, ok, detail):
    results.append((case, bool(ok), detail))


def report():
    width = max(len(c) for c, _, _ in results)
    for case, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {case:<{width}}  {detail}")
    failed = [c for c, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


def http_layer_checks():
    """Plan 03 cases, on the project e2e_fp.py --http-layer creates."""
    api = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'ip_api_exposed'
               RETURN v.matched_ip AS ip, v.severity AS sev, v.evidence AS ev, v.control_check AS cc""")
    by_ip = {r["ip"]: r for r in api}
    silent = sorted(ip for ip in (f"{NET}.15", f"{NET}.20", f"{NET}.25") if ip in by_ip)
    check("A-01", not silent, f"API Endpoint Exposed on IP on catch-alls: {silent} (expect none on the cache "
                              f"and SPA hosts, nor on the JSON catch-all .25)")
    r = by_ip.get(f"{NET}.22")
    check("A-02", r and r["sev"] == "high" and r["cc"] == "passed" and "control_check: passed" in (r["ev"] or ""),
          f"the real API on .22: {r}")

    ep = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = 'http://{NET}.23' AND e.path = '/'
               OPTIONAL MATCH (e)-[:USES_TECHNOLOGY]->(t:Technology)
               RETURN e.title AS title, e.server AS server, e.first_status_code AS first,
                      e.status_code AS last, e.redirect_chain_codes AS chain,
                      e.redirected_off_host AS off, e.final_url AS final, collect(t.name) AS techs""")
    r = ep[0] if ep else None
    ext = q(f"""MATCH (d:ExternalDomain) WHERE d.domain = '{NET}.21'
                RETURN d.sources AS src, d.redirect_from_urls AS frm, d.titles_seen AS titles""")
    x = ext[0] if ext else None
    ip_mode = any(d.get("ip") for d in q("MATCH (d:Domain) RETURN d.ip_mode AS ip"))
    if ip_mode:
        # IP mode follows same-host redirects only (httpx -fhr, I-1): .23's own
        # 302 is the answer, .21 is never requested, so nothing of its page and
        # no redirect record of it reach the graph.
        check("R-01", r and not r["title"] and "SAP" not in str(r["server"] or "")
              and not [t for t in r["techs"] if "SAP" in (t or "")],
              f".23's root Endpoint keeps nothing from the third-party IdP page: {r}")
        check("R-02", r and r["first"] == 302 and r["last"] == 302 and (r["chain"] or [None]) == [302]
              and not r["off"] and not (r["final"] or "").endswith("/saml/login"),
              f".23's off-host redirect is not followed in IP mode: {r}")
        check("R-03", not (x and "http_probe_redirect" in (x["src"] or [])),
              f"no redirect record of the IdP host, which httpx never asked: {x}")
    else:
        check("R-01", r and not r["title"] and not r["server"] and not [t for t in r["techs"] if "SAP" in (t or "")],
              f".23's root Endpoint keeps nothing from the third-party IdP page: {r}")
        check("R-02", r and r["first"] == 302 and r["off"] is True and (r["chain"] or [None])[0] == 302
              and (r["final"] or "").endswith("/saml/login"), f".23's redirect chain: {r}")
        check("R-03", x and "http_probe_redirect" in (x["src"] or [])
              and any(f"{NET}.23" in u for u in (x["frm"] or [])), f"the IdP host is an external domain: {x}")

    js = q(f"""MATCH (e:Endpoint) WHERE (e.source = 'js_recon' OR e.js_recon_source = true)
               AND e.baseurl IN ['http://{NET}.20', 'http://{NET}.22']
               RETURN e.baseurl AS b, e.path AS p, e.validation_status AS vs ORDER BY b, p""")
    shell = [x for x in js if x["b"] == f"http://{NET}.20" and x["p"] in ("/api/read", "/api/list")]
    check("E-02", not shell, f"js_recon Endpoints for paths the SPA shell answers like any path: {shell}")
    real = [x for x in js if x["b"] == f"http://{NET}.22" and x["p"] == "/api/v1"]
    check("E-03", real and real[0]["vs"] == "hittable", f"the real API path from the bundle: {real}")

    deny_hosts = [f"http://{NET}.{n}" for n in (26, 27, 28)]
    roots = q(f"""MATCH (e:Endpoint) WHERE e.path = '/' AND e.baseurl STARTS WITH 'http://{NET}.'
                  RETURN e.baseurl AS b, e.shared_body_cluster AS n""")
    marks = {r["b"]: r["n"] for r in roots}
    check("D-01", all((marks.get(b) or 0) >= 3 for b in deny_hosts),
          f"the shared deny page: { {b: marks.get(b) for b in deny_hosts} } (expect shared_body_cluster >= 3)")
    others = {b: n for b, n in marks.items() if n is not None and b not in deny_hosts}
    check("D-02", not others, f"pages no other host serves are not marked: {others}")


PASSIVE = "['shodan_api', 'internetdb', 'shodan', 'shodan_host_lookup']"


def passive_cves(stage):
    """Plan 04 cases, on the project e2e_fp.py --passive-cves creates, after each run."""
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source IN {PASSIVE}
                 RETURN v.id AS id, v.target_ip AS ip, v.target_port AS port, v.name AS cve,
                        v.port_confirmed AS pc, v.triage_state AS state,
                        v.triage_base_tier_rule AS rule, v.triage_tier AS tier,
                        toString(v.updated_at) AS seen""")
    by = {(r["ip"], r["cve"]): r for r in rows}
    ssh, nginx, catalog = (by.get((f"{NET}.14", "CVE-2018-15473")), by.get((f"{NET}.10", "CVE-2021-23017")),
                           by.get((f"{NET}.10", "CVE-2019-11043")))
    heartbleed = by.get((f"{NET}.13", "CVE-2014-0160"))
    if stage == "baseline":
        check("P-01", ssh and ssh["port"] == 22 and ssh["pc"] is False,
              f".14's OpenSSH CVE on 22, closed on the lab and in the port list: {ssh}")
        check("P-02", nginx and nginx["port"] == 80 and nginx["pc"] is True,
              f".10's nginx CVE on 80, which naabu found open: {nginx}")
        check("P-03", heartbleed and heartbleed["port"] == 443 and heartbleed["pc"] is False,
              f".13's verified CVE on 443, closed on the lab: {heartbleed}")
        check("P-04", ssh and ssh["state"] == "inactive" and ssh["rule"] == "the port scan found the port closed",
              f"the board: .14's CVE is resolved as inactive with the closed-port reason: {ssh}")
        check("P-05", nginx and nginx["state"] == "open" and nginx["tier"] not in ("T1", "T2"),
              f"the board: .10's confirmed CVE stays open, below Act soon: {nginx}")
        ports = q(f"""MATCH (i:IP)-[:HAS_PORT]->(p:Port) WHERE i.address IN ['{NET}.14', '{NET}.10']
                      RETURN i.address AS ip, p.number AS port, p.source AS src, p.passive_only AS passive""")
        pb = {(r["ip"], r["port"]): r for r in ports}
        p22, p80 = pb.get((f"{NET}.14", 22)), pb.get((f"{NET}.10", 80))
        check("P-06", p22 and p22["passive"] is True and p80 and p80["passive"] is False,
              f"Port 22 only Shodan saw is passive_only, port 80 naabu found is not: {p22} / {p80}")
        check("H-04", not [r for r in rows if r["ip"] in (f"{NET}.11", f"{NET}.12")],
              "no CVE on the Vercel / cdn-tagged hosts")
    elif stage == "partial":
        check("P-07", heartbleed is not None and nginx is not None and heartbleed["seen"] < nginx["seen"],
              f".13 could not be looked up: its CVE is kept as it was ({heartbleed}), .10's was refreshed "
              f"({nginx and nginx['seen']})")
        check("P-08", catalog is None, f".10's CVE the provider dropped is pruned: {catalog}")
        gaps = q("""MATCH (d:Domain) WHERE d.recon_coverage_gaps IS NOT NULL
                     RETURN d.recon_coverage_gaps AS g""")
        listed = [g for r in gaps for g in json.loads(r["g"] or "[]") if g.get("source") == "shodan"]
        check("P-09", len(listed) == 1 and listed[0].get("hosts") == 1,
              f"the coverage record names Shodan once, for one IP: {listed}")
    elif stage == "unscanned":
        check("P-10", ssh and ssh["pc"] is None,
              f"with naabu on 80,443 the scan did not look at 22: no port_confirmed: {ssh}")
        check("P-11", nginx and nginx["pc"] is True, f".10's port 80 is still confirmed open: {nginx}")
    elif stage == "off":
        # query_graph never sees a muted finding; the muted-findings tool does.
        out, err = mcp.call("search_muted_findings", {"projectId": P, "search": "CVE-2021-23017"})
        muted = [] if err else (out.get("findings") or out.get("items") or out.get("results") or [])
        check("P-12", not rows and len(muted) == 1 and "stale" in json.dumps(muted[0]).lower(),
              f"Shodan switched off: no unmuted Shodan CVE is left ({rows}); the muted one is kept "
              f"and stale: {json.dumps(muted)[:400]}")
    else:
        sys.exit(USAGE)


SPA = f"http://{NET}.20"
BULK = f"http://{NET}.29"
COVERAGE_FILES = {"/static/js/main.4f3a.js": "static", "/_next/static/chunks/pages/app-91c.js": "next",
                  "/js/app.min.js": "min", "/js/bundle.js__v_ab12": "hash"}


def bulk_count():
    """js_recon findings on the bulk host: what a capped rerun must keep."""
    total = 0
    for label in ("JsReconFinding", "Secret"):
        rows = q(f"""MATCH (f:{label}) WHERE f.source = 'js_recon'
                     AND f.source_url STARTS WITH '{BULK}/' RETURN count(f) AS n""")
        total += rows[0]["n"]
    return total


def js_coverage_checks(stage, expected_bulk=None):
    """Plan 06 cases, on the project e2e_fp.py --js-coverage creates."""
    files = q(f"""MATCH (jf:JsReconFinding {{finding_type: 'js_file'}}) WHERE jf.source_url STARTS WITH '{SPA}/'
                  OPTIONAL MATCH (jf)-[:HAS_ENDPOINT]->(e:Endpoint)
                  RETURN jf.source_url AS url, collect(e.path) AS paths""")
    by_url = {r["url"][len(SPA):]: r["paths"] for r in files}
    if stage == "first":
        # Each file calls fetch("/api/cov/<marker>"): its Endpoint under the
        # file's own node proves the file was downloaded and analyzed.
        analyzed = {p: f"/api/cov/{m}" in by_url.get(p, []) for p, m in COVERAGE_FILES.items()}
        check("J-11", all(analyzed.values()), f"bundles the default exclude list matches, analyzed: {analyzed}")
        excluded = [p for p in COVERAGE_FILES if p != "/js/bundle.js__v_ab12"]
        eps = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{SPA}' AND e.path IN {excluded}
                    RETURN e.path AS p""")
        check("J-12", not eps, f"the excluded JS files handed to js_recon are no Endpoints: {[r['p'] for r in eps]}")

        mapped = f"{SPA}/static/js/main.4f3a.js.map#src/config.ts"
        sec = q(f"""MATCH (s:Secret {{source: 'js_recon'}}) WHERE s.source_url = '{mapped}'
                    OPTIONAL MATCH (jf:JsReconFinding {{finding_type: 'js_file', source_url: '{mapped}'}})-[:HAS_SECRET]->(s)
                    RETURN s.secret_type AS t, s.base_url AS b, s.validation_status AS vs, count(jf) AS files""")
        r = sec[0] if sec else None
        check("S-04", r and r["t"] == "Stripe Secret Key" and r["b"] == SPA and r["files"] == 1,
              f"the key in the map's src/config.ts is a Secret under its own file node: {r}")
        ep = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{SPA}' AND e.path = '/api/v2/orders'
                   RETURN e.method AS m, e.source AS src, e.js_recon_source AS js""")
        check("S-04b", ep and ep[0]["m"] == "GET", f"the map source's fetch is an Endpoint: {ep}")
        sm = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'source_map_exposure'
                   AND f.source_url IN ['{SPA}/static/js/main.4f3a.js', '{SPA}/static/js/main.4f2a9c.js']
                   RETURN f.source_url AS js, f.severity AS sev, f.secrets_in_source AS n""")
        maps_ = {r["js"].rsplit("/", 1)[-1]: r for r in sm}
        r = maps_.get("main.4f3a.js")
        check("S-04c", r and r["sev"] == "low" and r["n"] == 1, f"the map itself is low and counts its secret: {r}")
        lib = [r for label in ("Secret", "JsReconFinding") for r in q(
            f"""MATCH (s:{label}) WHERE s.source = 'js_recon'
                AND (s.source_url CONTAINS 'lib.8e1f.js.map#' OR coalesce(s.matched_text, '') CONTAINS 'LIBRARYEXAMPLE')
                RETURN '{label}' AS l, s.source_url AS u""")]
        check("S-05", not lib, f"library sources feed no detector: {lib}")

        refs = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'source_map_reference'
                     AND f.source_url STARTS WITH '{SPA}/' RETURN f.source_url AS js, f.control_check AS cc""")
        ref = {r["js"].rsplit("/", 1)[-1]: r["cc"] for r in refs}
        check("M-07", "s3miss.0c1d.js" not in ref, f"an S3 AccessDenied 403 for a missing map: {ref.get('s3miss.0c1d.js')}")
        check("M-08", "cfmiss.2e3f.js" not in ref, f"a 403 the made-up sibling also gets: {ref.get('cfmiss.2e3f.js')}")
        check("M-04", ref.get("private.9c3d.js") == "passed", f"a 403 the sibling does not get: {ref.get('private.9c3d.js')}")

        want = {("GET", "/v1/lab-orders"), ("GET", "/lab-users"), ("GET", "/api/lab-users/"),
                ("GET", "/v2/lab-items"), ("GET", "/v1/lab-accounts"), ("GET", "/api/lab-export")}
        got = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{SPA}' AND (e.path CONTAINS 'lab-' OR e.path = '/q')
                    RETURN e.method AS m, e.path AS p, e.path_template AS t""")
        have = {(r["m"], r["p"]) for r in got}
        tmpl = {r["p"]: r["t"] for r in got}
        check("E-04", want <= have and tmpl.get("/api/lab-users/") == "/api/lab-users/${id}",
              f"the call shapes in calls.6e7f.js: missing {sorted(want - have)}; template {tmpl.get('/api/lab-users/')}")
        noise = sorted(p for _, p in have if "lab-key" in p or "lab-q" in p)
        check("E-05", not noise, f"Map / URLSearchParams / headers .get() yield no Endpoint: {noise}")

        detail = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{BULK}' AND e.path ENDS WITH '/detail' RETURN count(e) AS n""")
        check("F-00", detail[0]["n"] >= 500, f"bulk map sources analyzed at volume: {detail[0]['n']} detail endpoints")
        print(f"JS_BULK_COUNT={bulk_count()}")
        return

    gaps = q("""MATCH (d:Domain) WHERE d.recon_coverage_gaps IS NOT NULL
                RETURN d.name AS d, d.recon_coverage_gaps AS g""")
    text = " ".join(str(r["g"]) for r in gaps)
    check("F-01", "js_recon_file_cap" in text, f"the file cap is a coverage gap: {text[:400]}")
    check("F-02", "/js/app.min.js" not in by_url,
          f"a fully analyzed host still prunes: the hidden file's findings are gone: {by_url.get('/js/app.min.js')}")
    got = bulk_count()
    check("F-03", got == expected_bulk, f"the capped host keeps its findings: {got} (expect {expected_bulk})")


def vhost_origin_checks():
    """Plan 07 cases, on the project e2e_fp.py --vhost-origin creates."""
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{NET}.31'
                 RETURN v.hostname AS h, v.name AS name, v.type AS type, v.layer AS layer,
                        v.severity AS sev ORDER BY h""")
    by_host = {r["h"]: r for r in rows}
    portal = by_host.get(f"portal.{APEX}") or {}
    check("V-11", (portal.get("name"), portal.get("type"), portal.get("layer"))
          == (f"Hidden Virtual Host: portal.{APEX}", "hidden_vhost", "both"),
          f"same app on L7 and L4: {portal} (expect the hidden-vhost name and type, layer both)")
    split = by_host.get(f"split.{APEX}") or {}
    check("V-12", (split.get("name"), split.get("type"), split.get("layer"), split.get("sev"))
          == (f"Routing Inconsistency (L7 vs L4): split.{APEX}", "host_header_bypass", "both", "high"),
          f"Host and SNI reach different apps: {split} (expect the routing name, high)")
    check("V-13", sorted(by_host) == [f"portal.{APEX}", f"split.{APEX}"],
          f"names reported on .31: {sorted(by_host)} (expect portal and split only; the rest hit the default page)")
    ips = {r["ip"]: r for r in q(f"""MATCH (i:IP) WHERE i.address IN ['{NET}.31', '{NET}.32']
                                     RETURN i.address AS ip, i.is_cdn AS cdn, i.cdn_name AS name,
                                            i.cdn_source AS src""")}
    edge = ips.get(f"{NET}.32") or {}
    check("T-01", (edge.get("cdn"), edge.get("name"), edge.get("src")) == (True, "cloudflare", "tlsx"),
          f".32 behind a Cloudflare-issued certificate: {edge} (expect is_cdn, cloudflare, cdn_source tlsx)")
    plain = ips.get(f"{NET}.31") or {}
    check("T-02", plain and not plain.get("cdn") and plain.get("src") is None,
          f".31 with the lab's own certificate: {plain} (expect no CDN tag)")
    origin = _ownership([f"{NET}.35", f"{NET}.36"])
    for case, n in (("T-03", 35), ("T-04", 36)):
        r = origin.get(f"{NET}.{n}") or {}
        check(case, r and r.get("is_cdn") is not True and r.get("cdn") is None and r.get("src") is None
              and r.get("own") != "shared_edge",
              f".{n} behind a Cloudflare Origin CA certificate ({'ECC' if n == 36 else 'RSA'} issuer): "
              f"is_cdn {r.get('is_cdn')}, cdn_name {r.get('cdn')}, cdn_source {r.get('src')}, ownership "
              f"{r.get('own')} (expect an origin: no CDN tag, never shared_edge)")


CVE_SNAPSHOT = os.environ.get("COVERAGE_CVE_SNAPSHOT", "coverage_cve_snapshot.json")


def _summary(project_id=None):
    out, err = mcp.call("graph_summary", {"projectId": project_id or P})
    if err or not isinstance(out, dict):
        raise RuntimeError(f"graph_summary failed: {json.dumps(out)[:500]}")
    return out


def _stamps():
    """Each BaseURL's stamps, by the lab host it serves."""
    rows = q("""MATCH (b:BaseURL) RETURN b.url AS url, b.js_recon_status AS js, b.js_recon_inputs AS ji,
                       b.js_recon_outputs AS jo, b.js_recon_reason AS jr, b.nuclei_status AS nu,
                       b.nuclei_inputs AS ni, b.nuclei_reason AS nr""")
    return {r["url"].split("://", 1)[1].split(":")[0]: r for r in rows if "://" in (r["url"] or "")}


def _cve_links(project_id=None):
    global P
    saved, P = P, project_id or P
    try:
        return q("""MATCH (v:Vulnerability)-[r:INCLUDES_CVE]->(c:CVE)
                    RETURN c.id AS id, properties(c) AS props, count(r) AS links ORDER BY id""")
    finally:
        P = saved


def coverage_checks(stage, other=None):
    """Plan 09 cases, on the projects e2e_fp.py --coverage / --coverage-clean create."""
    if stage == "stamps":
        hosts = _stamps()
        spa, api, down = hosts.get(f"{NET}.20") or {}, hosts.get(f"{NET}.22") or {}, hosts.get(f"{NET}.33")
        check("CV-01", spa.get("js") in ("complete", "partial") and (spa.get("ji") or 0) > 0 and (spa.get("jo") or 0) > 0,
              f".20 (serves JavaScript): {spa} (expect js_recon complete or partial, files read, findings)")
        check("CV-02", (api.get("js"), api.get("ji")) == ("no_input", 0),
              f".22 (a JSON API, no JavaScript): {api} (expect js_recon no_input)")
        check("CV-03", down is not None and down.get("js") is None and down.get("nu") is None,
              f".33 (answers 503): {down} (expect a BaseURL with no stamp from either module)")
        scanned = {h: r for h, r in hosts.items() if r.get("nu")}
        check("CV-04", {f"{NET}.20", f"{NET}.22"} <= set(scanned)
              and all(r["nu"] in ("complete", "partial") and (r["ni"] or 0) > 0 for r in scanned.values()),
              f"nuclei stamps: { {h: (r['nu'], r['ni'], r['nr']) for h, r in scanned.items()} }")
        cov = _summary().get("coverage") or {}
        js, nu = cov.get("js_recon") or {}, cov.get("nuclei") or {}
        check("CV-05", js.get("recorded") and nu.get("recorded") and js.get("not_scanned", 0) >= 1
              and nu.get("not_scanned", 0) >= 1 and js.get("no_input", 0) >= 1,
              f"graph_summary coverage: {cov} (expect both recorded, .33 not_scanned, .22 no_input)")
        links = _cve_links()
        check("CV-06", links, f"INCLUDES_CVE links: {[(r['id'], r['links']) for r in links]} (expect some)")
        with open(CVE_SNAPSHOT, "w") as fh:
            json.dump(links, fh, sort_keys=True, default=str)
        print(f"CVE_LINKS={sum(r['links'] for r in links)} (snapshot in {CVE_SNAPSHOT})")
    elif stage == "clean":
        plain = _stamps().get(f"{NET}.34") or {}
        check("CC-01", (plain.get("js"), plain.get("ji"), plain.get("jo")) == ("complete", 1, 0),
              f".34 (one script, nothing in it): {plain} (expect js_recon complete, 1 file, 0 findings)")
        check("CC-02", js_recon_count() == 0, "js_recon findings: expect none")
        js = (_summary().get("coverage") or {}).get("js_recon") or {}
        check("CC-03", js.get("recorded") and js.get("complete") == 1,
              f"graph_summary coverage.js_recon: {js} (expect one complete host)")
    elif stage == "lost":
        out = _summary()
        check("GL-01", out.get("warning") == "graph_data_missing" and out.get("liveGraphState") == "stable",
              f"graph_summary after the project's nodes were deleted: warning={out.get('warning')!r}, "
              f"graphDataMissing={out.get('graphDataMissing')}")
    elif stage == "import":
        with open(CVE_SNAPSHOT) as fh:
            before = json.load(fh)
        original, imported = _cve_links(other), _cve_links()
        count = lambda rows: sorted((r["id"], r["links"]) for r in rows)  # noqa: E731
        check("EX-01", original and count(imported) == count(original),
              f"INCLUDES_CVE links, imported {count(imported)} vs original {count(original)}")
        same = json.loads(json.dumps(imported, sort_keys=True, default=str))
        check("EX-02", [r["props"] for r in same] == [r["props"] for r in before],
              "linked CVE nodes' properties after the import equal the snapshot taken before the export")
    else:
        sys.exit(USAGE)


def js_recon_count():
    """JsReconFinding + Secret written by js_recon: what a run with no JS input must keep."""
    findings = q("MATCH (f:JsReconFinding) WHERE f.source = 'js_recon' RETURN count(f) AS n")
    secrets = q("MATCH (s:Secret) WHERE s.source = 'js_recon' RETURN count(s) AS n")
    return findings[0]["n"] + secrets[0]["n"]


DISPOSITIONS = ("reportable", "candidate", "info", "excluded")
AI_FP_BLOCKER = "AI review: likely false positive"


def listed(**filters):
    """Every finding list_findings returns, paged, and the last answer."""
    rows, offset = [], 0
    while True:
        out, err = mcp.call("list_findings", {"projectId": P, "limit": 100, "offset": offset, **filters})
        if err or not isinstance(out, dict):
            raise RuntimeError(f"list_findings failed: {json.dumps(out)[:500]}")
        rows += out.get("findings", [])
        offset += out.get("returned", 0)
        if not out.get("returned") or offset >= out.get("total", 0):
            return rows, out


def disposition_checks(stage):
    """Plan 10A, on the main project after its Priority Board run. `before`: as the
    run left it. `decided`: after e2e_fp.py --disposition-decide made a person's
    Real, a person's False positive and an external agent's false_positive review."""
    rows, _ = listed()
    by_id = {r["id"]: r for r in rows}
    bad = [r["id"] for r in rows if r.get("disposition") not in DISPOSITIONS
           or bool(r.get("blocker")) != (r.get("disposition") == "candidate")]
    check("D-01", rows and not bad, f"{len(rows)} findings; no disposition, or a blocker outside "
                                     f"candidates: {bad[:5]}")
    if stage == "before":
        public = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.public_client_key = true
                      RETURN s.id AS id, s.secret_type AS t""")
        aws = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.secret_type = 'AWS Access Key ID'
                   RETURN s.id AS id""")
        got_pub = sorted((r["t"], by_id.get(r["id"], {}).get("disposition")) for r in public)
        got_aws = sorted({(by_id.get(r["id"], {}).get("disposition"), by_id.get(r["id"], {}).get("blocker"))
                          for r in aws}, key=str)
        check("D-02", public and all(d == "info" for _, d in got_pub),
              f"public client keys: {got_pub} (expect info, whatever their tier)")
        check("D-03", aws and all(d == "candidate" and b for d, b in got_aws),
              f"AWS keys: {got_aws} (expect candidates that name a blocker)")
        sinks = q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dom_sink'
                     RETURN f.id AS id, f.severity AS sev""")
        quiet = sorted({by_id.get(r["id"], {}).get("disposition") for r in sinks if r["sev"] == "info"}, key=str)
        loud = sorted({by_id.get(r["id"], {}).get("disposition") for r in sinks
                       if r["sev"] in ("high", "critical")}, key=str)
        check("D-04", quiet == ["info"] and loud == ["candidate"],
              f"sourceless info sinks: {quiet} (expect info); high/critical sinks: {loud} (expect candidate)")
        proven = [r["id"] for r in rows if r["disposition"] == "reportable"]
        check("D-05", not proven, f"reportable with no proof and no verdict: {proven[:5]} (expect none)")
    else:
        mine = [r for r in rows if r.get("decidedVia") == "mcp"]
        real = [(r["id"], r["disposition"]) for r in mine if r.get("triage_status") == "confirmed"]
        noise = [(r["id"], r["disposition"]) for r in mine if r.get("triage_status") == "likely_noise"]
        check("D-06", real and all(d == "reportable" for _, d in real), f"a person's Real: {real} (expect reportable)")
        check("D-07", noise and all(d == "excluded" for _, d in noise),
              f"a person's False positive: {noise} (expect excluded)")
        ai = [(r["id"], r.get("sectionName"), r["disposition"], r.get("blocker")) for r in rows
              if r.get("reviewedBy") == "mcp" and r.get("triage_ai_verdict") == "false_positive"]
        if ai:
            check("D-08", all(s == "likely_false_positive" and d == "candidate" and b == AI_FP_BLOCKER
                              for _, s, d, b in ai),
                  f"an agent's false_positive review: {ai} (expect the board's false-positive section, "
                  f"still a candidate blocked by '{AI_FP_BLOCKER}', never excluded)")
        else:
            check("D-08 (not reviewed)", True, "no agent review on this project (the decide step's token "
                                               "lacks triage:review); nothing to judge")
    counted = {d: sum(1 for r in rows if r["disposition"] == d) for d in DISPOSITIONS}
    filtered = {d: listed(disposition=d)[1].get("total") for d in ("candidate", "info")}
    check("D-09", all(filtered[d] == counted[d] for d in filtered),
          f"filter totals {filtered} vs the unfiltered listing {counted}")
    print(f"CANDIDATES={counted['candidate']} REPORTABLE={counted['reportable']} INFO={counted['info']}")


EDGE_SCANNER = "a scanner's CDN check named an edge CDN"
NOT_IN_TARGET = "default certificate covers no target domain"
STEALTH_SKIP = "default certificate not checked (stealth mode)"
NO_443 = "default certificate not checked (port 443 not found open)"


#: The run's own rule, imported rather than restated: score_model is stdlib-only.
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "agentic"))
from cypherfix_triage import score_model as sm  # noqa: E402

TRIAGED_LABELS = ("Vulnerability", "Secret", "JsReconFinding", "MultiscannerFinding", "GithubSecret",
                  "GithubSensitiveFile", "ExploitGvm")


def _stored():
    """Every finding a triage run scored, with what the run stored."""
    rows = []
    for label in TRIAGED_LABELS:
        rows += [dict(r, label=label) for r in q(f"""
            MATCH (n:{label}) WHERE n.triage_run_id IS NOT NULL
            RETURN n.id AS id, n.source AS source, n.name AS name, n.secret_type AS st,
                   n.triage_state AS state, n.triage_status AS status, n.triage_source AS src,
                   n.triage_tier_rule AS rule, n.triage_tier_inputs AS inputs,
                   n.triage_disposition AS d, n.triage_blocker AS b, n.triage_model_version AS mv,
                   n.port_confirmed AS pc, n.control_check AS cc, n.evidence AS ev,
                   coalesce(n.triage_host, '') AS host
            LIMIT 5000""")]
    for r in rows:
        try:
            r["inputs"] = json.loads(r["inputs"]) if isinstance(r["inputs"], str) else (r["inputs"] or {})
        except ValueError:
            r["inputs"] = {}
        r["gates"] = r["inputs"].get("gates") if isinstance(r["inputs"].get("gates"), dict) else None
    return rows


def _rule_says(r):
    person = r["status"] if r["src"] == "human" and r["status"] in sm.DECISION_STATUSES else None
    return sm.disposition_of(r["state"] or "open", r["rule"] or "", person, sm.TierInputs.from_dict(r["inputs"]))


def disposition_stored_checks(stage):
    """Plan 10B, after a v3.10 Priority Board run. `before` and `decided` on the
    main project (as disposition_checks), `http-layer` on the plan-03 project,
    whose security checks record a control."""
    rows = _stored()
    check("B-00", rows and all(r["mv"] == sm.SCORE_MODEL_VERSION for r in rows),
          f"{len(rows)} scored findings, model versions {sorted({r['mv'] for r in rows}, key=str)} "
          f"(expect every one rescored by {sm.SCORE_MODEL_VERSION})")
    bad = [(r["id"], r["d"], r["b"]) for r in rows if r["d"] not in sm.DISPOSITIONS
           or bool(r["b"]) != (r["d"] == "candidate") or r["gates"] is None]
    check("B-01", rows and not bad, f"stored answers missing, malformed or without gates: {bad[:5]}")
    drift = [(r["id"], (r["d"], r["b"]), _rule_says(r)) for r in rows if (r["d"], r["b"]) != _rule_says(r)]
    check("B-02", not drift, f"stored answers the rule over the stored inputs disagrees with: {drift[:5]}")
    listed_rows, _ = listed()
    by_key = {(x["id"], x["label"]): (x.get("disposition"), x.get("blocker")) for x in listed_rows}
    differ = [(r["id"], (r["d"], r["b"]), by_key.get((r["id"], r["label"]))) for r in rows
              if by_key.get((r["id"], r["label"])) != (r["d"], r["b"])]
    check("B-03", not differ, f"list_findings shows another answer than the stored one: {differ[:5]}")

    counts = {}
    for r in rows:
        if r["d"] == "candidate":
            counts[r["b"]] = counts.get(r["b"], 0) + 1
    print("BLOCKERS=" + json.dumps(dict(sorted(counts.items(), key=lambda kv: -kv[1]))))

    if stage == "http-layer":
        api = [r for r in rows if r["source"] == "security_check" and r["cc"] == "passed"]
        check("B-04", api and all(r["gates"]["controlled"] is True for r in api),
              f"security checks whose control passed: {[(r['name'], r['gates']) for r in api]} "
              f"(expect controlled true)")
        return
    cache = [r for r in rows if r["source"] == "cache_poisoning"]
    secrets = [r for r in rows if r["label"] == "Secret"]
    check("B-04", cache and all(r["gates"]["controlled"] is True for r in cache)
          and secrets and all(r["gates"]["controlled"] is None for r in secrets),
          f"cache poisoning (control passed): {[(r['name'], r['gates']['controlled'], r['b']) for r in cache]}; "
          f"JS secrets (no control): {sorted({str(r['gates']['controlled']) for r in secrets})} "
          f"(expect true for the first, null for the second)")
    shodan = [r for r in rows if (r["source"] or "").lower() in sm.PASSIVE_CVE_SOURCES]
    pairs = sorted({(str(r["pc"]), str(r["gates"]["reachable_now"]), r["d"]) for r in shodan})
    want = {("True", "True"), ("False", "False"), ("None", "None")}
    check("B-05", shodan and all((p, g) in want for p, g, _ in pairs)
          and all(d == "excluded" for p, _, d in pairs if p == "False"),
          f"Shodan CVEs (port_confirmed, reachable now, disposition): {pairs} (expect the port scan to "
          f"decide: confirmed reachable, closed excluded, unscanned unknown)")
    tags = _ownership(sorted({sm._gate_name(r["host"]) for r in rows
                              if sm._gate_name(r["host"]).startswith(NET + ".")}))
    off = []
    for r in rows:
        tag = (tags.get(sm._gate_name(r["host"])) or {}).get("own")
        want = (False if tag == "shared_edge" else True if tag in ("unknown", "dedicated") else None)
        if r["host"] and sm._gate_name(r["host"]) in tags and r["gates"]["attributed"] is not want:
            off.append((r["id"], r["host"], tag, r["gates"]["attributed"]))
    check("B-06", tags and not off, f"findings whose attributed gate disagrees with their IP's tag "
                                    f"({sorted({(t or {}).get('own') for t in tags.values()}, key=str)}): {off[:5]}")
    if stage == "before":
        early = [(r["id"], r["d"]) for r in rows if r["d"] == "reportable"]
        check("B-07", not early, f"stored reportable with no proof and no verdict: {early[:5]} (expect none)")
    else:
        mine = {(x["id"], x["label"]): x for x in listed_rows}
        real = [(r["id"], r["d"]) for r in rows if r["src"] == "human" and r["status"] == "confirmed"]
        noise = [(r["id"], r["d"], r["b"]) for r in rows if r["src"] == "human" and r["status"] == "likely_noise"]
        ai = [(r["id"], r["d"], r["b"]) for r in rows
              if (mine.get((r["id"], r["label"])) or {}).get("reviewedBy") == "mcp" and r["state"] == "false_positive"]
        check("B-07", real and all(d == "reportable" for _, d in real)
              and noise and all(d == "excluded" and b is None for _, d, b in noise)
              and all(d == "candidate" and b == sm.BLOCKER_AI_FALSE_POSITIVE for _, d, b in ai),
              f"stored after the decisions: Real {real}, False positive {noise}, agent's FP review {ai} "
              f"(expect reportable; excluded with no blocker; a candidate blocked by the AI review)")
    out, err = mcp.call("graph_schema", {})
    text = json.dumps(out)
    names = ("triage_disposition", "triage_blocker", "reachable_now")
    check("B-08", not err and all(n in text for n in names),
          f"graph_schema mentions {[n for n in names if n in text]} (expect all of {list(names)})")


def _ownership(addresses):
    listed_ = ", ".join(f"'{a}'" for a in addresses)
    return {r["ip"]: r for r in q(f"""MATCH (i:IP) WHERE i.address IN [{listed_}]
                                     RETURN i.address AS ip, i.ownership AS own, i.ownership_reasons AS why,
                                            i.cdn_name AS cdn, i.is_cdn AS is_cdn, i.cdn_source AS src,
                                            i.default_cert_names AS certs, i.current_dns_names AS dns""")}


def _schema_lists_the_tag(case):
    out, err = mcp.call("graph_schema", {})
    text = json.dumps(out)
    names = ("ownership_reasons", "default_cert_names", "current_dns_names", "shodan_rdns")
    check(case, not err and all(n in text for n in names),
          f"graph_schema mentions {[n for n in names if n in text]} (expect all of {list(names)})")


def ip_ownership_checks():
    """Plan 11 on the IP-mode project: .32 behind a Cloudflare-issued certificate,
    .31 with the lab's own, .10 with no 443; the Shodan stub gives .31 and .32
    the same CVE."""
    ips = _ownership([f"{NET}.10", f"{NET}.31", f"{NET}.32"])
    edge, plain, web = (ips.get(f"{NET}.{n}") or {} for n in (32, 31, 10))
    check("O-01", edge.get("own") == "shared_edge" and edge.get("cdn") == "cloudflare"
          and EDGE_SCANNER in (edge.get("why") or []),
          f".32: {edge.get('own')} {edge.get('cdn')} {edge.get('why')} (expect shared_edge, cloudflare, "
          f"tlsx's CDN flag as the reason)")
    check("O-02", plain.get("own") == "unknown" and web.get("own") == "unknown",
          f".31: {plain.get('own')}, .10: {web.get('own')} (expect unknown: IP mode has no target domain, "
          f"so never dedicated, and never 'not ours')")
    check("O-03", plain.get("certs") == [f"*.{APEX}"] and NOT_IN_TARGET in (plain.get("why") or [])
          and edge.get("certs"),
          f"default certificates read without SNI: .31 {plain.get('certs')}, .32 {edge.get('certs')}")
    check("O-04", NO_443 in (web.get("why") or []) and not web.get("certs"),
          f".10 (no 443): {web.get('why')} {web.get('certs')} (expect not checked, no certificate)")
    check("O-05", [ips.get(f"{NET}.{n}", {}).get("dns") for n in (10, 31, 32)] == [0, 0, 0],
          f"current_dns_names: {[ips.get(f'{NET}.{n}', {}).get('dns') for n in (10, 31, 32)]} "
          f"(expect 0: the lab IPs have no PTR, and a Shodan PTR name is not this run's DNS)")
    cves = {r["ip"]: r["cves"] for r in q(f"""MATCH (i:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                                            WHERE v.source IN {PASSIVE} AND i.address IN ['{NET}.31', '{NET}.32']
                                            RETURN i.address AS ip, collect(DISTINCT v.name) AS cves""")}
    check("O-06", not cves.get(f"{NET}.32") and "CVE-2023-44487" in json.dumps(cves.get(f"{NET}.31")),
          f"Shodan CVEs: {cves} (expect none on the shared edge .32, CVE-2023-44487 on .31)")
    _schema_lists_the_tag("O-07")


def ip_ownership_stealth_checks(log_path):
    ips = _ownership([f"{NET}.31", f"{NET}.32"])
    edge, plain = ips.get(f"{NET}.32") or {}, ips.get(f"{NET}.31") or {}
    check("O-S1", all(STEALTH_SKIP in (r.get("why") or []) and not r.get("certs") for r in (edge, plain)),
          f".31 {plain.get('why')}, .32 {edge.get('why')} (expect 'not checked (stealth mode)', no certificate)")
    # The lab edge's only CDN signal is tlsx's certificate issuer, an active
    # handshake stealth turns off: with no evidence the tag stays unknown, never
    # "not ours". (A real CDN address is still a shared edge by its published
    # range, which needs no traffic; recon/tests/test_ip_attribution.py.)
    check("O-S2", edge.get("own") == "unknown" and plain.get("own") == "unknown",
          f".32 {edge.get('own')}, .31 {plain.get('own')} (expect unknown: no traffic, no edge evidence)")
    try:
        text = open(log_path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        text = f"<{e}>"
    line = next((ln for ln in text.splitlines() if "[IpAttribution]" in ln and "handshake" in ln), "")
    check("O-S3", "0 TLS handshake(s) without SNI (stealth mode: none)" in line,
          f"recon log: {line.strip() or 'no IpAttribution summary line'}")


NWLAB_WEB1, NWLAB_WEB2 = "192.88.99.60", "192.88.99.61"


def ip_ownership_nwlab_checks():
    """Plan 11 on the domain-mode project over the nested-wildcard lab: web1's
    default certificate covers nwlab.test; the Shodan stub answers a PTR name for
    web1 and a domain-DNS record pointing a Shodan-only name at web2."""
    web1 = _ownership([NWLAB_WEB1]).get(NWLAB_WEB1) or {}
    check("N-01", web1.get("own") == "dedicated" and "default certificate covers nwlab.test" in (web1.get("why") or [])
          and any(c.endswith(".nwlab.test") for c in web1.get("certs") or []),
          f"web1: {web1.get('own')} {web1.get('why')} {web1.get('certs')} (expect dedicated)")
    edges = {r["sub"]: r["src"] for r in q(f"""MATCH (s:Subdomain)-[r:RESOLVES_TO]->(i:IP)
                                             WHERE i.address IN ['{NWLAB_WEB1}', '{NWLAB_WEB2}']
                                             RETURN s.name AS sub, r.source AS src""")}
    check("N-02", edges.get("ptr.nwlab.test") == "shodan_rdns" and edges.get("shodan-only.nwlab.test") == "shodan_dns",
          f"Shodan-made edges: ptr {edges.get('ptr.nwlab.test')}, shodan-only {edges.get('shodan-only.nwlab.test')} "
          f"(expect shodan_rdns and shodan_dns)")
    forward = sorted(s for s, src in edges.items() if src is None)
    # The run resolves the apex even when it is no target (no Subdomain edge for
    # it), so the count may be one above the forward edges; the PTR name would
    # make it two above.
    dns = web1.get("dns")
    check("N-03", forward and isinstance(dns, int) and len(forward) <= dns <= len(forward) + 1,
          f"forward-DNS names {forward}, current_dns_names {dns} (expect the forward names, plus the apex at "
          f"most; never the PTR name)")


# --------------------------------------------------------------------------- audit cases
def _lab_log(container, since):
    """A lab host's request lines since `since` (its log names method, path, host
    and whether an Authorization header came, never a value)."""
    import subprocess
    out = subprocess.run(["docker", "logs", "--since", since, container], capture_output=True, text=True)
    return [ln for ln in (out.stdout + out.stderr).splitlines() if ln.startswith("[") and "listening on" not in ln]


ASSET_LABELS = ("IP", "Port", "Service", "BaseURL", "Endpoint", "Technology", "Vulnerability", "Certificate",
                "Subdomain", "Header")


def _nodes_naming(needles):
    """Asset nodes with any property naming one of `needles` (read whole, matched here)."""
    hits = []
    for label in ASSET_LABELS:
        for r in q(f"MATCH (n:{label}) RETURN properties(n) AS p"):
            text = json.dumps(r["p"], default=str)
            if any(x in text for x in needles):
                p = r["p"]
                hits.append((label, p.get("address") or p.get("url") or p.get("name") or p.get("id")))
    return hits


def roe_checks(since):
    """R-3: .11 excluded by `192.88.94.11/admin`, .12 by `192.88.94.12/`."""
    hits = _nodes_naming([f"{NET}.11", f"{NET}.12", "192-88-94-11", "192-88-94-12"])
    check("RoE-01", not hits, f"asset nodes naming an excluded host: {hits} (expect none)")
    ports = q(f"""MATCH (i:IP {{address: '{NET}.10'}})-[]->(p:Port) RETURN p.number AS n""")
    bases = q(f"""MATCH (b:BaseURL) WHERE b.url STARTS WITH 'http://{NET}.10' RETURN b.url AS u""")
    check("RoE-02", ports and bases, f".10 still scanned: ports {[r['n'] for r in ports]}, "
                                     f"BaseURLs {[r['u'] for r in bases]}")
    touched = {c: _lab_log(c, since) for c in ("redamon-fp-cloudflare", "redamon-fp-redirect")}
    check("RoE-03", not any(touched.values()),
          f"requests on the excluded hosts since {since}: { {c: v[:3] for c, v in touched.items()} } (expect none)")
    fastly = [ln for ln in _lab_log("redamon-fp-fastly", since) if "] GET " in ln]
    check("RoE-04", fastly, f"requests on .10 since {since}: {len(fastly)} GET lines (expect some)")
    refused = {}
    for entry in ("0.5", f"{NET}.11/33"):
        out, err = mcp.call("update_recon_settings", {"projectId": P, "settings": {"roeExcludedHosts": [entry]}})
        refused[entry] = bool(err) and "would exclude nothing" in json.dumps(out)
    out, err = mcp.call("update_recon_settings",
                        {"projectId": P, "settings": {"roeExcludedHosts": [f"{NET}.11/admin", f"{NET}.12/"]}})
    check("RoE-05", all(refused.values()) and not err,
          f"MCP validator: refused {refused} (expect both 'would exclude nothing'); the path-form list "
          f"accepted: {not err} {json.dumps(out)[:160] if err else ''}")


def roe_window_checks():
    """R-32: a window that excludes now refuses the start; the overnight one that
    contains now (e2e_fp.py set it, the run completed) is restored after."""
    import e2e_fp
    out, err = mcp.call("update_recon_settings", {"projectId": P, "settings": e2e_fp.roe_window(False)})
    if err:
        check("RoE-06", False, f"could not set the excluding window: {json.dumps(out)[:300]}")
        return
    out, err = mcp.call("start_recon", {"projectId": P, "mode": "new"})
    text = json.dumps(out)
    check("RoE-06", err and ("window" in text.lower() or "403" in text),
          f"start outside the window: refused={bool(err)} {text[:300]}")
    mcp.call("update_recon_settings", {"projectId": P, "settings": e2e_fp.roe_window(True)})


def r29_checks(since):
    """R-29: one relative path on two origins is two Endpoints; .21 gets none."""
    rows = q("""MATCH (b:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint {path: '/api/v1', method: 'GET'})
                RETURN b.url AS base, e.source AS source ORDER BY base""")
    bases = [r["base"] for r in rows]
    check("R29-01", bases == [f"http://{NET}.20", f"http://{NET}.22"],
          f"/api/v1 Endpoints by BaseURL: {rows} (expect one on .20 and one on .22, none on .21)")
    rows = q("""MATCH (f:JsReconFinding {finding_type: 'js_file'})-[:HAS_ENDPOINT]->(e:Endpoint {path: '/api/v1'})
                RETURN f.source_url AS js, e.baseurl AS base""")
    got = sorted((r["js"], r["base"]) for r in rows)
    own = (f"http://{NET}.20/static/js/r29.relative.js", f"http://{NET}.20")
    check("R29-02", own in got and not [g for g in got if g[0] == own[0] and g[1] != own[1]],
          f"js_file -> /api/v1: {got} (expect r29.relative.js's relative call on .20, after .21's absolute one)")
    client = [g for g in got if g[0] == f"http://{NET}.22/js/client.js"]
    if client:
        check("R29-02b", client == [(f"http://{NET}.22/js/client.js", f"http://{NET}.22")],
              f".22's client.js resolves its relative call against .22: {client}")
    else:
        # The crawl scopes each seed to its own host, so .20's cross-host script
        # tag for .22's client.js is not collected (like J-09's loader on .21).
        check("R29-02b (not crawled)", True, ".22/js/client.js was not collected by the crawl; nothing to judge")
    spa = [ln for ln in _lab_log("redamon-fp-spa", since) if "GET /static/js/r29.relative.js" in ln]
    vendor = [ln for ln in _lab_log("redamon-fp-vendor", since) if "/api/v1" in ln]
    check("R29-03", spa and not vendor,
          f"r29.relative.js served {len(spa)}x; .21 asked for /api/v1 {len(vendor)}x (expect 0)")


R43_REFUSED = ("[!][GraphQL] Refused 1 user-specified endpoint(s) outside the project scope; "
               f"no request and no credential sent to: {NET}.21")


def r43_checks(since, log_path):
    """R-43: the typed endpoint on .21 (outside the project) gets no request and no token."""
    text = open(log_path, errors="replace").read()
    check("R43-01", text.count(R43_REFUSED) == 1, f"refusal line in the recon log: {text.count(R43_REFUSED)}x (expect 1)")
    vendor = [ln for ln in _lab_log("redamon-fp-vendor", since) if "/graphql" in ln or "auth=yes" in ln]
    check("R43-02", not vendor, f".21 requests for /graphql or with a credential: {vendor[:3]} (expect none)")
    spa = [ln for ln in _lab_log("redamon-fp-spa", since) if f"POST /graphql host={NET}.20" in ln]
    check("R43-03", spa and all(ln.endswith("auth=yes") for ln in spa),
          f".20 got POST /graphql {len(spa)}x, with a credential each: {spa[:2]}")
    gaps = q("""MATCH (d:Domain) WHERE d.name STARTS WITH 'ip-targets.' RETURN d.recon_coverage_gaps AS g""")
    listed = [g for r in gaps for g in json.loads(r["g"] or "[]")
              if g.get("source") == "roe_excluded" and g.get("module") == "graphql_scan"]
    check("R43-04", listed and any(g.get("skipped") == 1 or g.get("hosts") == 1 for g in listed),
          f"roe_excluded gap for graphql_scan: {listed}")


def nuclei_throttle_checks(jsonl_path):
    """R-19: "please wait" copy on a served page no longer hides a finding; a
    non-timing template's match on a throttled (429) host is kept."""
    rows = q("""MATCH (v:Vulnerability) WHERE v.source = 'nuclei'
                RETURN v.template_id AS t, coalesce(v.matched_at, v.url, v.host) AS at""")
    on = lambda ip, tid: [r for r in rows if r["t"] == tid and f"{NET}.{ip}" in (r["at"] or "")]
    check("N19-01", on(37, "git-config"), f"git-config on the please-wait host .37: {on(37, 'git-config')}")
    check("N19-02", on(38, "http-missing-security-headers"),
          f"a non-timing template on the throttled host .38 is kept: {on(38, 'http-missing-security-headers')[:2]}")
    check("N19-03", not on(38, "git-config"), f"no git-config on the 429 host: {on(38, 'git-config')}")
    recon = os.path.join(HERE, "..", "..", "..", "recon", "output", f"recon_{P}.json")
    fps = ((json.load(open(recon)).get("vuln_scan") or {}).get("false_positives") or []) if os.path.exists(recon) else None
    named = [f for f in (fps or []) if "git-config" in json.dumps(f)]
    check("N19-04", fps is not None and not named,
          f"vuln_scan.false_positives: {len(fps) if fps is not None else 'no recon file'} entries, "
          f"git-config among them: {len(named)} (expect 0)")
    heads = []
    if jsonl_path and os.path.exists(jsonl_path):
        # A nuclei_detection.jsonl, or the recon log, which echoes each of its
        # lines as "[*][Nuclei][DETECTION] {...}".
        for ln in open(jsonl_path, errors="replace"):
            if "{" not in ln or ("[Nuclei][" in ln and "{" not in ln.split("]", 3)[-1]):
                continue
            try:
                line = json.loads(ln[ln.index("{"):])
            except ValueError:
                continue
            if isinstance(line, dict) and line.get("template-id"):   # not a progress/stats line
                heads.append((line.get("response") or "")[:12])
    raw = [h for h in heads if h.startswith("HTTP/1.1 ")]
    check("N19-05", heads and len(raw) == len(heads),
          f"Nuclei JSONL lines: {len(heads)}, with a raw 'HTTP/1.1 ...' response head: {len(raw)} "
          f"(the throttle rule parses it; none means the rule is dead code)")


def redis_checks(stage):
    """R-24: open -> redis_no_auth; delay -> kept + a coverage gap; auth -> pruned."""
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'redis_no_auth'
                 RETURN v.id AS id, v.matched_ip AS ip, v.stale_since AS stale, toString(v.updated_at) AS seen""")
    gaps = q("""MATCH (d:Domain) WHERE d.recon_coverage_gaps IS NOT NULL RETURN d.recon_coverage_gaps AS g""")
    listed = [g for r in gaps for g in json.loads(r["g"] or "[]")
              if g.get("source") == "security_check" and "redis_no_auth" in json.dumps(g)]
    if stage == "open":
        check("RD-01", len(rows) == 1 and rows[0]["ip"] == f"{NET}.39", f"redis_no_auth on .39: {rows}")
        check("RD-02", not listed, f"no security_check gap for redis_no_auth: {listed}")
    elif stage == "delay":
        check("RD-03", len(rows) == 1, f"PING answered past the timeout: the finding is kept: {rows}")
        check("RD-04", listed, f"security_check coverage gap naming redis_no_auth: {listed}")
    elif stage == "auth":
        check("RD-05", not rows, f"NOAUTH is a verdict: the finding is pruned: {rows}")
        check("RD-06", not listed, f"no gap once Redis answered: {listed}")
    else:
        sys.exit(USAGE)


# --------------------------------------------------------------------------- recon-audit cases, round 2
def _all_gaps():
    rows = q("""MATCH (d:Domain) WHERE d.recon_coverage_gaps IS NOT NULL
                RETURN d.recon_coverage_gaps AS g, d.recon_skipped_hosts AS sk""")
    return ([g for r in rows for g in json.loads(r["g"] or "[]")],
            sorted({h for r in rows for h in (r.get("sk") or [])}))


def _gaps(source=None, module=None, reason=None):
    return [g for g in _all_gaps()[0] if (source is None or g.get("source") == source)
            and (module is None or g.get("module") == module)
            and (reason is None or reason in str(g.get("reason") or ""))]


def _recon_json():
    path = os.path.join(HERE, "..", "..", "..", "recon", "output", f"recon_{P}.json")
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return None


def _log_text(path):
    return open(path, errors="replace").read() if path and os.path.exists(path) else ""


def _http_lines(container, since):
    return [ln for ln in _lab_log(container, since) if any(f"] {m} " in ln for m in ("GET", "POST", "HEAD"))]


def _tool_lifetimes(prefix, since):
    """(name, seconds from start to die) of each container named `prefix`* that
    started since `since`, from the Docker event log. The daemon keeps only its
    last events, so run this right after the run."""
    import subprocess
    import datetime as dt
    out = subprocess.run(["docker", "events", "--since", since, "--until", "0s", "--filter", "type=container",
                          "--format", "{{json .}}"], capture_output=True, text=True).stdout
    starts, ends = {}, {}
    for ln in out.splitlines():
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        name = (ev.get("Actor") or {}).get("Attributes", {}).get("name", "")
        if not name.startswith(prefix):
            continue
        t = ev.get("timeNano", 0) / 1e9
        if ev.get("Action") == "start":
            starts[name] = t
        elif ev.get("Action") in ("die", "kill") and name not in ends:
            ends[name] = t
    return [(n, round(ends[n] - starts[n], 1) if n in ends else None) for n in sorted(starts)]


def _updated(rows):
    return [str(r.get("seen") or "") for r in rows]


def probefail_checks(stage, since, log_path=None):
    """R-21 (and R-9's tlsx kill): .40's expired certificate on 993, Nuclei and
    the header checks on 80, through a stalled handshake and a failed httpx."""
    tls = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'tls_expired'
                AND v.matched_ip = '{NET}.40' RETURN v.id AS id, v.url AS url, toString(v.updated_at) AS seen""")
    # The header checks read HTTPS only: on .40's port 80 the web findings are
    # Nuclei's missing-headers template and the direct-IP-over-HTTP check.
    web = q(f"""MATCH (v:Vulnerability) WHERE (v.source = 'nuclei' OR (v.source = 'security_check'
                AND v.type = 'direct_ip_http')) AND coalesce(v.matched_at, v.url, '') CONTAINS '{NET}.40'
                RETURN v.id AS id, v.source AS src, v.type AS t, toString(v.updated_at) AS seen""")
    log = _log_text(log_path)
    on993 = [r for r in tls if ":993" in (r["url"] or "")]
    if stage == "baseline":
        check("PF-01", len(on993) == 1, f"tls_expired on .40:993 (only tlsx reads it): {tls}")
        check("PF-02", any(r["src"] == "nuclei" for r in web) and any(r["src"] == "security_check" for r in web),
              f"Nuclei and security-check findings on .40:80: {sorted({(r['src'], str(r['t'])) for r in web})}")
    elif stage == "stall":
        check("PF-03", len(on993) == 1 and all(s < since for s in _updated(on993)),
              f"tls_expired kept, not re-written, through a tlsx run cut at its timeout: {on993}")
        gaps = _gaps("security_check", "tlsx", "tlsx timed out after 20s")
        check("PF-04", gaps, f"security_check gap from tlsx naming its timeout: {gaps or _all_gaps()[0]}")
        check("PF-05", "tlsx timed out after 20s" in log or not log_path,
              "recon log says tlsx timed out after 20s")
        kept = _tool_lifetimes("tlsx-", since)
        check("PF-06 (R-9)", kept and all(t is not None and t <= 30 for _, t in kept),
              f"tlsx containers (start -> die, s; the run timeout is 20 s): {kept} (expect each gone by 30 s)")
    elif stage == "httpx":
        rj = _recon_json() or {}
        meta = rj.get("metadata") or {}
        check("PF-07", "SKIPPING ACTIVE SCANS: http_probe failed (" in log,
              "recon log: SKIPPING ACTIVE SCANS: http_probe failed (...)")
        check("PF-08", (meta.get("phase_errors") or {}).get("http_probe")
              and "http_probe" not in (meta.get("modules_executed") or []),
              f"phase_errors.http_probe={str((meta.get('phase_errors') or {}).get('http_probe'))[:80]!r}, "
              f"modules_executed={meta.get('modules_executed')}")
        check("PF-09", web and all(s < since for s in _updated(web)),
              f"run-1 Nuclei and header findings kept untouched: {sorted({(r['src'], str(r['t']), r['seen'][:19]) for r in web})}")
        why = "http_probe failed, no host probed"
        named = {g.get("source") for g in _all_gaps()[0]
                 if why in str(g.get("reason") or "") or g.get("source") == "http_probe"}
        check("PF-10", {"http_probe", "nuclei", "security_check"} <= named,
              f"sources with a gap ({why!r} or httpx's own): {sorted(named)}")
        hits = _http_lines("redamon-fp-tlsmail", since)
        check("PF-11", not hits, f"HTTP requests on .40 while httpx had failed: {hits[:3]} (expect none: no Nuclei)")
    elif stage == "healthy":
        check("PF-12", not on993, f"a renewed certificate prunes tls_expired: {on993}")
        check("PF-13", web and all(s >= since for s in _updated(web)),
              f"Nuclei and header findings re-checked: {sorted({(r['src'], str(r['t']), r['seen'][:19]) for r in web})}")
        left = [g for g in _all_gaps()[0] if g.get("module") == "tlsx" or g.get("source") == "http_probe"]
        check("PF-14", not left, f"no tlsx or httpx gap on a healthy run: {left}")
    else:
        sys.exit(USAGE)


def secchk_checks(since):
    """L-20 SMTP relay, L-21 login form over HTTP, L-7 no header check off the host."""
    relay = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'smtp_open_relay'
                 RETURN coalesce(v.matched_ip, v.ip, v.matched_at, v.url) AS at""")
    at = sorted(str(r["at"]) for r in relay)
    check("SC-01 (L-20)", len(at) == 1 and f"{NET}.42" in at[0],
          f"smtp_open_relay: {at} (expect .42 only: .41 refuses with 554 after a split greeting, .43 greylists)")
    grey = [g for g in _gaps("security_check") if "smtp_open_relay" in json.dumps(g)]
    check("SC-02 (L-20)", grey and "451" in json.dumps(grey),
          f"security_check gap for the greylisted server: {grey}")
    login = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'login_no_https'
                 RETURN v.url AS url, v.control_check AS cc, v.evidence AS ev""")
    check("SC-03 (L-21)", len(login) == 1 and f"{NET}.45/login" in (login[0]["url"] or "")
          and login[0]["cc"] == "passed"
          and login[0]["ev"] == "Login form with password field found on HTTP; control_check: passed",
          f"login_no_https: {login} (expect .45/login only; not .44's shell without a password field, "
          f"not .46's catch-all)")
    import re as _re
    ctl = [ln for ln in _lab_log("redamon-fp-login-real", since) if _re.search(r"GET /\S*rdm-[0-9a-f]{12}", ln)]
    check("SC-04 (L-21)", len(ctl) >= 1, f".45 control requests (/…rdm-<hex>): {len(ctl)} {ctl[:2]}")
    page = lambda t: t.startswith(("missing_", "session_no_")) or t in (
        "cache_control_missing", "csp_unsafe_inline", "insecure_form_action")
    sso = [r["t"] for r in q(f"""MATCH (v:Vulnerability) WHERE v.source = 'security_check'
                                  AND v.url CONTAINS '{NET}.48' RETURN v.type AS t""") if page(r["t"])]
    own = [r["t"] for r in q(f"""MATCH (v:Vulnerability) WHERE v.source = 'security_check'
                                  AND v.url CONTAINS '{NET}.24' RETURN v.type AS t""") if page(r["t"])]
    check("SC-05 (L-7)", not sso and own,
          f"page findings on .48 (HTTPS 302 to .21): {sso} (expect none); on .24 (HTTPS 302 to its own "
          f"/login): {sorted(own)} (expect some)")
    # The direct-IP redirect analysis (_analyze_redirect_chain, outside L-7)
    # still follows .48's 302 once per scheme; the five page checks, which
    # followed it too before L-7, would add one request each.
    vendor = _http_lines("redamon-fp-vendor", since)
    check("SC-06 (L-7)", len(vendor) <= 2 and all("GET /saml/login" in ln for ln in vendor),
          f"requests on .21 (outside the project) since {since}: {len(vendor)} {vendor[:3]} (expect at most "
          f"the redirect analysis's one per scheme, none from the page checks)")


def redis_nohttp_checks(stage, extra=None):
    """R-22: with no live URL the port checks still run and keep their verdicts."""
    rows = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'redis_no_auth'
                RETURN v.id AS id, v.matched_ip AS ip""")
    meta = (_recon_json() or {}).get("metadata") or {}
    if stage in ("open", "rerun"):
        check("RN-01", meta.get("active_scans_skipped") is True,
              f"active_scans_skipped={meta.get('active_scans_skipped')} ({meta.get('active_scans_skip_reason')})")
        check("RN-02", len(rows) == 1 and rows[0]["ip"] == f"{NET}.39", f"redis_no_auth with no live URL: {rows}")
        not_run = sorted({g.get("source") for g in _gaps(reason="not run: no live HTTP URL")})
        redis_gap = [g for g in _gaps("security_check") if "redis_no_auth" in json.dumps(g)]
        check("RN-03", "nuclei" in not_run and not redis_gap,
              f"sources noted 'not run: no live HTTP URL': {not_run}; redis_no_auth gap: {redis_gap}")
        if stage == "open":
            pings = [ln for ln in _lab_log("redamon-fp-redis", extra) if "PING mode=open" in ln] if extra else []
            # The stand-in on 6379 logs "mode=", the toggle on 80 "host= ... auth=".
            web = [ln for ln in _http_lines("redamon-fp-redis", extra) if "auth=" in ln] if extra else []
            check("RN-04", pings and not web, f"PINGs on 6379: {len(pings)}; HTTP requests on :80 (Nuclei, "
                                             f"crawlers): {web[:3]} (expect none)")
            print(f"REDIS_FINDING_ID={rows[0]['id'] if rows else ''}")
        else:
            check("RN-05", rows and rows[0]["id"] == extra, f"same finding id on a rerun: {rows} vs {extra}")
    elif stage == "auth":
        check("RN-06", not rows, f"NOAUTH is a verdict with no live URL too: pruned: {rows}")
    else:
        sys.exit(USAGE)


PHASE_A = ("vuln_scan", "vhost_sni", "cache_scan", "origin_discovery", "graphql_scan", "port_scan")


def fanout_checks(log_path):
    """R-31: every Phase A tool ran, and no shared-snapshot race."""
    meta = (_recon_json() or {}).get("metadata") or {}
    ran = meta.get("modules_executed") or []
    check("FO-01", all(m in ran for m in PHASE_A), f"modules_executed: {ran} (expect {list(PHASE_A)})")
    errs = json.dumps(meta.get("phase_errors") or {})
    check("FO-02", "changed size" not in errs, f"phase_errors: {errs[:300]}")
    log = _log_text(log_path)
    bad = [w for w in ("changed size", "vuln_scan failed", "Enrichment failed") if w in log]
    check("FO-03", log and not bad, f"recon log lines naming a race or a failed tool: {bad}")


def _map_rows():
    return q("""MATCH (f:JsReconFinding) WHERE f.finding_type IN ['source_map_exposure', 'source_map_reference']
                RETURN f.source_url AS js, f.finding_type AS t, f.severity AS sev, f.map_url AS map,
                       f.fetch_result AS fr, f.first_party_files AS fp""")


def r14_checks(since, log_path=None):
    """R-14: a source map (or a map URL's redirect) off the run's hosts is never fetched."""
    m = {r["js"].rsplit("/", 1)[-1]: r for r in _map_rows()}
    vendor = _http_lines("redamon-fp-vendor", since)
    check("R14-01", not [ln for ln in vendor if ".map" in ln], f".map requests on .21: {vendor[:3]} (expect none)")
    r = m.get("r14.offhost.4d1e.js")
    check("R14-02", r and r["t"] == "source_map_reference" and r["fr"] == "out_of_scope"
          and f"{NET}.21" in (r["map"] or ""), f"map named on .21: {r}")
    check("R14-03", "r14.bounce.5e2f.js" not in m, f"map URL redirecting to .21: {m.get('r14.bounce.5e2f.js')}")
    r = m.get("r14.moved.6f3a.js")
    check("R14-04", r and r["t"] == "source_map_exposure", f"map URL redirecting to another .20 path: {r}")
    r = m.get("main.4f2a9c.js")
    check("R14-05 (M-01)", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 2,
          f"the first-party map is unchanged: {r}")
    if log_path:
        import re as _re
        hit = _re.search(r"Source-map requests not sent \(hop guard\): out_of_scope (\d+)", _log_text(log_path))
        check("R14-06", hit and int(hit.group(1)) >= 1, f"hop-guard summary line: {hit.group(0) if hit else None}")


def _timed_http_lines(container, since):
    """(epoch seconds, line) of a lab host's request lines since `since`."""
    import subprocess
    import datetime as dt
    out = subprocess.run(["docker", "logs", "--timestamps", "--since", since, container],
                         capture_output=True, text=True)
    rows = []
    for ln in (out.stdout + out.stderr).splitlines():
        stamp, _, rest = ln.partition(" ")
        if not any(f"] {m} " in rest for m in ("GET", "POST", "HEAD")):
            continue
        t = dt.datetime.fromisoformat(stamp[:26].rstrip("Z") + "+00:00").timestamp()
        rows.append((t, rest))
    return rows


def r14js_checks(since, log_path):
    """R-14 (downloads): a .20 bundle redirecting to the RoE-excluded .21 is not
    followed by JS Recon; one moving to another .20 path is analysed. The crawl
    (GROUP 5) fetches the bundle before JS Recon (GROUP 5b) does, so a .21
    request right after .20's LAST answer for the bundle would be JS Recon's
    (R14J-01); any .21 request at all breaks the RoE (R14J-05)."""
    bundle = "GET /static/js/r14js.offhost.7a8b.js"
    asked = [t for t, ln in _timed_http_lines("redamon-fp-spa", since) if bundle in ln]
    vendor = [(t, ln) for t, ln in _timed_http_lines("redamon-fp-vendor", since) if "GET /loader.js" in ln]
    last = max(asked) if asked else None
    js_recon = [ln for t, ln in vendor if last is not None and last <= t <= last + 2]
    check("R14J-01", asked and not js_recon,
          f".20 served the redirecting bundle {len(asked)}x; .21 requests right after the last (JS Recon's): "
          f"{js_recon} (expect none)")
    check("R14J-05", not vendor, f"requests on .21 (RoE-excluded) during the run: {[ln for _, ln in vendor][:3]} "
                                 f"(expect none: an excluded host gets no request)")
    log = _log_text(log_path)
    check("R14J-02", "blocked (RoE exclusion)" in log and "[-][RoE] js_recon: not sent to" in log,
          "recon log: 'blocked (RoE exclusion)' and '[-][RoE] js_recon: not sent to ...'")
    moved = q("""MATCH (f:JsReconFinding) WHERE f.source_url CONTAINS 'r14js.'
                 RETURN f.finding_type AS t, f.source_url AS u""")
    eps = q(f"""MATCH (e:Endpoint) WHERE e.path = '/api/r14js/moved' RETURN e.baseurl AS b""")
    check("R14J-03", moved or eps, f"the moved bundle was analysed: findings {moved[:4]}, endpoints {eps}")
    off = [r for r in moved if "offhost" in (r["u"] or "")]
    check("R14J-04", not [r for r in off if r["t"] != "js_file"], f"nothing analysed from the .21 redirect: {off}")


def graphql_rate_checks(since):
    """R-7: graphqlRateLimit 0 under a 2 rps ceiling runs at 2 requests a second at most."""
    import subprocess
    out, err = mcp.call("preflight_scope_check", {"projectId": P})
    rates = (out or {}).get("resolvedRates") or [] if isinstance(out, dict) else []
    entry = next((x for x in rates if x.get("field") == "graphqlRateLimit"), None)
    check("GQ-01", not err and entry and entry.get("written") == 0,
          f"preflight lists graphqlRateLimit as written: {entry}")
    check("GQ-02", entry and entry.get("resolved") == 2 and entry.get("capped") is True,
          f"graphqlRateLimit 0 (unlimited) under a 2 rps ceiling resolves to 2, capped: {entry}")
    logs = subprocess.run(["docker", "logs", "--timestamps", "--since", since, "redamon-fp-graphql"],
                          capture_output=True, text=True)
    per_s = {}
    for ln in (logs.stdout + logs.stderr).splitlines():
        if "] POST /graphql" in ln:
            per_s[ln[:19]] = per_s.get(ln[:19], 0) + 1
    worst = max(per_s.values()) if per_s else 0
    check("GQ-03", sum(per_s.values()) >= 3 and worst <= 2, f"POST /graphql: {sum(per_s.values())} in {len(per_s)} s, "
                                         f"busiest second {worst} (expect <= 2)")


def graphql_cop_checks(stage, since, log_path=None):
    """R-42: graphql-cop never runs in stealth or with a DoS test excluded."""
    started = _tool_lifetimes("graphql-cop-", since)
    import subprocess
    ev = subprocess.run(["docker", "events", "--since", since, "--until", "0s", "--filter", "type=container",
                         "--filter", "image=dolevf/graphql-cop:1.14", "--filter", "event=start",
                         "--format", "{{.Actor.Attributes.name}}"], capture_output=True, text=True).stdout.split()
    # The writer stamps graphql_cop_scanned_at for a run that executed
    # (graphql_cop_ran stays in the recon JSON); Endpoints are rebuilt per run.
    ran = q("""MATCH (e:Endpoint) WHERE e.graphql_cop_ran = true OR e.graphql_cop_scanned_at IS NOT NULL
               RETURN e.baseurl AS b, e.path AS p""")
    if stage in ("stealth", "dos-off"):
        check(f"GC-{stage}", not ev and not ran, f"graphql-cop containers: {ev or started}; "
                                                  f"Endpoints graphql-cop scanned: {ran} (expect none)")
        if stage == "dos-off":
            check("GC-dos-off log", "denial-of-service test(s) excluded" in _log_text(log_path),
                  "recon log: Skipping ... denial-of-service test(s) excluded")
    elif stage == "ran":
        check("GC-ran", ev and ran, f"graphql-cop containers: {len(ev)}; Endpoints graphql-cop scanned: {ran}")
    else:
        sys.exit(USAGE)


def vhost_drop_checks(since, log_path):
    """R-46 run 2: .10's baseline fails, so its vhost findings are kept, not re-written."""
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{NET}.10'
                 RETURN v.hostname AS h, v.id AS id, toString(v.updated_at) AS seen ORDER BY h""")
    names = sorted(r["h"] for r in rows)
    want = sorted(f"{w}.{APEX}" for w in ("admin", "dev-api", "dev.api", "wiki"))
    check("VD-01", names == want and all(s < since for s in _updated(rows)),
          f".10 findings kept from run 1: {[(r['h'], r['seen'][:19]) for r in rows]}")
    gaps = _gaps("vhost_sni_enum")
    skipped = _all_gaps()[1]
    log = _log_text(log_path)
    line = f"[!][VhostSni] IP {NET}.10:80 (http) baseline failed -- skipping port"
    check("VD-02", gaps and (f"{NET}.10:80" in skipped or line in log),
          f"vhost_sni_enum gap: {gaps}; recon_skipped_hosts: {skipped}; log line: {line in log}")
    others = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip IN ['{NET}.11', '{NET}.14']
                   RETURN v.ip AS ip, toString(v.updated_at) AS seen""")
    check("VD-03", others and all(s >= since for s in _updated(others)), f".11/.14 refreshed: {others}")


def cache_checks(stage, since, log_path=None):
    """R-23 / R-9: a stalled cache scan keeps C-01 and says why; WCVS is stopped."""
    rows = q("""MATCH (v:Vulnerability) WHERE v.source = 'cache_poisoning'
                AND coalesce(v.endpoint_url, v.url, v.matched_at, '') CONTAINS '/home'
                RETURN v.id AS id, toString(v.updated_at) AS seen""")
    gaps = _gaps("cache_poisoning", "cache_scan")
    if stage == "stall":
        check("CS-01", rows and all(s < since for s in _updated(rows)), f"C-01 kept, not re-written: {rows}")
        check("CS-02", any("no answer" in str(g.get("reason")) for g in gaps), f"cache_scan gaps: {gaps}")
        check("CS-03 (R-9)", any("WCVS timed out after 60s" in str(g.get("reason")) for g in gaps),
              f"WCVS timeout gap: {gaps}")
        log = _log_text(log_path)
        check("CS-04", "not fully tested (no answer)" in log and "WCVS timed out after 60s" in log,
              "recon log: '... not fully tested (no answer)' and 'WCVS timed out after 60s'")
        stalled = [ln for ln in _lab_log("redamon-fp-cache", since) if "stalled GET /home ua=RedAmon-CachePoison" in ln]
        check("CS-05", stalled, f".15 stalled the cache scanner's /home: {len(stalled)}x")
        wcvs = _tool_lifetimes("wcvs-", since)
        check("CS-06 (R-9)", wcvs and all(t is not None and t <= 70 for _, t in wcvs),
              f"wcvs containers (start -> die, s; timeout 60 s): {wcvs} (expect each gone by 70 s)")
    elif stage == "open":
        check("CS-07", rows and all(s >= since for s in _updated(rows)), f"C-01 re-checked: {rows}")
        # .11's TLS edge refuses the scanner on every run (a gap of its own);
        # the stalled host and WCVS must be clean.
        targets = ((_recon_json() or {}).get("cache_scan") or {}).get("by_target") or {}
        cut15 = {u: t.get("unchecked") for u, t in targets.items()
                 if f"{NET}.15" in u and isinstance(t, dict) and t.get("unchecked")}
        check("CS-08", not [g for g in gaps if "WCVS" in str(g.get("reason"))] and not cut15,
              f"no WCVS gap and no .15 URL left unchecked: gaps {gaps}, .15 unchecked {cut15}")
    else:
        sys.exit(USAGE)


EPAI_Q1 = """MATCH (e:Endpoint) RETURN e.baseurl AS b, e.path AS path, e.method AS m, e.category AS cat,
             e.urls_found AS n, e.source AS src, e.sources AS srcs, e.ai_interface_type AS ai ORDER BY b, path, m"""
EPAI_Q2 = """MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter) RETURN DISTINCT p.baseurl AS b,
             p.endpoint_path AS path, p.name AS name, p.position AS pos, p.category AS cat,
             p.sample_values AS sv, p.is_ai_prompt_injectable AS inj ORDER BY b, path, name"""


def epai_checks(stage, path, host=None):
    """R-27: a partial EndpointAiClassifier writes only AI fields, only on its run's hosts."""
    snap = {"q1": q(EPAI_Q1), "q2": q(EPAI_Q2),
            "counts": q("MATCH (e:Endpoint) RETURN count(e) AS e") + q("MATCH (p:Parameter) RETURN count(p) AS p")}
    if stage == "snapshot":
        json.dump(snap, open(path, "w"), default=str)
        hosts = sorted({r["b"] for r in snap["q2"] if r.get("sv")})
        print(f"EPAI_SNAPSHOT={path} endpoints={len(snap['q1'])} params={len(snap['q2'])} hosts_with_samples={hosts}")
        return
    before = json.load(open(path))
    key = lambda r: (r["b"], r["path"], r.get("m") or r.get("name"))
    b1 = {key(r): r for r in before["q1"]}
    a1 = {key(r): r for r in json.loads(json.dumps(snap["q1"], default=str))}
    check("EP-01", json.dumps(before["counts"]) == json.dumps(snap["counts"], default=str),
          f"node counts: {before['counts']} -> {snap['counts']}")
    fixed = ("cat", "n", "src", "srcs")
    changed = [(k, f, b1[k].get(f), a1[k].get(f)) for k in b1 if k in a1 for f in fixed
               if b1[k].get(f) != a1[k].get(f)]
    check("EP-02", not changed, f"cat/urls_found/source/sources changed: {changed[:4]}")
    on_h = [(k, b1[k].get("ai"), a1[k].get("ai")) for k in b1 if k in a1 and host and host in k[0]
            and b1[k].get("ai") != a1[k].get("ai")]
    check("EP-03", not on_h, f"the RoE-excluded host's endpoints untouched (ai): {on_h[:4]}")
    tagged = [k for k in b1 if k in a1 and not (host and host in k[0]) and b1[k].get("ai") is None
              and a1[k].get("ai") is not None]
    if tagged:
        check("EP-04", True, f"other hosts' endpoints newly typed by the classifier: {len(tagged)} {tagged[:3]}")
    else:
        # The rules-only classifier types AI-interface paths and prompt
        # parameters; the main project has none, so it annotates nothing.
        check("EP-04 (not exercised)", True, "the classifier typed no endpoint (no AI-interface path in the lab)")
    b2 = {key(r): r for r in before["q2"]}
    a2 = {key(r): r for r in json.loads(json.dumps(snap["q2"], default=str))}
    p_changed = [(k, f) for k in b2 if k in a2 for f in ("pos", "sv", "cat")
                 if b2[k].get(f) != a2[k].get(f)]
    p_host = [k for k in b2 if k in a2 and host and host in k[0] and b2[k] != a2[k]]
    check("EP-05", not p_changed and not p_host and set(b2) == set(a2),
          f"Parameter position/sample_values/category changed: {p_changed[:4]}; on the excluded host: {p_host[:3]}")


def userinput_checks(tool):
    """L-11: a partial run marks its own UserInput nodes completed, with their PRODUCED edges."""
    rows = q(f"""MATCH (ui:UserInput {{tool_id: '{tool}'}})
                 RETURN ui.id AS id, ui.status AS status, toString(ui.completed_at) AS done,
                        size([(ui)-[:PRODUCED]->(x) | x]) AS produced""")
    print(f"USERINPUT={json.dumps(rows)}")
    check("UI-01", rows and all(r["status"] == "completed" and r["done"] and r["produced"] >= 1 for r in rows),
          f"UserInput nodes of {tool}: {rows}")


def upload_sink_checks(name):
    """L-1: a partial JS Recon run on an upload alone writes its DOM sink."""
    rows = q(f"""MATCH (f:JsReconFinding {{finding_type: 'js_file'}}) WHERE f.source_url CONTAINS '{name}'
                 OPTIONAL MATCH (f)-[]->(s:JsReconFinding {{finding_type: 'dom_sink'}})
                 RETURN f.source_url AS u, collect(s.title) AS sinks""")
    check("UP-01", rows and any(r["sinks"] for r in rows), f"uploaded bundle's js_file node and its sinks: {rows}")

if len(sys.argv) > 2:
    if sys.argv[2] == "--probefail" and len(sys.argv) in (5, 6):
        probefail_checks(sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) == 6 else None)
        sys.exit(report())
    if sys.argv[2] == "--secchk" and len(sys.argv) == 4:
        secchk_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--redis-nohttp" and len(sys.argv) in (4, 5):
        redis_nohttp_checks(sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else None)
        sys.exit(report())
    if sys.argv[2] == "--fanout" and len(sys.argv) == 4:
        fanout_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--r14" and len(sys.argv) in (4, 5):
        r14_checks(sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else None)
        sys.exit(report())
    if sys.argv[2] == "--r14js" and len(sys.argv) == 5:
        r14js_checks(sys.argv[3], sys.argv[4])
        sys.exit(report())
    if sys.argv[2] == "--graphql-rate" and len(sys.argv) == 4:
        graphql_rate_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--graphql-cop" and len(sys.argv) in (5, 6):
        graphql_cop_checks(sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) == 6 else None)
        sys.exit(report())
    if sys.argv[2] == "--vhost-drop" and len(sys.argv) == 5:
        vhost_drop_checks(sys.argv[3], sys.argv[4])
        sys.exit(report())
    if sys.argv[2] == "--cache" and len(sys.argv) in (5, 6):
        cache_checks(sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) == 6 else None)
        sys.exit(report())
    if sys.argv[2] == "--epai" and len(sys.argv) in (5, 6):
        epai_checks(sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) == 6 else None)
        sys.exit(0 if sys.argv[3] == "snapshot" else report())
    if sys.argv[2] == "--userinput" and len(sys.argv) == 4:
        userinput_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--upload-sink" and len(sys.argv) == 4:
        upload_sink_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--ip-ownership" and len(sys.argv) == 3:
        ip_ownership_checks()
        sys.exit(report())
    if sys.argv[2] == "--roe" and len(sys.argv) == 4:
        roe_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--roe-window" and len(sys.argv) == 3:
        roe_window_checks()
        sys.exit(report())
    if sys.argv[2] == "--r29" and len(sys.argv) == 4:
        r29_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--r43" and len(sys.argv) == 5:
        r43_checks(sys.argv[3], sys.argv[4])
        sys.exit(report())
    if sys.argv[2] == "--nuclei-throttle" and len(sys.argv) in (3, 4):
        nuclei_throttle_checks(sys.argv[3] if len(sys.argv) == 4 else None)
        sys.exit(report())
    if sys.argv[2] == "--redis" and len(sys.argv) == 4:
        redis_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--ip-ownership-stealth" and len(sys.argv) == 4:
        ip_ownership_stealth_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--ip-ownership-nwlab" and len(sys.argv) == 3:
        ip_ownership_nwlab_checks()
        sys.exit(report())
    if sys.argv[2] == "--js-count" and len(sys.argv) == 3:
        print(f"JS_RECON_COUNT={js_recon_count()}")
        sys.exit(0)
    if sys.argv[2] == "--js-count-equals" and len(sys.argv) == 4:
        expected, got = int(sys.argv[3]), js_recon_count()
        print(f"{'PASS' if got == expected else 'FAIL'}  N-01  js_recon findings after a run with "
              f"no JS input: {got} (expect the {expected} from before)")
        sys.exit(0 if got == expected else 1)
    if sys.argv[2] == "--http-layer" and len(sys.argv) == 3:
        http_layer_checks()
        sys.exit(report())
    if sys.argv[2] == "--js-coverage" and sys.argv[3:4] == ["first"] and len(sys.argv) == 4:
        js_coverage_checks("first")
        sys.exit(report())
    if sys.argv[2] == "--js-coverage" and sys.argv[3:4] == ["capped"] and len(sys.argv) == 5:
        js_coverage_checks("capped", int(sys.argv[4]))
        sys.exit(report())
    if sys.argv[2] == "--vhost-origin" and len(sys.argv) == 3:
        vhost_origin_checks()
        sys.exit(report())
    if sys.argv[2] == "--passive-cves" and len(sys.argv) == 4:
        passive_cves(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--coverage" and len(sys.argv) in (4, 5):
        coverage_checks(sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else None)
        sys.exit(report())
    if sys.argv[2] == "--disposition" and sys.argv[3:4] in (["before"], ["decided"]) and len(sys.argv) == 4:
        disposition_checks(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--disposition-stored" and sys.argv[3:4] in (["before"], ["decided"], ["http-layer"]) \
            and len(sys.argv) == 4:
        disposition_stored_checks(sys.argv[3])
        sys.exit(report())
    sys.exit(USAGE)


# --------------------------------------------------------------------------- VHost
def vhosts(ip):
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{ip}'
                 RETURN v.hostname AS h, v.layer AS layer, v.severity AS sev ORDER BY h, layer""")
    return sorted((r["h"], r["layer"]) for r in rows), rows


got, _ = vhosts(f"{NET}.10")
check("V-01/V-02/V-03", got == [(f"admin.{APEX}", "L7"), (f"dev-api.{APEX}", "L7"), (f"dev.api.{APEX}", "L7"),
                                 (f"wiki.{APEX}", "L7")],
      f"Fastly-like edge: {got} (expect admin, dev-api, dev.api and wiki, L7, nothing from the 19 catch-all names)")
ids = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{NET}.10'
            AND v.hostname IN ['dev-api.{APEX}', 'dev.api.{APEX}'] RETURN v.hostname AS h, v.id AS id""")
import re as _re  # noqa: E402
check("V-16 (R-46)", len(ids) == 2 and len({r["id"] for r in ids}) == 2
      and all(_re.fullmatch(r"vhost_sni_[0-9a-f]{20}", r["id"] or "") for r in ids),
      f"dev-api and dev.api, two apps one character apart: {[(r['h'], r['id']) for r in ids]} "
      f"(expect two distinct vhost_sni_<20 hex> ids)")
got, _ = vhosts(f"{NET}.11")
check("V-04/V-05", got == [(f"admin.{APEX}", "L4")], f"Cloudflare-like edge: {got} (expect the SNI-routed admin only)")
got, _ = vhosts(f"{NET}.12")
check("V-07", got == [], f"provider redirect: {got}")
got, _ = vhosts(f"{NET}.13")
check("V-08", got == [], f"Akamai-style deny page: {got}")
got, _ = vhosts(f"{NET}.14")
check("V-09/V-10", got == [(f"admin.{APEX}", "L7")],
      f"rate-limited edge: {got} (expect admin kept despite its 429 on the second probe, no 429 names)")
got = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip IN ['{NET}.15', '{NET}.20']
            RETURN v.ip AS ip, v.hostname AS h""")
check("V-catch-all", got == [], f"catch-all app hosts (cache, SPA): {got}")
got = q("""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.severity = 'high'
           RETURN v.ip AS ip, v.hostname AS h""")
check("V-06", got == [], f"vhost findings rated high: {got}")
got = q(f"""MATCH (i:IP) WHERE i.address IN ['{NET}.10', '{NET}.13']
            RETURN i.address AS ip, i.vhost_sni_suppressed_by_control AS supp""")
check("V-controls", all((r.get("supp") or 0) >= 15 for r in got) and len(got) == 2,
      f"control-suppressed names per edge: {got}")


# --------------------------------------------------------------------------- JS: DOM sinks
def sinks(file_name):
    rows = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dom_sink' AND f.source_url ENDS WITH '/{file_name}'
                 RETURN f.title AS t, f.severity AS sev, f.confidence AS conf, f.user_source AS src,
                        f.vendor AS vendor, f.third_party AS tp, f.evidence AS ev, f.id AS id
                 ORDER BY t, sev""")
    return sorted((r["t"], r["sev"]) for r in rows), rows


got, rows = sinks("main.4f2a9c.js")
check("J-01/J-02/J-03/J-05/J-06",
      got == [("innerHTML", "high"), ("innerHTML", "low"), ("location.href", "low")],
      f"main bundle sinks: {got} (expect the hash->innerHTML bug high, the sourceless sink and the "
      f"navigation write low, no Function/eval/__proto__ from the shim or the guards)")
high = [r for r in rows if r["sev"] == "high"]
check("X-04", high and "location.hash" in (high[0].get("ev") or "") and "!function" not in (high[0].get("ev") or ""),
      f"evidence of the real bug: {(high[0].get('ev') if high else None)!r:.160}")
got, _ = sinks("msg.7c8d.js")
check("J-04", got == [("eval", "critical")], f"minified message handler: {got}")
got, _ = sinks("proto.6a7b.js")
check("J-07", got == [("__proto__", "low")], f"prototype writes: {got} (expect the write through __proto__, not the shim)")
got, rows = sinks("vendor.3c1d.js")
check("J-08", got == [("innerHTML", "info")] and all(r.get("vendor") for r in rows), f"vendor bundle: {got}")
got, _ = sinks("jquery.prettyPhoto.js")
check("J-10", got == [("innerHTML", "high")], f"hash-reading plugin: {got}")
got, rows = sinks("loader.js")
if rows:
    check("J-09", all(r["sev"] == "info" and r.get("tp") for r in rows), f"third-party loader: {got}")
else:
    check("J-09 (not crawled)", True, "the third-party loader was not collected by the crawl; nothing to judge")


# --------------------------------------------------------------------------- JS: source maps
def maps():
    rows = q("""MATCH (f:JsReconFinding) WHERE f.finding_type IN ['source_map_exposure', 'source_map_reference']
                RETURN f.source_url AS js, f.finding_type AS t, f.severity AS sev, f.map_url AS map,
                       f.fetch_result AS fr, f.first_party_files AS fp, f.has_sources_content AS sc,
                       f.control_check AS cc""")
    return {r["js"].rsplit("/", 1)[-1]: r for r in rows}


m = maps()
r = m.get("main.4f2a9c.js")
check("M-01", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 2
      and (r["map"] or "").endswith("main.4f2a9c.js.map"),
      f"served map with own source (low: its impact is the findings its sources produce): {r}")
r = m.get("lib.8e1f.js")
check("M-02", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 0, f"library-only map: {r}")
check("M-03", "shell.2b7a.js" not in m, f"map answered by the SPA shell: {m.get('shell.2b7a.js')}")
r = m.get("private.9c3d.js")
check("M-04", r and r["t"] == "source_map_reference" and r["sev"] == "info" and r["fr"] == "http_403"
      and r["cc"] == "passed", f"map behind a 403 a made-up sibling does not get: {r}")
check("M-07", "s3miss.0c1d.js" not in m, f"an S3 AccessDenied 403 for a missing map: {m.get('s3miss.0c1d.js')}")
check("M-08", "cfmiss.2e3f.js" not in m, f"a 403 the made-up sibling also gets: {m.get('cfmiss.2e3f.js')}")
r = m.get("buildref.7a8b.js")
# R-14: .99 is not one of the run's hosts, so the hop guard refuses it before
# any request (out_of_scope); before R-14 the fetch was tried and failed.
check("M-05", r and r["t"] == "source_map_reference" and r["fr"] in ("unreachable", "unsafe", "out_of_scope")
      and f"{NET}.99" in (r["map"] or ""), f"map on another unreachable host: {r}")
r = m.get("inline.5e6f.js")
check("M-06", r and r["t"] == "source_map_exposure" and (r["map"] or "").startswith("data:application/json;base64,…")
      and len(r["map"] or "") < 300, f"inline map stored as a label: {r}")


# --------------------------------------------------------------------------- JS: secrets
secrets = q("""MATCH (s:Secret) WHERE s.source = 'js_recon'
               RETURN s.secret_type AS t, s.matched_text AS mt, s.sample AS sample""")
types_ = sorted(r["t"] for r in secrets)
blob = json.dumps(secrets)
noise = [w for w in ("Forgot your", "auth.form", "#password-input", "/account/reset-password",
                     "Keep this secret", "localhost", "devapi", "debug") if w in blob]
check("K-01", not noise, f"UI text / dev literals stored as secrets: {noise}")
check("K-04/K-05", "AWS Access Key ID" in types_ and "Generic API Key" in types_
      and sum(1 for t in types_ if t in ("Generic Secret", "Hardcoded Password")) >= 2,
      f"Secret types: {types_} (expect the AWS key, the API key, 'Summer 2024!' and '$ecureP4ss2024')")
refs = q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dev_reference'
            RETURN f.title AS t, f.evidence AS ev, f.severity AS sev ORDER BY t""")
got = sorted((r["t"], r["sev"]) for r in refs)
check("K-02", got == [("Debug Flag", "info"), ("Internal/Staging URL", "info"), ("Localhost with Port", "info")]
      and any("devapi.fplab.test" in (r["ev"] or "") for r in refs), f"developer references: {refs}")
check("K-03", "developer.vendor.test" not in json.dumps(refs) + blob, "documentation host not reported")
ext = sorted(r["d"] for r in q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'external_domain'
                                   RETURN f.title AS d"""))
own = {f"{NET}.{n}" for n in (10, 11, 12, 13, 14, 15, 20)}
check("X-05", f"{NET}.99" in ext and not own.intersection(ext),
      f"external domains: {ext} (expect the unreachable map host, never a scanned target IP)")

long_secrets = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/auth.1d2e.js'
                    RETURN s.secret_type AS t, size(s.matched_text) AS n""")
got = sorted((r["t"], r["n"]) for r in long_secrets)
# The lab's JWT carries role service_role, so since plan 05.6 it is named by its role.
check("K-06", any(t in ("JWT Token", "Supabase service_role key") and n >= 220 for t, n in got)
      and any(t == "Bearer Token" and n >= 220 for t, n in got),
      f"secrets longer than 200 characters: {got} (expect the JWT and its Bearer header, not dropped "
      f"as a base64 blob)")
font = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/theme.5b6c.js'
            RETURN s.secret_type AS t, s.matched_text AS mt""")
check("K-07", [(r["t"], r["mt"]) for r in font] == [("AWS Access Key ID", "AKIAZ3FPLB7QW4XN6R2T")],
      f"key 8,000 characters after a font marker on a long minified line: {font}")
# Plan 05: keys.8c2d.js
keys = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/keys.8c2d.js'
            RETURN s.secret_type AS t, s.severity AS sev, s.confidence AS conf,
                   s.public_client_key AS pub, s.matched_text AS mt, s.context AS ctx""")
by_t = {}
for r in keys:
    by_t.setdefault(r["t"], []).append(r)
pub = sorted((t, r["sev"], r["pub"]) for t in ("GCP API Key", "Segment Write Key") for r in by_t.get(t, []))
check("K-08", pub == [("GCP API Key", "info", True), ("Segment Write Key", "info", True)],
      f"public-by-design keys: {pub} (expect both at info with public_client_key)")
check("K-09", "LoginForm_password__3xYz9" not in json.dumps(secrets) and "Secret_secret__a1B2c" not in json.dumps(secrets),
      f"CSS-module class names stored as secrets: {[r['t'] for r in secrets if '__' in (r['mt'] or '')]}")
sup = {t: sorted((r["sev"], r["pub"]) for r in by_t.get(t, [])) for t in ("Supabase service_role key", "Supabase anon key")}
check("K-10", sup == {"Supabase service_role key": [("critical", False)], "Supabase anon key": [("info", True)]}
      and not by_t.get("JWT Token") and not by_t.get("Supabase Key"),
      f"Supabase keys by role: {sup}; other names on them: {sorted(t for t in by_t if 'JWT' in t or t == 'Supabase Key')}")
signed = [r["sev"] for r in by_t.get("Signed URL in client code", [])]
zap = [r["sev"] for r in by_t.get("Zapier Webhook", [])]
check("K-11", signed == ["medium"] and zap == ["high"],
      f"presigned S3 URL: {signed} (expect medium); Zapier hook: {zap} (expect high)")
raws = [r["mt"] for r in keys if r["mt"]]
two = sorted(r["t"] for r in keys if r["t"] in ("GitHub Token Classic", "Stripe Secret Key"))
leaks = [(r["t"], raw[:8]) for r in keys for raw in raws if raw in (r["ctx"] or "")]
check("K-12", two == ["GitHub Token Classic", "Stripe Secret Key"] and all(r["ctx"] for r in keys) and not leaks,
      f"two keys 100 characters apart: {two}; contexts present: {all(r['ctx'] for r in keys)}; "
      f"raw values inside a context: {leaks}")
eps = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = 'http://{NET}.20' AND e.path IN ['/api/read', '/api/list', '/api/save']
            RETURN e.path AS path, e.method AS method ORDER BY path, method""")
got = sorted((r["path"], r["method"]) for r in eps)
check("E-01", got == [("/api/list", "GET"), ("/api/read", "GET"), ("/api/save", "POST")],
      f"endpoint methods on a minified line with postMessage: {got} (expect read and list GET, the "
      f"axios.post control POST)")


# --------------------------------------------------------------------------- Shodan
shodan = q(f"""MATCH (i:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)
               WHERE v.source IN ['shodan_api', 'internetdb', 'shodan'] AND i.address STARTS WITH '{NET}.'
               RETURN i.address AS ip, v.name AS cve, v.source AS src, v.detection_method AS dm,
                      v.severity AS sev, v.target_port AS port, v.product AS product, v.verified AS verified""")
by = {(r["ip"], r["cve"]): r for r in shodan}
api = any(r["src"] == "shodan_api" for r in shodan)
check("H-04", not [r for r in shodan if r["ip"] in (f"{NET}.11", f"{NET}.12")],
      f"CVE rows on the Vercel / cdn-tagged hosts: {[r for r in shodan if r['ip'] in (f'{NET}.11', f'{NET}.12')]}")
r = by.get((f"{NET}.10", "CVE-2021-23017"))
if api:
    check("H-01", r and r["dm"] == "passive_version_match" and r["sev"] == "high" and r["port"] == 80
          and r["product"] == "nginx", f"banner CVE: {r}")
    r2 = by.get((f"{NET}.13", "CVE-2014-0160"))
    check("H-02", r2 and r2["dm"] == "passive_verified" and r2["verified"] is True and r2["port"] == 443,
          f"verified banner CVE: {r2}")
else:
    check("H-01/H-02 (InternetDB path)", r and r["dm"] == "passive_catalog",
          f"no Shodan key configured, so only InternetDB answered: {r}")
r = by.get((f"{NET}.10", "CVE-2019-11043"))
check("H-03", r and r["dm"] == "passive_catalog" and not r.get("sev"), f"catalog-only CVE: {r}")


# --------------------------------------------------------------------------- Cache
cache = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'cache_poisoning'
              RETURN coalesce(v.endpoint_url, v.url, v.matched_at) AS url, v.cache_impact AS impact,
                     v.confidence_tier AS tier""")
urls = json.dumps(cache)
check("C-02", "/promo" not in urls, f"A/B page reported as poisoned: {[c for c in cache if '/promo' in json.dumps(c)]}")
check("C-01", "/home" in urls, f"real unkeyed-header poisoning on /home: {cache}")


# --------------------------------------------------------------------------- Priority Board
# query_graph scopes every query to the tenant through a labelled node, so the
# two finding kinds are read separately rather than through one unlabelled MATCH.
tiers = q("""MATCH (n:JsReconFinding) WHERE n.finding_type IN ['dom_sink', 'dev_reference']
             RETURN 'JsReconFinding' AS label, n.finding_type AS kind, n.title AS name,
                    n.severity AS sev, n.triage_tier AS tier""")
tiers += q("""MATCH (n:Vulnerability) WHERE n.source IN ['shodan_api', 'internetdb']
              RETURN 'Vulnerability' AS label, n.source AS kind, n.name AS name,
                     n.severity AS sev, n.triage_tier AS tier""")
scored = [t for t in tiers if t.get("tier")]
bad = [t for t in scored if t["tier"] in ("T1", "T2")]
check("X-01a", scored and not bad, f"{len(scored)} scored; in T1/T2: {bad}")
cat = [t for t in scored if t["kind"] in ("shodan_api", "internetdb") and t["name"] == "CVE-2019-11043"]
check("X-01b", cat and all(t["tier"] == "T4" for t in cat), f"catalog-only CVE tier: {cat}")
refs_t = [t for t in scored if t["kind"] == "dev_reference"]
check("X-01c", refs_t and all(t["tier"] == "T4" for t in refs_t), f"developer reference tiers: {refs_t}")
public = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.public_client_key = true
              RETURN s.secret_type AS t, s.triage_tier AS tier""")
check("X-01d", public and all(r["tier"] == "T4" for r in public),
      f"public client keys on the board: {sorted((r['t'], r['tier']) for r in public)} (expect every one in T4)")


# --------------------------------------------------------------------------- Priority Board: secret groups
# Grouped by the leaked VALUE, and learned per pattern: before plan 02 every
# js_recon secret of one category on one host was a single board row.
aws = q(f"""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.secret_type = 'AWS Access Key ID'
              AND s.base_url = 'http://{NET}.20' AND s.triage_group_key IS NOT NULL
              RETURN s.matched_text AS mt, s.source_url AS url, s.triage_group_key AS g,
                     s.triage_detector AS d""")
by_value = {}
for r in aws:
    by_value.setdefault(r["mt"], set()).add(r["g"])
groups = [g for gs in by_value.values() for g in gs]
check("S-01", len(by_value) >= 2 and len(set(groups)) == len(by_value) == len(groups),
      f"distinct AWS keys on one host -> groups: { {k[:8]: sorted(v) for k, v in by_value.items()} } "
      f"(expect one group per key, never one per category)")
twice = [r for r in aws if r["mt"] == "AKIAZ3FPLB7QW4XN6R2T"]
check("S-02", len({r["url"] for r in twice}) == 2 and len({r["g"] for r in twice}) == 1,
      f"the same key in theme and config bundles: {[(r['url'].rsplit('/', 1)[-1], r['g']) for r in twice]} "
      f"(expect two findings, one group: one rotation)")
check("S-03", aws and {r["d"] for r in aws} == {"js_recon:aws-access-key-id"},
      f"detector of the AWS secrets: {sorted({r['d'] for r in aws})} (expect the pattern, not 'js_recon:cloud')")


# --------------------------------------------------------------------------- report
sys.exit(report())
