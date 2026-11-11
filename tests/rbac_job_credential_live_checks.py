"""
Run INSIDE the agent container by tests/rbac_job_credential_live.sh (fed on stdin, after a
preamble that sets MEMBER_A_ID, MEMBER_B_ID, PA_ID, PB_ID, A_TAVILY_SECRET). The agent holds
INTERNAL_API_KEY and SCANNER_API_KEY in its environment: it mints job credentials as the
webapp does (same format, same key) and calls the webapp and itself as a scan container
would. Prints PASS/FAIL lines and `RESULT_IN <pass> <fail>`; never a key, a credential or a
response body.
"""
import json
import os
import time
import urllib.error
import urllib.request

import machine_credential as mc

WEBAPP = os.environ.get("WEBAPP_URL", "http://webapp:3000").rstrip("/")
AGENT = "http://localhost:8080"
SCANNER = os.environ.get("SCANNER_API_KEY", "")
RESULTS = [0, 0]

g = globals()
MEMBER_A_ID, MEMBER_B_ID, PA_ID, PB_ID = (g["MEMBER_A_ID"], g["MEMBER_B_ID"], g["PA_ID"], g["PB_ID"])
A_TAVILY_SECRET = g["A_TAVILY_SECRET"]


def job(tenant, project, exp_in=3600):
    key = mc.derive_key(os.environ["INTERNAL_API_KEY"], mc.JOB_CREDENTIAL_LABEL)
    return mc.mint({"aud": "scan", "ten": tenant, "pid": project, "job": "rbac-live-116",
                    "exp": int(time.time()) + exp_in}, key)


def call(method, url, body=None, cred=None):
    headers = {"X-Internal-Key": SCANNER, "Content-Type": "application/json"}
    if cred:
        headers["X-Redamon-Job"] = cred
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def check(name, ok, got=""):
    RESULTS[0 if ok else 1] += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name} -> {got}")


def code_of(text):
    try:
        body = json.loads(text)
    except ValueError:
        return ""
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        return detail.get("code", "")
    return (body.get("reason") or body.get("code") or "") if isinstance(body, dict) else ""


settings_url = f"{WEBAPP}/api/users/{MEMBER_A_ID}/settings?internal=true"
s, t = call("GET", settings_url)
check("webapp: the bare scanner key reads no settings (403 missing)", s == 403 and code_of(t) == "missing", s)
s, t = call("GET", settings_url, cred=job(MEMBER_A_ID, PA_ID))
check("webapp: scanner key + the owner's credential reads them unmasked", s == 200 and A_TAVILY_SECRET in t, s)
s, t = call("GET", settings_url, cred=job(MEMBER_B_ID, PB_ID))
check("webapp: another tenant's credential reads nothing (tenant_mismatch)",
      s == 403 and code_of(t) == "tenant_mismatch" and A_TAVILY_SECRET not in t, s)
s, t = call("GET", settings_url, cred=job(MEMBER_A_ID, PA_ID, exp_in=-1))
check("webapp: an expired credential reads nothing", s == 403 and code_of(t) == "expired", s)

s, t = call("GET", f"{WEBAPP}/api/projects/{PA_ID}")
check("webapp: the bare scanner key reads no project", s == 403 and "rbac-PA" not in t, s)
s, t = call("GET", f"{WEBAPP}/api/projects/{PA_ID}", cred=job(MEMBER_A_ID, PA_ID))
check("webapp: the credential reads its own project", s == 200 and "rbac-PA" in t, s)
s, t = call("GET", f"{WEBAPP}/api/projects/{PB_ID}", cred=job(MEMBER_A_ID, PA_ID))
check("webapp: the credential reads no other project (project_mismatch)",
      s == 403 and code_of(t) == "project_mismatch", s)

ingest = {"source": "recon", "transactions": []}
s, t = call("POST", f"{WEBAPP}/api/traffic/{PA_ID}/ingest", ingest)
check("webapp: the bare scanner key ingests nothing", s == 403, s)
s, t = call("POST", f"{WEBAPP}/api/traffic/{PA_ID}/ingest", ingest, cred=job(MEMBER_A_ID, PA_ID))
check("webapp: the credential ingests into its own project", s in (200, 202), s)
s, t = call("POST", f"{WEBAPP}/api/traffic/{PB_ID}/ingest", ingest, cred=job(MEMBER_A_ID, PA_ID))
check("webapp: the credential ingests into no other project", s == 403, s)

tags = {"technologies": ["php"], "servers": [], "current_tags": ["cve"], "candidates": ["cve", "php"],
        "model": "gpt-4o"}
s, t = call("POST", f"{AGENT}/llm/nuclei-tags", tags)
check("agent: /llm/* refuse the bare scanner key (job_credential_missing)",
      s == 401 and code_of(t) == "job_credential_missing", s)
s, t = call("POST", f"{AGENT}/llm/nuclei-tags", {**tags, "user_id": MEMBER_B_ID}, cred=job(MEMBER_A_ID, PA_ID))
check("agent: a body user other than the credential's is refused",
      s == 403 and code_of(t) == "job_credential_user_mismatch", s)
s, t = call("POST", f"{AGENT}/llm/nuclei-tags", tags, cred=job(MEMBER_A_ID, PA_ID))
check("agent: with the credential the route runs for its tenant (no 401/403)", s not in (401, 403), s)
s, t = call("POST", f"{AGENT}/jev/page-type", {"pages": [{"url": "http://rbac.test/"}]})
check("agent: /jev/* refuse the bare scanner key", s == 401, s)
s, t = call("POST", f"{AGENT}/jev/page-type", {"pages": [{"url": "http://rbac.test/"}]}, cred=job(MEMBER_A_ID, PA_ID))
check("agent: /jev/* with the credential reach the owner binding (no gate refusal)",
      s not in (401,) and not code_of(t).startswith("job_credential_"), s)

print(f"RESULT_IN {RESULTS[0]} {RESULTS[1]}")
