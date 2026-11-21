#!/usr/bin/env python3
"""
Seed for the live isolation harness of group 1 (per-user Kali sandboxes):
tests/kali_sandbox_isolation_live.sh. Run on the host against the LIVE stack:

    python3 tests/kali_sandbox_seed_live.py

Everything goes through the webapp's own routes, signed in as the admin of the
repo-root .env (UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD, read inline, never printed):

  - members g1-alice and g1-bob (g1-*@e2e.local, on the Red-team operator set), with
    generated passwords;
  - projects g1-PA (Alice), g1-PB (Bob) and g1-PS (Alice), targets under `.invalid`;
  - g1-PS shared with Bob at Read + Write with "Use AI agent" and "Exploitation &
    shells", after Alice's owner consent;
  - "Allow MCP sandbox commands" (mcpKaliExecEnabled) on for all three;
  - one MCP token per person with the `kali:exec` scope, reaching shared projects.

Idempotent: accounts, projects, the share and a still-working token are reused. An
account whose password the state file does not hold gets a new one through the
admin's credentials reset. A block_private value an interrupted harness run recorded
is put back; its other leftovers stay recorded for the harness's next start. Ids, passwords and tokens go to the state file only
($G1_STATE, default ${TMPDIR:-/tmp}/g1-live-state.json, mode 0600); stdout carries
ids and outcomes, never a secret. Synthetic data only: no real target.

Needs the stack up (webapp answering /api/health); prints SKIP and exits 0 when it
is not. As a *_live file it is never in the gate.
"""
import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PEOPLE = {
    "alice": {"email": "g1-alice@e2e.local", "name": "G1 Alice"},
    "bob": {"email": "g1-bob@e2e.local", "name": "G1 Bob"},
}
# key -> (owner, project name, placeholder target)
PROJECTS = {
    "PA": ("alice", "g1-PA", "g1-pa.invalid"),
    "PB": ("bob", "g1-PB", "g1-pb.invalid"),
    "PS": ("alice", "g1-PS", "g1-ps.invalid"),
}
# The built-in set that holds agent:kali_exec whatever the instance's default member set is.
MEMBER_SET = "builtin:red-team-operator"
TOKEN_NAME = "g1-live-isolation"
STATE_VERSION = 1


class SeedError(Exception):
    """A step of the seed that cannot go on; the message never holds a secret."""


def env_value(key):
    """`key` from the process environment, else the repo-root .env (never printed)."""
    if os.environ.get(key):
        return os.environ[key]
    try:
        with open(os.path.join(ROOT, ".env"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return ""


def base_url():
    return os.environ.get("BASE_URL") or f"http://localhost:{env_value('WEBAPP_PORT') or '3000'}"


def state_path():
    return os.environ.get("G1_STATE") or os.path.join(os.environ.get("TMPDIR") or "/tmp", "g1-live-state.json")


def read_state(path=None):
    path = path or state_path()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("version") == STATE_VERSION else None


def write_state(data, path=None):
    path = path or state_path()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    # O_CREAT keeps the mode of a leftover tmp file, so set it explicitly.
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def update_state(**changes):
    """Set (or, with None, drop) top-level keys of the state file; False when there is none."""
    data = read_state()
    if data is None:
        return False
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    write_state(data)
    return True


def webapp_up(base=None, timeout=5):
    try:
        with urllib.request.urlopen((base or base_url()) + "/api/health", timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


class Web:
    """One signed-in browser: a cookie jar, and Origin on every non-GET as a browser sends."""

    def __init__(self, base=None):
        self.base = base or base_url()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, timeout=60, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if method not in ("GET", "HEAD"):
            req.add_header("Origin", self.base)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            raise SeedError(f"{method} {path}: no answer ({type(e).__name__})") from None
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    def login(self, email, password):
        status, body = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        return status, (body or {}) if isinstance(body, dict) else {}


def _err(body):
    """A refusal's code and message, for a SeedError (the routes never echo a secret)."""
    if isinstance(body, dict):
        return f"{body.get('code') or ''} {str(body.get('error') or '')[:160]}".strip()
    return ""


def new_password():
    return "G1-" + secrets.token_urlsafe(24) + "-x9Q"


def block_private_route(admin, admin_id):
    """(route, current value) of the capture proxy's block_private toggle: the instance
    settings with the identity switch on, else the admin's own settings row."""
    for path in ("/api/admin/instance-settings", f"/api/users/{admin_id}/settings"):
        status, body = admin.call("GET", path)
        if status == 200 and isinstance(body, dict) and isinstance(body.get("captureEgressBlockPrivate"), bool):
            return path, body["captureEgressBlockPrivate"]
    raise SeedError("the Global Settings routes did not answer captureEgressBlockPrivate")


def put_block_private(admin, path, value):
    status, body = admin.call("PUT", path, {"captureEgressBlockPrivate": value})
    if status != 200:
        raise SeedError(f"saving block_private={value} answered {status} {_err(body)}")


def mcp_call(token, method, params=None, base=None, timeout=120):
    """One JSON-RPC call to the inbound MCP server; the answer may come as an SSE frame."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request((base or base_url()) + "/api/mcp-server", data=body, method="POST")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return 0, {"transport_error": type(e).__name__}
    for line in raw.splitlines():
        if line.startswith("data: "):
            raw = line[6:]
            break
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None


def token_works(token, base=None):
    if not token:
        return False
    status, body = mcp_call(token, "tools/list", base=base, timeout=30)
    tools = ((body or {}).get("result") or {}).get("tools") or [] if isinstance(body, dict) else []
    return status == 200 and any(t.get("name") == "kali_exec" for t in tools if isinstance(t, dict))


def ensure_person(admin, admin_password, key, saved):
    spec = PEOPLE[key]
    status, users = admin.call("GET", "/api/users")
    if status != 200 or not isinstance(users, list):
        raise SeedError(f"listing accounts answered {status}")
    row = next((u for u in users if str(u.get("email", "")).lower() == spec["email"]), None)
    password = saved.get("password") or ""
    if row is None:
        password = new_password()
        body = {"name": spec["name"], "email": spec["email"], "password": password, "role": "standard",
                "requirePasswordChange": False, "sets": [MEMBER_SET], "stepUpPassword": admin_password}
        status, created = admin.call("POST", "/api/users", body)
        if status != 201 or not isinstance(created, dict):
            raise SeedError(f"creating {spec['email']} answered {status} {_err(created)}")
        row = created
        print(f"  created account {spec['email']} ({row['id']})")
    elif row.get("status") not in (None, "active"):
        raise SeedError(f"{spec['email']} exists but is {row.get('status')}: enable it or delete it, then seed again")
    person = Web(admin.base)
    status, answer = person.login(spec["email"], password) if password else (401, {})
    if status != 200:
        # The state file lost the password (or never had it): the admin resets it.
        password = new_password()
        body = {"newPassword": password, "stepUpPassword": admin_password, "requirePasswordChange": False,
                "reason": "g1 live isolation harness seed"}
        status, reset = admin.call("PUT", f"/api/users/{row['id']}/password", body)
        if status != 200:
            raise SeedError(f"resetting {spec['email']}'s password answered {status} {_err(reset)}")
        status, answer = person.login(spec["email"], password)
        if status != 200:
            raise SeedError(f"signing in as {spec['email']} answered {status}")
        print(f"  reset the password of {spec['email']}")
    if answer.get("mustChangePassword"):
        raise SeedError(f"{spec['email']} must change its password first: delete the account and seed again")
    return {"id": row["id"], "email": spec["email"], "password": password}, person


def ensure_project(owner_web, owner_id, name, target):
    status, projects = owner_web.call("GET", "/api/projects")
    if status != 200 or not isinstance(projects, list):
        raise SeedError(f"listing {name}'s owner's projects answered {status}")
    row = next((p for p in projects if p.get("name") == name and p.get("userId") == owner_id), None)
    if row is None:
        # The soft guardrail asks a model about the target; a placeholder needs no opinion.
        body = {"name": name, "targetDomain": target, "targetGuardrailEnabled": False, "mcpKaliExecEnabled": True}
        status, row = owner_web.call("POST", "/api/projects", body, timeout=120)
        if status not in (200, 201) or not isinstance(row, dict) or not row.get("id"):
            raise SeedError(f"creating project {name} answered {status} {_err(row)}")
        print(f"  created project {name} ({row['id']})")
    pid = row["id"]
    status, full = owner_web.call("GET", f"/api/projects/{pid}")
    if status != 200 or not isinstance(full, dict):
        raise SeedError(f"reading project {name} answered {status}")
    if full.get("mcpKaliExecEnabled") is not True:
        status, body = owner_web.call("PUT", f"/api/projects/{pid}", {"mcpKaliExecEnabled": True})
        if status != 200:
            raise SeedError(f"turning on MCP sandbox commands for {name} answered {status} {_err(body)}")
        print(f"  turned on MCP sandbox commands for {name}")
    return pid


def ensure_share(alice_web, alice_password, ps_id, bob):
    status, policy = alice_web.call("GET", f"/api/projects/{ps_id}/access-policy")
    if status != 200 or not isinstance(policy, dict):
        raise SeedError(f"reading g1-PS's owner consent answered {status}: is Read + Write sharing in force?")
    if not policy.get("ownerCredentialConsent"):
        status, body = alice_web.call("POST", f"/api/projects/{ps_id}/access-policy",
                                      {"ownerCredentialConsent": True, "stepUpPassword": alice_password})
        if status != 200:
            raise SeedError(f"Alice's owner consent on g1-PS answered {status} {_err(body)}")
        print("  Alice consented to collaborators spending g1-PS's credentials")
    terms = {"access": "write", "useAgent": True, "exploit": True}
    status, listing = alice_web.call("GET", f"/api/projects/{ps_id}/collaborators")
    if status != 200:
        raise SeedError(f"listing g1-PS's shares answered {status}")
    rows = (listing or {}).get("collaborators") if isinstance(listing, dict) else listing
    share = next((r for r in rows or [] if (r.get("user") or {}).get("id") == bob["id"] or r.get("userId") == bob["id"]), None)
    if share is None:
        status, body = alice_web.call("POST", f"/api/projects/{ps_id}/collaborators",
                                      {"email": bob["email"], **terms, "note": "g1 live isolation harness",
                                       "stepUpPassword": alice_password})
        if status != 201:
            raise SeedError(f"sharing g1-PS with Bob answered {status} {_err(body)}")
        print("  shared g1-PS with Bob (Read + Write, Use AI agent, Exploitation & shells)")
    elif any(share.get(k) != v for k, v in terms.items()) or share.get("expired"):
        status, body = alice_web.call("PATCH", f"/api/projects/{ps_id}/collaborators/{bob['id']}",
                                      {**terms, "expiresAt": None, "stepUpPassword": alice_password})
        if status != 200:
            raise SeedError(f"changing Bob's share of g1-PS answered {status} {_err(body)}")
        print("  set Bob's share of g1-PS back to Read + Write, Use AI agent, Exploitation & shells")


def ensure_token(person_web, person, saved):
    if token_works(saved.get("token", ""), person_web.base):
        return saved["token"], saved.get("token_id", "")
    status, listing = person_web.call("GET", f"/api/users/{person['id']}/mcp-tokens")
    rows = (listing or {}).get("tokens") if isinstance(listing, dict) else listing
    for row in rows or []:
        if isinstance(row, dict) and row.get("name") == TOKEN_NAME and row.get("id"):
            person_web.call("DELETE", f"/api/users/{person['id']}/mcp-tokens/{row['id']}")
    body = {"name": TOKEN_NAME, "scopes": ["kali:exec"], "expiresInDays": 30,
            "includeSharedProjects": True, "password": person["password"]}
    status, minted = person_web.call("POST", f"/api/users/{person['id']}/mcp-tokens", body)
    if status != 201 or not isinstance(minted, dict) or not minted.get("plaintext"):
        raise SeedError(f"minting {person['email']}'s MCP token answered {status} {_err(minted)}")
    token, token_id = minted["plaintext"], str((minted.get("token") or {}).get("id") or "")
    if not token_works(token, person_web.base):
        raise SeedError(f"{person['email']}'s new MCP token does not list kali_exec: is MCP_KALI_EXEC_ENABLED on?")
    print(f"  minted {person['email']}'s MCP token ({token_id})")
    return token, token_id


def seed():
    admin_email, admin_password = env_value("UI_LOGIN_USERNAME"), env_value("UI_LOGIN_PASSWORD")
    if not admin_email or not admin_password:
        raise SeedError("UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD are not set in .env")
    previous = read_state() or {}
    admin = Web()
    status, answer = admin.login(admin_email, admin_password)
    if status != 200:
        raise SeedError(f"signing in as the .env admin answered {status}")
    if answer.get("mustChangePassword"):
        raise SeedError("the .env admin must change its password first")
    # What an interrupted harness run left for its successor: kept in the new state,
    # except a block_private value, which the seed puts back itself.
    carry = {k: previous[k] for k in ("pending_block_private", "active_run") if k in previous}
    if isinstance(carry.get("pending_block_private"), bool):
        path, now = block_private_route(admin, answer.get("id"))
        if now != carry["pending_block_private"]:
            put_block_private(admin, path, carry["pending_block_private"])
        print(f"  put the capture proxy's block_private back to {carry.pop('pending_block_private')} "
              "(left by an interrupted harness run)")

    people, webs = {}, {}
    for key in PEOPLE:
        people[key], webs[key] = ensure_person(admin, admin_password, key, previous.get(key) or {})
    projects = {key: ensure_project(webs[owner], people[owner]["id"], name, target)
                for key, (owner, name, target) in PROJECTS.items()}
    ensure_share(webs["alice"], people["alice"]["password"], projects["PS"], people["bob"])
    for key in PEOPLE:
        token, token_id = ensure_token(webs[key], people[key], previous.get(key) or {})
        people[key].update(token=token, token_id=token_id)

    state = {"version": STATE_VERSION, "base_url": admin.base, "projects": projects, **people, **carry}
    write_state(state)
    return state


def main():
    if not webapp_up():
        print(f"SKIP: RedAmon webapp not answering at {base_url()}/api/health")
        return 0
    print("== Seeding the g1 live fixtures ==")
    try:
        state = seed()
    except SeedError as e:
        print(f"FAIL  seed: {e}")
        return 1
    print(f"  alice={state['alice']['id']} bob={state['bob']['id']} "
          + " ".join(f"{k}={v}" for k, v in sorted(state["projects"].items())))
    print(f"  state written to {state_path()} (mode 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
