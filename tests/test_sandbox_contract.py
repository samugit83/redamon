"""The per-user Kali sandbox contract: the three copies agree, and its pure rules
keep persons apart.

recon_orchestrator/sandbox_contract.py and agentic/sandbox_contract.py must be
byte-identical, and webapp/src/lib/sandbox/contract.ts must carry the same values.
Both Python copies are loaded by path under unique module names (as
tests/test_resource_governor.py does with its two copies): the agent section puts
both directories on sys.path, so `import sandbox_contract` would let the drift
check compare one copy with itself.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import random
import re
import sys
from collections.abc import Mapping

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORCH_PATH = os.path.join(ROOT, "recon_orchestrator", "sandbox_contract.py")
AGENT_PATH = os.path.join(ROOT, "agentic", "sandbox_contract.py")
TS_PATH = os.path.join(ROOT, "webapp", "src", "lib", "sandbox", "contract.ts")


def _load(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


c = _load(ORCH_PATH, "_orch_sandbox_contract")
agent_copy = _load(AGENT_PATH, "_agent_sandbox_contract")

# Ids in the formats the database holds (WI-S01-1): Prisma's cuid() default for
# users and projects, a client-chosen project id (`^[a-z0-9]{20,32}$`, the
# projects POST route), and the fixed ids of the e2e seeds.
ALICE = "cm3k1x9q20000ab12cd34ef56"
BOB = "cm3k1x9q20001ab12cd34ef57"
CAROL = "rbac-deleted-fixture"
P_ALICE_1 = "cm3k2a0000000aaaaaaaaaaaa"
P_ALICE_2 = "k3j4h5g6f7d8s9a0q1w2e3r4"
P_BOB_1 = "cm3k2b0000000bbbbbbbbbbbb"


# --- the three copies -----------------------------------------------------------


def test_python_copies_identical():
    assert os.path.realpath(ORCH_PATH) != os.path.realpath(AGENT_PATH)
    assert c.__file__ != agent_copy.__file__, "not comparing two real copies"
    with open(ORCH_PATH, "rb") as f:
        orch = f.read()
    with open(AGENT_PATH, "rb") as f:
        agent = f.read()
    assert orch, "the orchestrator copy is empty"
    assert orch == agent, (
        "agentic/sandbox_contract.py differs from recon_orchestrator/sandbox_contract.py; "
        "they are one contract and must stay byte-identical")


def _strip_ts_comments(text: str) -> str:
    """contract.ts with every comment blanked and every string kept intact: a
    constant inside a comment does not exist, and `//` inside a string is not a
    comment. Newlines are kept so error line numbers still hold."""
    out, i, n, quote = [], 0, len(text), None
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
        elif ch in "'\"`":
            quote = ch
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise ValueError("contract.ts: unterminated comment")
            out.append(" " + "\n" * text.count("\n", i, end))
            i = end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class _TsLiteral:
    """Reads the TypeScript literal subset contract.ts uses, from comment-free
    text: strings in either quote, numbers (with `_` separators),
    true/false/null, arrays and objects with bare or quoted keys, trailing
    commas. Anything else is an error, so a constant written as an expression
    fails instead of being skipped."""

    _NUMBER = re.compile(r"-?[0-9][0-9_]*(?:\.[0-9_]+)?")
    _IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
    _ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"', "`": "`"}

    def __init__(self, text: str, pos: int):
        self.text = text
        self.pos = pos

    def _ws(self):
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def _fail(self, what: str):
        line = self.text.count("\n", 0, self.pos) + 1
        raise ValueError(f"contract.ts line {line}: {what}")

    def value(self):
        self._ws()
        ch = self.text[self.pos:self.pos + 1]
        if ch in ("'", '"'):
            return self._string(ch)
        if ch == "[":
            return self._array()
        if ch == "{":
            return self._object()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.pos) and not self._IDENT.match(
                    self.text, self.pos + len(word)):
                self.pos += len(word)
                return val
        m = self._NUMBER.match(self.text, self.pos)
        if m:
            self.pos = m.end()
            raw = m.group(0).replace("_", "")
            return float(raw) if "." in raw else int(raw)
        self._fail(f"not a literal: {self.text[self.pos:self.pos + 30]!r}")

    def _string(self, quote: str) -> str:
        out, self.pos = [], self.pos + 1
        while True:
            ch = self.text[self.pos]
            if ch == quote:
                self.pos += 1
                return "".join(out)
            if ch == "\n":
                self._fail("unterminated string")
            if ch == "\\":
                nxt = self.text[self.pos + 1]
                if nxt not in self._ESCAPES:
                    self._fail(f"unsupported escape \\{nxt}")
                out.append(self._ESCAPES[nxt])
                self.pos += 2
                continue
            out.append(ch)
            self.pos += 1

    def _array(self) -> list:
        items, self.pos = [], self.pos + 1
        while True:
            self._ws()
            if self.text[self.pos] == "]":
                self.pos += 1
                return items
            items.append(self.value())
            self._ws()
            if self.text[self.pos] == ",":
                self.pos += 1
            elif self.text[self.pos] != "]":
                self._fail("expected , or ]")

    def _object(self) -> dict:
        out, self.pos = {}, self.pos + 1
        while True:
            self._ws()
            ch = self.text[self.pos]
            if ch == "}":
                self.pos += 1
                return out
            if ch in ("'", '"'):
                key = self._string(ch)
            else:
                m = self._IDENT.match(self.text, self.pos)
                if not m:
                    self._fail("expected a key")
                key, self.pos = m.group(0), m.end()
            self._ws()
            if self.text[self.pos] != ":":
                self._fail("expected :")
            self.pos += 1
            out[key] = self.value()
            self._ws()
            if self.text[self.pos] == ",":
                self.pos += 1
            elif self.text[self.pos] != "}":
                self._fail("expected , or }")


# After a literal: an optional `as const` and `;`, then the next statement or the
# end of the file. A trailing operator, call or `satisfies` makes the value
# something other than the literal read, so it fails.
_TS_STATEMENT_END = re.compile(
    r"\s*(?:as\s+const\b)?\s*;?\s*(?:\Z|(?:export|type|interface|function)\b)")
_TS_EXPORT_KINDS = ("const", "type", "interface", "function")


def _ts_constants(text: str) -> dict:
    text = _strip_ts_comments(text)
    for m in re.finditer(r"^[ \t]*export\b(.*)$", text, re.M):
        kind = (m.group(1).split() or [""])[0]
        if kind not in _TS_EXPORT_KINDS:
            raise ValueError(f"contract.ts: an `export {kind}` the drift check cannot read")
    strict = list(re.finditer(r"^export const ([A-Z][A-Z0-9_]*)\s*=\s*", text, re.M))
    if len(strict) != len(re.findall(r"^[ \t]*export\s+const\b", text, re.M)):
        raise ValueError("contract.ts: an exported constant is not `export const UPPER_NAME = <literal>`")
    found = {}
    for m in strict:
        name = m.group(1)
        if name in found:
            raise ValueError(f"contract.ts declares {name} twice")
        literal = _TsLiteral(text, m.end())
        found[name] = literal.value()
        if not _TS_STATEMENT_END.match(text, literal.pos):
            raise ValueError(f"contract.ts: {name} is not a plain literal")
    return found


def _ts_interface_keys(text: str, name: str) -> list:
    text = _strip_ts_comments(text)
    m = re.search(r"^export interface " + name + r" \{\n(.*?)^\}", text, re.M | re.S)
    if not m:
        raise ValueError(f"contract.ts has no interface {name}")
    return re.findall(r"^\s*([A-Za-z_]\w*)\??:", m.group(1), re.M)


def _plain(value):
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


#: Every constant the webapp needs (WI-S01-4). A name missing from contract.ts is
#: a failure, so the check cannot pass by finding nothing.
TS_REQUIRED = (
    "CONTRACT_VERSION", "VIEWS",
    "ROUTE_ENSURE", "ROUTE_LEASES", "ROUTE_LEASE", "ROUTE_RECONCILE", "ROUTE_STOP_USER",
    "ROUTE_STOP_PROJECT", "ROUTE_STOP_ALL", "ROUTE_STATUS", "ROUTE_LIST",
    "INTERNAL_ROUTE_ENSURE", "INTERNAL_ROUTE_LEASE", "INTERNAL_ROUTE_RELEASE",
    "INTERNAL_ROUTE_LIST", "SESSION_ROUTE_STATUS", "AGENT_ROUTE_DROP", "AGENT_ROUTE_TUNNEL",
    "ERR_INVALID_PROJECT_ID", "ERR_INVALID_USER_ID", "ERR_INVALID_VIEW",
    "ERR_IMAGE_MISSING", "ERR_START_FAILED", "ERR_START_TIMEOUT", "ERR_UNKNOWN_INSTANCE",
    "ERR_NOT_RUNNING", "ERR_DRAINING", "ERR_RAM", "ERR_HARD", "ERR_USER_REFUSED",
    "ERR_PROJECT_REFUSED",
    "STATES", "LEASE_KINDS", "STOP_REASONS",
    "SANDBOX_STATUS", "SANDBOX_STATUS_STATES", "SANDBOX_STATUS_REASONS",
    "KALI_EXEC_STATUS_STARTING", "KALI_EXEC_ERROR_CODES", "SANDBOX_REFUSED",
    "MODAL_RAM_TITLE", "MODAL_RAM_BODY", "MODAL_HARD_TITLE", "MODAL_HARD_BODY",
    "MODAL_REFUSED_TITLE", "MODAL_REFUSED_BODY", "MODAL_RETRY_LABEL", "MODAL_CLOSE_LABEL",
    "PARTIAL_ANSWER_ONE", "PARTIAL_ANSWER_MANY", "SHARE_KEYS_LENT_TEXT",
    "HOLD_WARN_BEFORE_S", "HOLD_MAX_NO_USE_S", "START_TIMEOUT_S",
    "ORCHESTRATOR_ENSURE_TIMEOUT_S", "ENSURE_RUNNING_KEYS", "ENSURE_STARTING_KEYS",
)


def _ts_mismatches(ts_text: str) -> list[str]:
    ts = _ts_constants(ts_text)
    problems = []
    for name in TS_REQUIRED:
        if name not in ts:
            problems.append(f"{name} is missing from contract.ts")
    for name, ts_value in ts.items():
        if not hasattr(c, name):
            problems.append(f"contract.ts has {name}, which the Python contract does not")
        elif _plain(getattr(c, name)) != ts_value:
            problems.append(f"{name}: contract.ts {ts_value!r} != Python {_plain(getattr(c, name))!r}")
    return problems


def test_ts_constants_match():
    with open(TS_PATH, encoding="utf-8") as f:
        text = f.read()
    assert _ts_mismatches(text) == []
    assert set(TS_REQUIRED) <= set(_ts_constants(text))


def test_ts_check_fails_when_a_constant_is_missing_or_differs():
    with open(TS_PATH, encoding="utf-8") as f:
        text = f.read()
    without = re.sub(r"^export const START_TIMEOUT_S = .*$", "", text, count=1, flags=re.M)
    assert without != text
    assert "START_TIMEOUT_S is missing from contract.ts" in _ts_mismatches(without)
    changed = re.sub(r"^export const ROUTE_LIST = .*$", "export const ROUTE_LIST = 'x'",
                     text, count=1, flags=re.M)
    assert any(p.startswith("ROUTE_LIST:") for p in _ts_mismatches(changed))
    with pytest.raises(ValueError):
        _ts_constants("export const X = 1 + 2\n")


def _edit(text: str, pattern: str, replacement: str) -> str:
    edited = re.sub(pattern, lambda _m: replacement, text, count=1, flags=re.M)
    assert edited != text, pattern
    return edited


def test_ts_check_refuses_an_expression_or_a_hidden_constant():
    with open(TS_PATH, encoding="utf-8") as f:
        text = f.read()
    start = r"^export const START_TIMEOUT_S = 300$"
    # A literal that continues on the next line is another value at run time.
    for bad in (
        _edit(text, start, "export const START_TIMEOUT_S = 300\n  * 2"),
        _edit(text, r"^export const ERR_RAM = 'sandbox_ram'$",
              "export const ERR_RAM = 'sandbox_ram'\n  .replace('ram', 'hard')"),
        _edit(text, start, "export const START_TIMEOUT_S = 300 as const satisfies number"),
        _edit(text, start, "export const START_TIMEOUT_S: number = 300"),
        _edit(text, start, "export let START_TIMEOUT_S = 300"),
        _edit(text, start, "export const START_TIMEOUT_S = 300\nconst HIDDEN = 1"),
        _edit(text, start, "export const start_timeout_s = 300"),
    ):
        with pytest.raises(ValueError):
            _ts_mismatches(bad)
    # A constant inside a comment does not exist.
    for hidden in (_edit(text, start, "/* export const START_TIMEOUT_S = 300 */"),
                   _edit(text, start, "/*\nexport const START_TIMEOUT_S = 300\n*/"),
                   _edit(text, start, "// export const START_TIMEOUT_S = 300")):
        assert "START_TIMEOUT_S is missing from contract.ts" in _ts_mismatches(hidden)
    # `//` inside a string is not a comment: the whole value is compared.
    sliced = _edit(text, r"^export const ROUTE_LIST = .*$",
                   "export const ROUTE_LIST = '/sandboxes//x'")
    assert any(p.startswith("ROUTE_LIST:") for p in _ts_mismatches(sliced))


def test_ensure_answers_carry_fresh():
    # A start the gateway caused writes the sandbox.started row and turns the
    # person's tunnels off; a non-waiting ensure (the ws-ticket warm-up) creates
    # the instance too, so the 202 answer must say so as well.
    assert "fresh" in c.ENSURE_STARTING_KEYS and "fresh" in c.ENSURE_RUNNING_KEYS
    assert c.ENSURE_STARTING_KEYS == ("state", "instance", "fresh")
    with open(TS_PATH, encoding="utf-8") as f:
        text = f.read()
    assert _ts_interface_keys(text, "EnsureStarting") == list(c.ENSURE_STARTING_KEYS)
    assert _ts_interface_keys(text, "EnsureRunning") == list(c.ENSURE_RUNNING_KEYS)
    assert re.search(r"^export interface EnsureStarting \{[^}]*^  fresh: boolean$", text, re.M)


# --- the mount plan (T5, I9, D16) -----------------------------------------------------


def _workspace_targets(mounts):
    return {m.target for m in mounts if m.kind == c.MOUNT_WORKSPACE}


def test_mount_plan_has_only_allowed_projects():
    alice = c.mount_targets(ALICE, "own", [P_ALICE_2, P_ALICE_1, P_ALICE_1])
    bob = c.mount_targets(BOB, "own", [P_BOB_1])
    assert _workspace_targets(alice) == {f"/workspace/{P_ALICE_1}", f"/workspace/{P_ALICE_2}"}
    assert _workspace_targets(bob) == {f"/workspace/{P_BOB_1}"}
    assert not _workspace_targets(alice) & _workspace_targets(bob)
    # One mount per project, sorted, the rel naming exactly that project folder.
    ws = [m for m in alice if m.kind == c.MOUNT_WORKSPACE]
    assert [m.rel for m in ws] == sorted({P_ALICE_1, P_ALICE_2})
    assert all(m.target == f"/workspace/{m.rel}" and not m.read_only for m in ws)
    # An empty list is a sandbox with no project folder.
    assert _workspace_targets(c.mount_targets(ALICE, "own", [])) == set()
    for mounts in (alice, bob):
        assert "/workspace" not in {m.target for m in mounts}


def test_mount_plan_never_mounts_workspace_root_or_staging():
    rng = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    for _ in range(200):
        ids = ["".join(rng.choice(alphabet[:62]) + "".join(
            rng.choice(alphabet) for _ in range(rng.randint(0, 40))))
            for _ in range(rng.randint(0, 6))]
        for view in c.VIEWS:
            for m in c.mount_targets(ALICE, view, ids):
                assert m.target != "/workspace"
                assert not m.target.startswith("/workspace/.")
                assert m.target.rstrip("/") == m.target
    mounts = c.mount_targets(ALICE, "own", [P_ALICE_1])
    kinds = {m.kind for m in mounts}
    assert kinds == {"workspace", "output", "servers", "graph_db", "custom_templates",
                     "volume:templates", "volume:osv"}
    # Nothing else: no Docker socket, no secret, no other folder.
    targets = {m.target for m in mounts}
    assert targets == {f"/workspace/{P_ALICE_1}", "/opt/output", "/opt/mcp_servers",
                       "/opt/graph_db", "/opt/nuclei-templates", "/root/nuclei-templates",
                       "/osv-db"}
    assert not any("docker.sock" in m.target or "docker.sock" in m.rel for m in mounts)
    read_only = {m.target for m in mounts if m.read_only}
    assert read_only == targets - {f"/workspace/{P_ALICE_1}", "/opt/output"}
    # The empty custom templates folder is left out on request.
    assert "/opt/nuclei-templates" not in {
        m.target for m in c.mount_targets(ALICE, "own", [], custom_templates=False)}
    # Every host-side kind has its orchestrator mount; volumes name their volume.
    for m in mounts:
        if m.kind.startswith("volume:"):
            assert m.rel
        else:
            assert c.MOUNT_HOST_BASES[m.kind].startswith("/app/")
    osv = [m for m in c.mount_targets(ALICE, "own", [], osv_volume="custom-osv") if m.kind == "volume:osv"]
    assert osv[0].rel == "custom-osv"
    tpl = [m for m in mounts if m.kind == "volume:templates"]
    assert tpl[0].rel == c.TEMPLATES_VOLUME == "redamon-kali-nuclei-templates"


BAD_PROJECT_IDS = [
    ".", "..", ".staging", "a/b", "a\\b", "/etc", "x..y", "", "a" * 65, "ünïcode", "id\n",
    # whitespace, encodings, look-alikes, separators, reserved names, leading punctuation
    " abc", "abc ", "abc\t", "a b", "%2e%2e", "..%2f", "abc\x00", "ａｂｃ", "аbc",
    "a:b", "a.b", "-abc", "_abc", "CON", "nul", "Com1", "lpt9", "​abc",
]


@pytest.mark.parametrize("bad", BAD_PROJECT_IDS)
def test_mount_plan_refuses_bad_project_ids(bad):
    with pytest.raises(ValueError, match="invalid_project_id"):
        c.mount_targets(ALICE, "own", [P_ALICE_1, bad])
    with pytest.raises(ValueError, match="invalid_project_id"):
        c.projects_hash([bad])


@pytest.mark.parametrize("bad_list", [P_ALICE_1, P_ALICE_1.encode(), None, 5, [None], [5], [b"abc"]])
def test_mount_plan_refuses_a_project_list_that_is_not_a_list_of_ids(bad_list):
    # A bare string would otherwise iterate into one mount per character.
    with pytest.raises(ValueError, match="invalid_project_id"):
        c.mount_targets(ALICE, "own", bad_list)


def test_mount_plan_refuses_bad_volume_names():
    for bad in ("", "../x", "a/b", "/var/run/docker.sock", " x"):
        with pytest.raises(ValueError):
            c.mount_targets(ALICE, "own", [], osv_volume=bad)


def test_output_folder_is_per_person():
    def output(user, view="own"):
        (m,) = [m for m in c.mount_targets(user, view, []) if m.kind == c.MOUNT_OUTPUT]
        assert m.target == "/opt/output" and not m.read_only
        return m.rel

    assert output(ALICE) == f"users/{c.sandbox_key(ALICE, 'own')}"
    assert len({output(ALICE), output(BOB), output(CAROL)}) == 3
    for rel in (output(ALICE), output(BOB)):
        assert re.fullmatch(r"users/[0-9a-f]{16}", rel)
        assert ALICE not in rel and BOB not in rel
    assert c.person_output_rels(ALICE) == (output(ALICE, "own"), output(ALICE, "act_as"))


def test_projects_from_destinations_reads_back_the_plan():
    mounts = c.mount_targets(ALICE, "own", [P_ALICE_2, P_ALICE_1])
    dests = [m.target for m in mounts] + ["/tmp/x", "/workspacefoo/x"]
    assert c.projects_from_destinations(dests) == sorted([P_ALICE_1, P_ALICE_2])
    for bad in (["/workspace"], ["/workspace/"], ["/workspace/.staging"], ["/workspace/a/b"]):
        with pytest.raises(ValueError):
            c.projects_from_destinations(bad)


# --- views, names and keys (TD-26, S7, E4, E3, D24, I10) -------------------------------


def test_act_as_view_has_its_own_key_network_and_output():
    inst = c.new_instance()
    own_key, act_key = c.sandbox_key(ALICE, "own"), c.sandbox_key(ALICE, "act_as")
    assert own_key != act_key
    assert own_key == c.user_key(ALICE)
    assert c.network_name(ALICE, "own") != c.network_name(ALICE, "act_as")
    assert c.container_name(ALICE, "own", inst) != c.container_name(ALICE, "act_as", inst)
    assert c.person_output_rels(ALICE)[0] != c.person_output_rels(ALICE)[1]
    others = {c.sandbox_key(u, v) for u in (BOB, CAROL) for v in c.VIEWS}
    assert own_key not in others and act_key not in others
    for bad_view in ("", "OWN", "own ", "act-as", "shared", None, "admin"):
        with pytest.raises(ValueError, match="invalid_view"):
            c.sandbox_key(ALICE, bad_view)
        with pytest.raises(ValueError):
            c.mount_targets(ALICE, bad_view, [])


def test_network_plan_is_private_per_user():
    names = {c.network_name(u, v) for u in (ALICE, BOB, CAROL) for v in c.VIEWS}
    assert len(names) == 6
    for name in names:
        assert name not in ("redamon-network", "redamon_pentest-net", "bridge", "host", "none")
        assert re.fullmatch(r"redamon-sbx-[0-9a-f]{16}", name)
    labels = c.network_labels(ALICE, "act_as")
    assert labels == {"redamon.sandbox": "1", "redamon.sandbox.user": ALICE,
                      "redamon.sandbox.view": "act_as",
                      "redamon.sandbox.key": c.sandbox_key(ALICE, "act_as")}
    pool = ipaddress.ip_network("10.214.0.0/16")
    assert c.SUBNET_POOL == "10.214.0.0/16" and c.SUBNET_PREFIX == 28
    assert c.allocate_subnet([]) == "10.214.0.0/28"
    assert c.gateway_for("10.214.0.0/28") == "10.214.0.1"
    # Existing Docker networks of every shape: the pick never overlaps one.
    used = ["10.214.0.0/28", "172.17.0.0/16", "10.214.0.16/30", "", None,
            "fd00::/64", ipaddress.ip_network("10.214.0.64/26")]
    assert c.allocate_subnet(used) == "10.214.0.32/28"
    rng = random.Random(3)
    taken: list = []
    for _ in range(300):
        prefix = rng.choice([24, 26, 27, 28, 29, 30])
        base = rng.randrange(0, 1 << 16)
        noise = ipaddress.ip_network((int(pool.network_address) + base, prefix), strict=False)
        got = ipaddress.ip_network(c.allocate_subnet(taken + [noise]))
        assert got.prefixlen == 28 and got.subnet_of(pool)
        assert not got.overlaps(noise)
        assert not any(got.overlaps(ipaddress.ip_network(t)) for t in taken)
        taken.append(str(got))
    # A supernet covering the pool, or a full pool, is exhausted, never an overlap.
    for blocker in (["10.0.0.0/8"], ["10.214.0.0/16"], [str(s) for s in pool.subnets(new_prefix=28)]):
        with pytest.raises(c.SubnetPoolExhausted):
            c.allocate_subnet(blocker)
    with pytest.raises(ValueError):
        c.allocate_subnet(["not-a-subnet"])


def test_two_users_never_share_a_container_or_network_name():
    users = [ALICE, BOB, CAROL] + [f"user{i:04d}" for i in range(60)]
    containers, networks, reservations, keys = set(), set(), set(), set()
    for u in users:
        for v in c.VIEWS:
            keys.add(c.sandbox_key(u, v))
            networks.add(c.network_name(u, v))
            for _ in range(3):
                inst = c.new_instance()
                assert re.fullmatch(r"[0-9a-f]{6}", inst)
                containers.add(c.container_name(u, v, inst))
                reservations.add(c.reservation_key(u, inst))
    assert len(keys) == len(networks) == len(users) * 2
    assert len(containers) == len(users) * 2 * 3
    assert len(reservations) == len(users) * 2 * 3
    assert all(r.startswith(c.RESERVATION_PREFIX) for r in reservations)
    name = c.container_name(ALICE, "own", "a1b2c3")
    assert name == f"redamon-kali-{c.sandbox_key(ALICE, 'own')}-a1b2c3"
    assert c.reservation_key(ALICE, "a1b2c3") == f"kali_sandbox:{ALICE}:a1b2c3"
    for bad in ("", "shared", "A1B2C3", "a1b2c", "a1b2c3d", "../x1", "a1b2c\n"):
        with pytest.raises(ValueError):
            c.container_name(ALICE, "own", bad)
        with pytest.raises(ValueError):
            c.reservation_key(ALICE, bad)


BAD_USER_IDS = ["", "a" * 65, "a b", "a/b", "../x", "act_as:x", "ünï", "id\n", "a.b",
                None, 7, "ensure", "stop-all", "stop-project"]


@pytest.mark.parametrize("bad", BAD_USER_IDS)
def test_bad_user_ids_get_no_key(bad):
    # An empty id would give every caller without a person the same sandbox; a
    # route word would make GET /sandboxes/<id> unreachable.
    with pytest.raises(ValueError, match="invalid_user_id"):
        c.user_key(bad)
    with pytest.raises(ValueError, match="invalid_user_id"):
        c.sandbox_key(bad, "own")
    with pytest.raises(ValueError, match="invalid_user_id"):
        c.instance_env(bad, "own", "a1b2c3")


def test_id_formats_accept_database_ids():
    for uid in (ALICE, BOB, CAROL, "4f9c2a1e-8b7d-4c3a-9e2f-1a2b3c4d5e6f", "a", "a" * 64):
        assert c.valid_user_id(uid), uid
    for pid in (P_ALICE_1, P_ALICE_2, "4f9c2a1e-8b7d-4c3a-9e2f-1a2b3c4d5e6f", "a", "a" * 64):
        assert c.valid_project_id(pid), pid


def test_container_labels_and_projects_hash():
    labels = c.container_labels(ALICE, "own", "a1b2c3", [P_ALICE_2, P_ALICE_1],
                                created=1_700_000_000.9, port=40001, servers="0123456789abcdef")
    assert labels == {
        "redamon.sandbox": "1", "redamon.sandbox.user": ALICE, "redamon.sandbox.view": "own",
        "redamon.sandbox.key": c.sandbox_key(ALICE, "own"), "redamon.sandbox.instance": "a1b2c3",
        "redamon.sandbox.projects": c.projects_hash([P_ALICE_1, P_ALICE_2]),
        "redamon.sandbox.created": "1700000000", "redamon.sandbox.port": "40001",
        "redamon.sandbox.servers": "0123456789abcdef", "redamon.sandbox.contract": "1",
    }
    assert c.container_labels(ALICE, "own", "a1b2c3", [], created=1, port=None,
                              servers="x")["redamon.sandbox.port"] == ""
    assert c.projects_hash([P_ALICE_1, P_ALICE_2]) == c.projects_hash([P_ALICE_2, P_ALICE_1, P_ALICE_1])
    assert c.projects_hash([P_ALICE_1]) != c.projects_hash([P_ALICE_1, P_ALICE_2])
    assert re.fullmatch(r"[0-9a-f]{16}", c.projects_hash([]))
    assert c.templates_labels() == {"redamon.sandbox": "1", "redamon.sandbox.role": "templates"}


def test_servers_fingerprint_follows_code_and_ignores_bytecode(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("y = 2\n")
    first = c.servers_fingerprint(str(tmp_path))
    assert re.fullmatch(r"[0-9a-f]{16}", first)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "a.cpython-311.pyc").write_bytes(b"\0" * 10)
    (tmp_path / "sub" / "b.pyc").write_bytes(b"\0")
    (tmp_path / ".pytest_cache").mkdir()
    (tmp_path / ".pytest_cache" / "v").write_text("z")
    assert c.servers_fingerprint(str(tmp_path)) == first
    (tmp_path / "sub" / "b.py").write_text("y = 22\n")
    assert c.servers_fingerprint(str(tmp_path)) != first
    assert c.servers_hash([("a.py", 1, 2)]) != c.servers_hash([("a.py", 1, 3)])
    assert c.servers_hash([("a.py", 1, 2), ("b.py", 1, 2)]) == c.servers_hash([("b.py", 1, 2), ("a.py", 1, 2)])


# --- the container (I10, S5, D22) ------------------------------------------------------


def test_container_env_has_its_own_tokens_and_no_platform_secret():
    inst = "a1b2c3"
    first = c.container_env(ALICE, "own", inst, None, environ={})
    second = c.container_env(ALICE, "own", inst, None, environ={})
    for key in ("MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN"):
        assert len(first[key]) >= 32 and len(second[key]) >= 32
        assert first[key] != second[key]
    assert first["MCP_AUTH_TOKEN"] != first["TUNNEL_AUTH_TOKEN"]
    for env in (first, second, c.container_env(BOB, "act_as", inst, 40001, environ={})):
        assert not set(env) & set(c.NEVER_IN_ENV)
        for value in env.values():
            assert isinstance(value, str)
            assert value not in (ALICE, BOB)
            assert ALICE not in value and BOB not in value
    assert first["REDAMON_SANDBOX_KEY"] == c.sandbox_key(ALICE, "own")
    assert first["MSF_REVERSE_PORT"] == "4444"
    assert c.instance_env(ALICE, "own", inst, 40001, environ={})["MSF_REVERSE_PORT"] == "40001"
    assert first["REDAMON_SANDBOX_MODE"] == "per_user"
    assert first["WEBAPP_API_URL"] == ""
    assert first["MSF_AUTO_UPDATE"] == first["NUCLEI_AUTO_UPDATE"] == "false"
    for name in ("INTERNAL_API_KEY", "SCANNER_API_KEY", "AUTH_SECRET", "ORCHESTRATOR_API_KEY",
                 "DATABASE_URL", "POSTGRES_PASSWORD", "NEO4J_PASSWORD", "NGROK_AUTHTOKEN"):
        assert name in c.NEVER_IN_ENV
    # The orchestrator's own secrets never ride along, whatever its environment holds.
    leaky = {name: "secret-value" for name in c.NEVER_IN_ENV}
    leaky["TERMINAL_MAX_SESSIONS"] = " 3 "
    env = c.container_env(ALICE, "own", inst, None, environ=leaky)
    assert "secret-value" not in env.values()
    assert env["TERMINAL_MAX_SESSIONS"] == "3"
    for raw in ("", "x", "-1", "3; rm", "²"):
        assert "TERMINAL_MAX_SESSIONS" not in c.instance_env(
            ALICE, "own", inst, None, environ={"TERMINAL_MAX_SESSIONS": raw})
    for bad_port in (0, 65536, -1, "4444", True):
        with pytest.raises(ValueError):
            c.instance_env(ALICE, "own", inst, bad_port, environ={})
    # The fixed environment is read-only, so one instance's tokens cannot leak into the next.
    with pytest.raises(TypeError):
        c.CONTAINER_ENV_FIXED["MCP_AUTH_TOKEN"] = "x"


def test_limits_per_container():
    gib = 1 << 30
    for cpus in (None, 0, 1, 2, 3, 4, 8, 12, 64):
        lim = c.limits(gib, cpus)
        assert lim["mem_limit"] == lim["memswap_limit"] == gib
        assert lim["pids_limit"] == 4096
        assert 1_000_000_000 <= lim["nano_cpus"] <= 4_000_000_000
        assert lim["nano_cpus"] % 1_000_000_000 == 0
    assert c.limits(gib, 12)["nano_cpus"] == 4_000_000_000
    assert c.limits(gib, 6)["nano_cpus"] == 3_000_000_000
    assert c.limits(gib, 2)["nano_cpus"] == 1_000_000_000
    for bad in (0, -1, None, "1g", 1.5, True):
        with pytest.raises(ValueError):
            c.limits(bad, 4)
    assert c.ENVELOPE_DEFAULT_BYTES == gib
    assert c.ENVELOPE_PROFILE_KEY == "kali_sandbox_envelope_bytes"


def test_healthcheck_probes_every_server_port():
    hc = c.healthcheck(c.START_TIMEOUT_S)
    assert hc["test"][:3] == ["CMD", "python3", "-c"]
    probe = hc["test"][3]
    compile(probe, "<probe>", "exec")
    assert c.HEALTH_PROBE_PORTS == (8000, 8002, 8003, 8004, 8005, 8013, 8015, 8016)
    for port in c.HEALTH_PROBE_PORTS:
        assert str(port) in probe
    assert hc["interval"] == hc["timeout"] == 2_000_000_000
    assert hc["retries"] == 3
    assert hc["start_period"] == c.START_TIMEOUT_S * 1_000_000_000
    assert hc["start_interval"] == 1_000_000_000


def test_published_ports_only_the_pool_port():
    assert c.published_ports(None) == {}
    assert c.published_ports(40001) == {"40001/tcp": ("127.0.0.1", 40001)}
    assert c.published_ports(40001, "192.168.1.5") == {"40001/tcp": ("192.168.1.5", 40001)}


# --- variables (B.14) -----------------------------------------------------------------


def test_env_parsers_defaults():
    for raw in ("", "x", "0", "-1", None, "1.5", " ", "²", "9" * 20):
        assert c.idle_minutes(raw) == 20, raw
    assert c.idle_minutes("1") == 1
    assert c.idle_minutes(" 45 ") == 45
    assert c.max_concurrent("") is None
    assert c.max_concurrent(None) is None
    assert c.max_concurrent("0") == 0
    assert c.max_concurrent(" 3 ") == 3
    for raw in ("x", "-1", "1.5", "9" * 20):
        assert c.max_concurrent(raw) is None, raw
    pool = c.port_pool("40000-40010")
    assert pool == c.PortPool("127.0.0.1", 40000, 40010)
    assert list(pool.ports()) == list(range(40000, 40011))
    assert c.port_pool("0.0.0.0:40000-40001") == c.PortPool("0.0.0.0", 40000, 40001)
    assert c.port_pool(" 192.168.1.5:41000-41000 ") == c.PortPool("192.168.1.5", 41000, 41000)
    assert c.port_pool("[::1]:40000-40001") == c.PortPool("::1", 40000, 40001)
    for raw in ("", None, "x", "40000", "40010-40000", "0-10", "1-65536", "host:40000-40001",
                "999.1.1.1:40000-40001", ":40000-40001", "127.0.0.1:", "40000-40001-40002",
                "40000 - 40001"):
        assert c.port_pool(raw) is None, raw
    assert c.ENV_VARS == ("KALI_SANDBOX_IDLE_MINUTES", "KALI_SANDBOX_MAX_CONCURRENT",
                          "KALI_SANDBOX_PORT_POOL")


def test_the_pool_never_hands_out_the_default_reverse_port():
    # A sandbox without a pool port listens on 4444, which the agent reads as "nothing
    # published" (agentic/utils.py): a pool port of 4444 would tell its person the same.
    assert c.DEFAULT_REVERSE_PORT == 4444
    assert list(c.port_pool("4440-4449").ports()) == [4440, 4441, 4442, 4443, 4445, 4446,
                                                      4447, 4448, 4449]
    assert list(c.port_pool("0.0.0.0:4444-4444").ports()) == []
    assert list(c.port_pool("4450-4452").ports()) == [4450, 4451, 4452]
    assert list(agent_copy.port_pool("4443-4445").ports()) == [4443, 4445]


def test_guest_sysctls_turn_forwarding_off():
    assert dict(c.GUEST_SYSCTLS) == {"net.ipv4.ip_forward": "0"}
    assert c.GUEST_GATEWAY_PRIORITY == -1000
    with pytest.raises(TypeError):
        c.GUEST_SYSCTLS["net.ipv4.ip_forward"] = "1"


def test_timeouts_are_ordered():
    assert 300 <= c.START_TIMEOUT_S <= 600
    assert c.START_TIMEOUT_S < c.ORCHESTRATOR_ENSURE_TIMEOUT_S < c.GATEWAY_ENSURE_TIMEOUT_S
    assert c.ORCHESTRATOR_ENSURE_TIMEOUT_S == c.START_TIMEOUT_S + 15
    assert c.GATEWAY_ENSURE_TIMEOUT_S == c.START_TIMEOUT_S + 30
    assert c.FANOUT_TIMEOUT_S < c.GATEWAY_TIMEOUT_S == 10
    assert c.LEASE_RENEW_S * 2 < c.LEASE_TTL_S
    assert c.HOLD_WARN_BEFORE_S < c.HOLD_MAX_NO_USE_S
    assert c.IDLE_CHECK_S < c.IDLE_MINUTES_DEFAULT * 60


def test_lease_kinds_and_states():
    assert c.LEASE_KINDS == ("run", "terminal", "exec", "job", "triage", "tradecraft",
                             "interact", "hold")
    assert c.USE_KINDS == tuple(k for k in c.LEASE_KINDS if k != "hold")
    assert c.STATES == ("starting", "running", "draining", "stopping")
    assert "account_deleted" in c.STOP_REASONS and len(set(c.STOP_REASONS)) == 11
    for code, status in c.ERROR_STATUS.items():
        assert status in (400, 403, 404, 409, 503, 504), code


#: The switch and the shared container's names, gone with the shared mode (S20).
SWITCH_NAMES = ("MODE_ENV", "MODE_SHARED", "MODE_PER_USER", "MODES", "DEFAULT_MODE",
                "mode_from_env", "ROUTE_MODE", "SHARED_INSTANCE")


def test_the_switch_is_gone_from_every_copy():
    for copy in (c, agent_copy):
        assert [n for n in SWITCH_NAMES if hasattr(copy, n)] == []
        assert "mode" not in copy.ENSURE_RUNNING_KEYS and "mode" not in copy.ENSURE_STARTING_KEYS
        assert "mode" not in copy.RESERVED_USER_IDS
    with open(ORCH_PATH, encoding="utf-8") as f:
        assert "KALI_SANDBOX_MODE" not in f.read()
    with open(TS_PATH, encoding="utf-8") as f:
        text = f.read()
    assert [n for n in SWITCH_NAMES if n in _ts_constants(text)] == []
    assert "/sandboxes/mode" not in text and "SandboxMode" not in text
    assert "EnsureShared" not in text
    for interface in ("EnsureRunning", "EnsureStarting"):
        assert "mode" not in _ts_interface_keys(text, interface)
    # The sandbox still tells the servers inside it they run for one person
    # (mcp/servers/tunnel_manager.py and metasploit_server.py read it).
    assert c.CONTAINER_ENV_FIXED["REDAMON_SANDBOX_MODE"] == "per_user"


# --- no code reaches the shared container (WI-S20-5) ---------------------------------

#: Code only: tests may name the old address to assert nothing calls it.
_NOT_CODE = re.compile(r"(^|/)(tests?|tests_live|__tests__|node_modules|__testing__)/|\.test\.tsx?$|(^|/)test_[^/]*\.py$"
                       r"|_test\.sh$|conftest\.py$|\.spec\.ts$")
_CODE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".sh", ".json")


#: Folders that hold results or a person's files, not code, by their path from the root: a
#: folder's name alone would also skip code (webapp/src/app/api/plugin-gateway/v1/data/).
_NOT_SCANNED = re.compile(r"^(scanners/[^/]+/output|agentic/agent-workspace|agentic/logs"
                          r"|(agentic|services)/knowledge_base/data)$")


def _code_files(*roots):
    for root in roots:
        for folder, dirs, files in os.walk(os.path.join(ROOT, root)):
            here = os.path.relpath(folder, ROOT).replace(os.sep, "/")
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".next", "__pycache__", ".venv", "venv")
                       and not _NOT_SCANNED.match(f"{here}/{d}")]
            for name in files:
                path = os.path.join(folder, name)
                rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
                if name.endswith(_CODE_SUFFIXES) and not _NOT_CODE.search(rel):
                    yield rel, path


def _hits(pattern, *roots):
    found = []
    for rel, path in _code_files(*roots):
        with open(path, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                if pattern.search(line):
                    found.append(f"{rel}:{n}: {line.strip()[:120]}")
    return found


def test_no_code_dials_the_shared_container():
    # Its addresses, the variables that named them, and its one MCP token.
    pattern = re.compile(r"(https?|wss?)://kali-sandbox[:/]|\bMCP_NETWORK_RECON_URL\b"
                         r"|\bMCP_(NUCLEI|METASPLOIT|NMAP|PLAYWRIGHT|METASPLOIT_PROGRESS|HYDRA_PROGRESS)_URL\b"
                         r"|\bKALI_TERMINAL_WS_URL\b")
    assert _hits(pattern, "agentic", "webapp/src", "recon_orchestrator") == []


def test_the_agent_reads_no_shared_kali_token():
    # Each sandbox has its own two tokens, handed out by the orchestrator; the shared
    # container's (still in an old .env) must never ride on a Kali call.
    pattern = re.compile(r"""(environ(\.get)?\(|environ\[|getenv\(|token_env_var\s*=)\s*["'](MCP|TUNNEL)_AUTH_TOKEN""")
    assert _hits(pattern, "agentic") == []


#: A quoted, backticked or URL `kali-sandbox` host, in every service that dials containers.
_SHARED_HOST = re.compile(r"""["'`]kali-sandbox["'`]|(https?|wss?)://kali-sandbox\b|["'`]kali-sandbox:\d""")
_HOST_ROOTS = ("agentic", "webapp/src", "recon_orchestrator", "services", "graph_db", "scanners")


def test_no_code_names_the_shared_container_as_a_host():
    # Docker makes a container's hostname a DNS name on its network, and the agent joins
    # every sandbox network: a bare "kali-sandbox" (a default, an `or` fallback) can
    # resolve to one person's sandbox. Only the contract names it, for the sandbox's own
    # /etc/hosts.
    hits = [h for h in _hits(_SHARED_HOST, *_HOST_ROOTS) if not h.split(":", 1)[0].endswith("/sandbox_contract.py")]
    assert hits == []


def test_a_sandbox_is_its_own_kali_sandbox_and_nobody_else_s():
    for copy in (c, agent_copy):
        assert not hasattr(copy, "CONTAINER_HOSTNAME")
        assert dict(copy.EXTRA_HOSTS) == {"kali-sandbox": "127.0.0.1"}
        assert copy.SELF_NAME == "kali-sandbox"
        with pytest.raises(TypeError):
            copy.EXTRA_HOSTS["kali-sandbox"] = "10.214.0.2"
    # The hostname each sandbox gets (its container name) never repeats across persons,
    # views or instances, so no name is shared on a network the agent joins.
    names = {c.container_name(u, v, i) for u in (ALICE, BOB) for v in c.VIEWS for i in ("a1b2c3", "d4e5f6")}
    assert len(names) == 8 and c.SELF_NAME not in names


def test_no_text_tells_a_user_the_sandbox_is_shared():
    pattern = re.compile(r"shared with every other project|sandbox shared by every project"
                         r"|a shared sandbox where every project|Shared environment: other projects",
                         re.I)
    assert _hits(pattern, "webapp/src") == []


def test_the_static_checks_find_what_they_look_for():
    # The walk would pass by finding nothing: it must see real code and skip tests.
    seen = {rel for rel, _ in _code_files("agentic", "webapp/src", "recon_orchestrator")}
    assert "agentic/sandbox_router.py" in seen and "webapp/src/lib/sandbox/gateway.ts" in seen
    assert "recon_orchestrator/sandbox_manager.py" in seen
    assert not any(_NOT_CODE.search(rel) for rel in seen)
    assert _NOT_CODE.search("agentic/tests/test_x.py") and _NOT_CODE.search("webapp/src/a.test.ts")
    assert not _NOT_CODE.search("webapp/src/lib/sandbox/contract.ts")
    assert _NOT_CODE.search("services/plugin_runner/tests_live/probe.py")
    for planted in ('url = "kali-sandbox"', "host || 'kali-sandbox'", "const h = `kali-sandbox`",
                    'base = "kali-sandbox:8013"', "ws://kali-sandbox/x"):
        assert _SHARED_HOST.search(planted), planted
    assert not _SHARED_HOST.search("The listener runs inside kali-sandbox on 4444.")
    seen_hosts = {rel.split("/", 1)[0] for rel, _ in _code_files("services", "graph_db", "scanners")}
    assert {"services", "graph_db", "scanners"} <= seen_hosts
    assert "webapp/src/app/api/plugin-gateway/v1/data/get/route.ts" in seen
    assert _NOT_SCANNED.match("scanners/gvm_scan/output") and _NOT_SCANNED.match("agentic/agent-workspace")
    assert not _NOT_SCANNED.match("webapp/src/app/api/plugin-gateway/v1/data")
