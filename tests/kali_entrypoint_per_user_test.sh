#!/usr/bin/env bash
# =============================================================================
# The Kali image starts as a per-user sandbox (group 1: I9) and refreshes its
# Metasploit modules in one cheap layer (TD-14).
# Run:  bash tests/kali_entrypoint_per_user_test.sh
#
# A per-user sandbox (REDAMON_SANDBOX_MODE=per_user, which the orchestrator sets
# from CONTAINER_ENV_FIXED in recon_orchestrator/sandbox_contract.py) must never
# ask the webapp for the instance-wide tunnel config: the agent pushes that
# person's own config. The shared container, where the variable is unset, keeps
# today's boot sync. The entrypoint's deferred_init is cut out and run with curl,
# msfconsole, nuclei and sleep stubbed, so what each mode sends is observed.
#
# The Dockerfile: ARG MSF_REFRESH_STAMP in the final stage, before `msfdb init`;
# the stamp is only tested for emptiness and copied into the redamon.msf_refresh
# label (the last instruction before ENTRYPOINT), never run as code; no secret
# reaches the build as an argument. The refresh RUN is cut out and run with only
# stubs on PATH, hostile stamps included.
#
# Exits 77 (the gate's "cannot run") when python3, PyYAML or a file it reads is
# missing.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="$REPO_ROOT/mcp/kali-sandbox/entrypoint.sh"
DOCKERFILE="$REPO_ROOT/mcp/kali-sandbox/Dockerfile"
CONTRACT="$REPO_ROOT/recon_orchestrator/sandbox_contract.py"

for f in "$ENTRYPOINT" "$DOCKERFILE" "$CONTRACT"; do
    [[ -f "$f" ]] || { echo "CANNOT RUN: $f is missing"; exit 77; }
done
command -v python3 >/dev/null 2>&1 || { echo "CANNOT RUN: python3 is not installed"; exit 77; }
python3 -c 'import yaml' 2>/dev/null || { echo "CANNOT RUN: PyYAML is not installed for python3"; exit 77; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
finish() {
    echo
    echo "kali_entrypoint_per_user: $PASS passed, $FAIL failed"
    [[ "$FAIL" -eq 0 ]]
    exit
}

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
STUBS="$SANDBOX/bin"
CALLS="$SANDBOX/calls"
mkdir -p "$STUBS"

# One stub for every external command the cut-out code may run: it records its
# argv (one line, each argument in brackets) and, for curl, its stdin. Builtins
# only, so it also works with nothing else on PATH.
cat > "$STUBS/stub" <<'SH'
#!/bin/sh
name="${0##*/}"
{ printf '%s' "$name"; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$CALLS"
case "$name" in
    curl) while IFS= read -r line; do printf '%s\n' "$line"; done >> "$CALLS.stdin"
          exit "${STUB_CURL_RC:-0}" ;;
    apt-get) exit "${STUB_APT_RC:-0}" ;;
esac
exit 0
SH
chmod +x "$STUBS/stub"
for tool in curl msfconsole nuclei sleep apt-get rm; do
    ln -s stub "$STUBS/$tool"
done
calls() { grep -c "^$1" "$CALLS"; }

# A fake token: never a real credential.
TOKEN="s08-fake-tunnel-token-0123456789"

echo "== the entrypoint parses, and the contract names the per-user mode =="
if bash -n "$ENTRYPOINT" 2>/dev/null; then ok "entrypoint.sh parses (bash -n)"; else bad "entrypoint.sh parses (bash -n)" "a syntax error" "none"; fi

PER_USER="$(python3 -I - "$CONTRACT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("sandbox_contract", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
print(mod.CONTAINER_ENV_FIXED["REDAMON_SANDBOX_MODE"])
PY
)"
eq "the orchestrator starts sandboxes with REDAMON_SANDBOX_MODE=per_user" "$PER_USER" "per_user"

LIVE="$(grep -v '^[[:space:]]*#' "$ENTRYPOINT")"
eq "msfdb init still runs before the servers" "$(grep -cxF 'msfdb init 2>/dev/null || true' <<<"$LIVE")" "1"
eq "deferred_init still runs in the background" "$(grep -cxF 'deferred_init &' <<<"$LIVE")" "1"

BLOCK="$(awk '/^deferred_init\(\) \{$/{on=1} on{print} on && /^\}$/{exit}' "$ENTRYPOINT")"
case "$BLOCK" in
    *'/api/global/tunnel-config/sync'*'Initialization complete'*) ok "cut deferred_init out of the entrypoint" ;;
    *) bad "cut deferred_init out of the entrypoint" "${BLOCK:0:60}" "the function with the tunnel sync"
       finish ;;
esac

# run_init VAR=value...: runs deferred_init under `set -e`, as the entrypoint's
# background job does, with both auto-updates off unless the arguments say
# otherwise; prints its output, records the stubs' calls in $CALLS.
run_init() {
    : > "$CALLS"; : > "$CALLS.stdin"
    env -i PATH="$STUBS:/usr/bin:/bin" HOME="$SANDBOX" CALLS="$CALLS" STUB_CURL_RC="${STUB_CURL_RC:-0}" \
        MSF_AUTO_UPDATE=false NUCLEI_AUTO_UPDATE=false "$@" \
        bash -c 'set -e; eval "$1"; deferred_init' _ "$BLOCK" </dev/null 2>&1
}

echo "== a per-user sandbox never asks the webapp for tunnels =="
out="$(run_init REDAMON_SANDBOX_MODE="$PER_USER" TUNNEL_AUTH_TOKEN="$TOKEN")"; rc=$?
eq "per-user: deferred_init succeeds" "$rc" "0"
eq "per-user: no call to the webapp" "$(calls curl)" "0"
eq "per-user: one line says the agent pushes the tunnels" "$(grep -c 'tunnels are pushed by the agent' <<<"$out")" "1"
eq "per-user: no sync is requested" "$(grep -c 'Requesting tunnel config sync' <<<"$out")" "0"
eq "per-user: the deferred init completes" "$(grep -c 'Initialization complete' <<<"$out")" "1"
eq "per-user: auto-updates off run neither msfconsole nor nuclei" "$(grep -cE '^(msfconsole|nuclei)' "$CALLS")" "0"
eq "per-user: the token is printed nowhere" "$(grep -cF "$TOKEN" <<<"$out")" "0"

out="$(run_init REDAMON_SANDBOX_MODE="$PER_USER")"
eq "per-user without a token: no call to the webapp" "$(calls curl)" "0"
eq "per-user without a token: the same single line" "$(grep -c 'tunnels are pushed by the agent' <<<"$out")" "1"

out="$(run_init REDAMON_SANDBOX_MODE="$PER_USER" TUNNEL_AUTH_TOKEN="$TOKEN" MSF_AUTO_UPDATE=true NUCLEI_AUTO_UPDATE=true)"
eq "per-user, auto-updates on: msfconsole still updates the modules" "$(calls msfconsole)" "1"
eq "per-user, auto-updates on: nuclei still updates the templates" "$(calls 'nuclei \[-update-templates\]')" "1"
eq "per-user, auto-updates on: still no call to the webapp" "$(calls curl)" "0"

echo "== the shared container keeps today's boot sync =="
SYNC_CALL="curl [-sf] [-X] [POST] [-H] [@-] [http://webapp:3000/api/global/tunnel-config/sync]"
for mode in unset shared empty; do
    case "$mode" in
        unset) out="$(run_init TUNNEL_AUTH_TOKEN="$TOKEN")" ;;
        shared) out="$(run_init REDAMON_SANDBOX_MODE=shared TUNNEL_AUTH_TOKEN="$TOKEN")" ;;
        empty) out="$(run_init REDAMON_SANDBOX_MODE= TUNNEL_AUTH_TOKEN="$TOKEN")" ;;
    esac
    eq "shared ($mode): one sync call to the webapp" "$(grep '^curl' "$CALLS")" "$SYNC_CALL"
    eq "shared ($mode): the bearer goes through stdin" "$(cat "$CALLS.stdin")" "Authorization: Bearer $TOKEN"
    eq "shared ($mode): the token is on no command line" "$(grep -cF "$TOKEN" "$CALLS")" "0"
    eq "shared ($mode): the sync is requested" "$(grep -c 'Tunnel config sync requested' <<<"$out")" "1"
    eq "shared ($mode): no per-user line" "$(grep -c 'pushed by the agent' <<<"$out")" "0"
done

out="$(run_init TUNNEL_AUTH_TOKEN="$TOKEN" WEBAPP_API_URL=http://webapp.test:3999)"
eq "shared: WEBAPP_API_URL still names the webapp" "$(grep -c '\[http://webapp.test:3999/api/global/tunnel-config/sync\]$' "$CALLS")" "1"

out="$(run_init)"
eq "shared without a token: no call" "$(calls curl)" "0"
eq "shared without a token: says why" "$(grep -c 'TUNNEL_AUTH_TOKEN not set: no tunnel sync' <<<"$out")" "1"

out="$(STUB_CURL_RC=7 run_init TUNNEL_AUTH_TOKEN="$TOKEN")"
eq "shared, webapp down: 30 attempts" "$(calls curl)" "30"
eq "shared, webapp down: gives up with the usual line" "$(grep -c 'Webapp not reachable for tunnel sync' <<<"$out")" "1"

echo "== the Dockerfile's Metasploit refresh layer =="
# Prints one tab-separated "ok name" or "FAIL name got want" line per check (a
# value may hold "|", never a tab), and writes the refresh RUN's shell command
# to its second argument for the run below.
DF_CHECKS="$(python3 -I - "$DOCKERFILE" "$SANDBOX/refresh.sh" "$REPO_ROOT" <<'PY'
import glob, os, re, sys
import yaml

dockerfile, refresh_out, repo = sys.argv[1:4]
results = []
def check(name, got, want):
    results.append(("ok", name) if got == want else ("FAIL", name, repr(got), repr(want)))

# Instructions as Docker reads them: comments dropped, continuations joined.
instrs, buf = [], ""
for raw in open(dockerfile, encoding="utf-8").read().splitlines():
    s = raw.strip()
    if s.startswith("#") or (not buf and not s):
        continue
    if raw.rstrip().endswith("\\"):
        buf += raw.rstrip()[:-1] + " "
        continue
    buf += raw
    word, _, rest = buf.strip().partition(" ")
    instrs.append((word.upper(), " ".join(rest.split())))
    buf = ""

def where(pred):
    return [i for i, ins in enumerate(instrs) if pred(*ins)]

STAMP = "MSF_REFRESH_STAMP"
last_from = max(where(lambda k, r: k == "FROM"))
entry = where(lambda k, r: k == "ENTRYPOINT")
stamp_args = where(lambda k, r: k == "ARG" and r.split("=")[0] == STAMP)
refresh = where(lambda k, r: k == "RUN" and STAMP in r)
msfdb = where(lambda k, r: k == "RUN" and "msfdb init" in r)
labels = where(lambda k, r: k == "LABEL" and "redamon.msf_refresh" in r)

check("ENTRYPOINT is the image's last instruction", entry, [len(instrs) - 1])
check("ARG MSF_REFRESH_STAMP is declared once, empty by default",
      [instrs[i][1] for i in stamp_args], [STAMP + "="])
check("one RUN reads the stamp", len(refresh), 1)
check("msfdb init runs once", len(msfdb), 1)
if entry and stamp_args and len(refresh) == 1 and len(msfdb) == 1:
    a, r, m, e = stamp_args[0], refresh[0], msfdb[0], entry[0]
    check("the stamp is declared in the final stage", a > last_from, True)
    check("order: ARG, refresh RUN, msfdb init, ENTRYPOINT", a < r < m < e, True)
    check("the label is the last instruction before ENTRYPOINT",
          instrs[e - 1], ("LABEL", 'redamon.msf_refresh="${MSF_REFRESH_STAMP}"'))
    check("the label is set once", labels, [e - 1])
    run = instrs[r][1]
    check("the RUN only tests the stamp for emptiness",
          re.sub(r'\[ -n "\$MSF_REFRESH_STAMP" \]', "", run).count(STAMP), 0)
    check("the RUN only upgrades metasploit-framework",
          re.findall(r"apt-get install [^)|;&]*", run),
          ["apt-get install -y -qq --only-upgrade metasploit-framework"])
    with open(refresh_out, "w", encoding="utf-8") as fh:
        fh.write(run)
users = where(lambda k, r: STAMP in r)
check("nothing else reads the stamp", users,
      sorted(stamp_args + refresh + labels))

SECRET = re.compile(r"TOKEN|SECRET|PASS(WORD|WD)?|PWD|KEY|AUTH|CRED|PRIVATE|COOKIE|SESSION", re.I)
def secret_refs(text):
    return [n for n in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", text or "") if SECRET.search(n)]

df_args = [instrs[i][1] for i in where(lambda k, r: k == "ARG")]
check("no build argument of the Dockerfile is a secret",
      [a for a in df_args if SECRET.search(a.split("=")[0]) or secret_refs(a)], [])

# Every compose file that builds this Dockerfile: no secret as a build argument.
class Loader(yaml.SafeLoader):
    pass
Loader.add_multi_constructor("!", lambda loader, suffix, node: (
    loader.construct_mapping(node) if isinstance(node, yaml.MappingNode)
    else loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
    else loader.construct_scalar(node)))
composes = set(glob.glob(os.path.join(repo, "docker-compose*.yml")))
composes |= set(glob.glob(os.path.join(repo, "mcp", "docker-compose*.yml")))
composes |= set(glob.glob(os.path.join(repo, "tooling", "**", "docker-compose*.yml"), recursive=True))
builders, leaks = [], []
for path in sorted(composes):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=Loader) or {}
    for name, svc in (doc.get("services") or {}).items():
        build = (svc or {}).get("build")
        if not isinstance(build, dict) or not str(build.get("dockerfile", "")).endswith("kali-sandbox/Dockerfile"):
            continue
        builders.append(os.path.relpath(path, repo))
        args = build.get("args") or {}
        pairs = (args.items() if isinstance(args, dict)
                 else (str(a).partition("=")[::2] for a in args))
        leaks += [f"{os.path.relpath(path, repo)}:{k}" for k, v in pairs
                  if SECRET.search(str(k)) or secret_refs(str(v))]
check("the root compose file builds the Kali image", "docker-compose.yml" in builders, True)
check("no compose file passes a secret as a Kali build argument", leaks, [])

for res in results:
    print("\t".join(res))
PY
)"
if [[ -z "$DF_CHECKS" ]]; then
    bad "read the Dockerfile" "no result" "one line per check"
fi
while IFS=$'\t' read -r verdict name got want; do
    [[ -n "$verdict" ]] || continue
    if [[ "$verdict" == ok ]]; then ok "$name"; else bad "$name" "$got" "$want"; fi
done <<<"$DF_CHECKS"

if [[ ! -s "$SANDBOX/refresh.sh" ]]; then
    bad "cut the refresh RUN out of the Dockerfile" "nothing" "the RUN's command"
    finish
fi
REFRESH="$(cat "$SANDBOX/refresh.sh")"

# run_refresh <stamp>: the RUN as Docker runs it (/bin/sh -c), the stamp in the
# environment as a build argument is, only the stubs on PATH, and globbing off
# so the cleanup's argument is recorded as written.
run_refresh() {
    : > "$CALLS"
    env -i PATH="$STUBS" CALLS="$CALLS" STUB_APT_RC="${STUB_APT_RC:-0}" MSF_REFRESH_STAMP="$1" \
        /bin/sh -fc "$REFRESH" </dev/null 2>&1
}

out="$(run_refresh "")"; rc=$?
eq "no stamp: the layer succeeds" "$rc" "0"
eq "no stamp: nothing runs" "$(wc -l < "$CALLS" | tr -d ' ')" "0"

out="$(run_refresh 20261121)"; rc=$?
eq "a stamp: the layer succeeds" "$rc" "0"
eq "a stamp: the package lists are refreshed, then only Metasploit is upgraded" \
    "$(grep '^apt-get' "$CALLS" | tr '\n' ';')" \
    "apt-get [update] [-qq];apt-get [install] [-y] [-qq] [--only-upgrade] [metasploit-framework];"
eq "a stamp: the package lists are removed afterwards" "$(grep '^rm' "$CALLS")" "rm [-rf] [/var/lib/apt/lists/*]"

out="$(STUB_APT_RC=100 run_refresh 20261121)"; rc=$?
eq "a failed refresh does not fail the build" "$rc" "0"
eq "a failed refresh says it was skipped" "$(grep -c '^metasploit refresh skipped$' <<<"$out")" "1"
eq "a failed refresh still removes the package lists" "$(calls rm)" "1"

# Each payload writes a file through builtins alone, so it would work with
# nothing on PATH. The control proves it does when a shell evaluates it.
n=0
for payload in '$(echo x >"$OUT")' '`echo x >"$OUT"`' 'x; echo x >"$OUT"' "x
echo x >\"\$OUT\""; do
    n=$((n+1)); OUT="$SANDBOX/pwned$n"
    env -i OUT="$OUT" MSF_REFRESH_STAMP="$payload" /bin/sh -c 'eval "$MSF_REFRESH_STAMP"' >/dev/null 2>&1
    if [[ -e "$OUT" ]]; then ok "hostile stamp $n: the control runs it when evaluated"; else bad "hostile stamp $n: the control runs it when evaluated" "no file" "a file"; fi
    rm -f "$OUT"
    : > "$CALLS"
    env -i PATH="$STUBS" CALLS="$CALLS" OUT="$OUT" MSF_REFRESH_STAMP="$payload" /bin/sh -fc "$REFRESH" </dev/null >/dev/null 2>&1
    if [[ -e "$OUT" ]]; then bad "hostile stamp $n: the layer never runs it" "it ran" "not run"; else ok "hostile stamp $n: the layer never runs it"; fi
    eq "hostile stamp $n: it only triggers the refresh" "$(calls apt-get)" "2"
done

finish
