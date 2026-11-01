#!/usr/bin/env bash
# Run JS Recon's TruffleHog sidecar, with the PRODUCTION argv
# (recon/helpers/js_recon/trufflehog_bridge.py build_argv), over a directory of
# files, and print one line per result: DetectorName, Verified, whether
# verification errored, and the file. Never a value. A dev tool for the
# detector mapping, the V2 exclusion review and the SSRF positive control.
#
#   tooling/scripts/trufflehog_probe.sh <dir> [--verify] [--network <name>] [--no-exclusions]
#
#   --verify          verification on (default off: --network none)
#   --network <name>  the network for --verify (default redamon-trufflehog-net)
#   --no-exclusions   drop the V2 exclusion list except PrivateKey, which sends
#                     key material to a third party (the SSRF positive control)
#
# On snap Docker the daemon has its own /tmp: give a <dir> under $HOME.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dir="" verify=0 network="" noexcl=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify) verify=1 ;;
        --network) network="$2"; shift ;;
        --no-exclusions) noexcl=1 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) dir="$1" ;;
    esac
    shift
done
[[ -n "$dir" && -d "$dir" ]] || { echo "usage: $0 <dir> [--verify] [--network <n>] [--no-exclusions]" >&2; exit 2; }
dir="$(cd "$dir" && pwd)"

argv_json="$(python3 -I - "$REPO" "$dir" "$verify" "$network" "$noexcl" <<'PY'
import importlib.util, json, sys, types
repo, stage, verify, network, noexcl = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4], sys.argv[5] == "1"

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

# The recon package's __init__ pulls in the scanner's dependencies; the bridge
# needs only patterns.py (stdlib) and the resource governor.
for pkg in ("recon", "recon.helpers", "recon.helpers.js_recon", "graph_db"):
    sys.modules.setdefault(pkg, types.ModuleType(pkg))
load("recon.helpers.js_recon.patterns", f"{repo}/recon/helpers/js_recon/patterns.py")
try:
    sys.modules["graph_db"].resource_governor = load("graph_db.resource_governor", f"{repo}/graph_db/resource_governor.py")
except Exception:
    pass
bridge = load("recon.helpers.js_recon.trufflehog_bridge", f"{repo}/recon/helpers/js_recon/trufflehog_bridge.py")
argv = bridge.build_argv(stage, verify=verify, concurrency=4, validation_timeout=5,
                         name=bridge.container_name("probe"), network=network or None)
if noexcl:
    argv = [a if not a.startswith("--exclude-detectors=") else "--exclude-detectors=PrivateKey" for a in argv]
print(json.dumps(argv))
PY
)"

mapfile -t argv < <(python3 -I -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])))' "$argv_json")
echo "[*] probe: verify=$verify network=$(printf '%s\n' "${argv[@]}" | grep -A1 -x -- '--network' | tail -1) exclusions=$([[ $noexcl == 1 ]] && echo PrivateKey-only || echo V2)" >&2

summary="$(cat <<'PY'
import json, sys
n = 0
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if "DetectorName" not in r:
        continue
    n += 1
    fs = ((r.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
    error = "yes" if r.get("VerificationError") else "no"
    print("%-28s verified=%-5s error=%-3s file=%s"
          % (r["DetectorName"], r.get("Verified") is True, error, fs.get("file", "?")))
print("[*] %d result(s)" % n, file=sys.stderr)
PY
)"

set +e
"${argv[@]}" 2>/dev/null | python3 -I -c "$summary"
rc=${PIPESTATUS[0]}
echo "[*] trufflehog exit $rc" >&2
exit "$rc"
