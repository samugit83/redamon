#!/usr/bin/env bash
# =============================================================================
# The five RBAC switches are on by default, and an operator's value is kept.
# Run:  bash tests/redamon_rbac_env_test.sh
#
# ensure_auth_secrets (install, update, up) writes each RBAC_*_ENABLED switch
# true when it has no line or only a blank value, so a fresh install and an
# update from a release without them both run with them on. Any other value is
# the operator's and is never touched: a `false` set by hand must survive every
# later update.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Requirement order (webapp/src/lib/authz/flags.ts REQUIRES), the order they are written in.
SWITCHES=(RBAC_IDENTITY_ENABLED RBAC_PERMISSIONS_ENABLED RBAC_SHARING_ENABLED
          RBAC_SHARING_WRITE_ENABLED RBAC_GOVERNANCE_ENABLED)
all_false() { local s out=""; for s in "${SWITCHES[@]}"; do out+="$s=false\n"; done; printf '%s' "$out"; }

# Under `set -euo pipefail`, as install/update/up run it: a grep that matches nothing
# inside a pipeline would otherwise abort the install, and the exit status says so.
run_secrets() {   # run_secrets <dir>   (HOME is <dir>/home: no real ~/.redamon-deploy leaks in)
    mkdir -p "$1/home"; rm -f "$1/.rc"
    ( cd "$REPO_ROOT" && ENVDIR="$1" HOME="$1/home" bash -c '
        set -uo pipefail
        source ./redamon.sh
        set -euo pipefail
        info(){ :; }; warn(){ :; }; error(){ :; }; success(){ :; }
        SCRIPT_DIR="$ENVDIR"
        ensure_auth_secrets
        echo "$?" > "$ENVDIR/.rc"
    ' >/dev/null 2>&1 )
}
finished() { [[ "$(cat "$1/.rc" 2>/dev/null)" == 0 ]] && echo yes || echo no; }
case_dir() { mkdir -p "$TMP/$1"; [[ $# -gt 1 ]] && printf '%b' "$2" > "$TMP/$1/.env"; echo "$TMP/$1"; }
val()   { grep -E "^[[:space:]]*(export[[:space:]]+)?$2=" "$1/.env" | tail -1 | cut -d= -f2-; }
lines() { grep -cE "^[[:space:]]*(export[[:space:]]+)?$2=" "$1/.env"; }
line_no() { grep -nE "^$2=" "$1/.env" | cut -d: -f1; }
same_after_run() {   # same_after_run <label> <dir>: a second run leaves .env byte-identical
    cp "$2/.env" "$TMP/before"
    run_secrets "$2"
    if cmp -s "$TMP/before" "$2/.env"; then ok "$1"; else bad "$1" "changed" "identical"; fi
}

echo "== a fresh install writes all five switches, on =="
D="$(case_dir fresh)"
run_secrets "$D"
eq "ensure_auth_secrets finishes under set -e on an empty .env" "$(finished "$D")" "yes"
for s in "${SWITCHES[@]}"; do
    eq "$s written true" "$(val "$D" "$s")" "true"
    eq "one $s line" "$(lines "$D" "$s")" "1"
done
prev=0; in_order=yes
for s in "${SWITCHES[@]}"; do n="$(line_no "$D" "$s")"; (( ${n:-0} > prev )) || in_order=no; prev="${n:-0}"; done
eq "written in requirement order (each after the switch it needs)" "$in_order" "yes"
same_after_run "an update on that .env changes nothing" "$D"

echo
echo "== an update from a release without the lines turns all five on =="
D="$(case_dir upgrade 'AUTH_SECRET=kept\nMCP_SERVER_ENABLED=true\n')"
run_secrets "$D"
eq "ensure_auth_secrets finishes under set -e" "$(finished "$D")" "yes"
for s in "${SWITCHES[@]}"; do eq "$s added true" "$(val "$D" "$s")" "true"; done
eq "the other lines are kept" "$(val "$D" AUTH_SECRET)" "kept"

D="$(case_dir upgrade-two-on 'RBAC_IDENTITY_ENABLED=true\nRBAC_PERMISSIONS_ENABLED=true\n')"
run_secrets "$D"
for s in RBAC_SHARING_ENABLED RBAC_SHARING_WRITE_ENABLED RBAC_GOVERNANCE_ENABLED; do
    eq "a .env with only the first two gets $s true" "$(val "$D" "$s")" "true"
done

echo
echo "== an operator's false survives every update =="
D="$(case_dir off "$(all_false)")"
run_secrets "$D"
for s in "${SWITCHES[@]}"; do
    eq "$s stays false" "$(val "$D" "$s")" "false"
    eq "no second $s line" "$(lines "$D" "$s")" "1"
done
same_after_run "the next update leaves it byte-identical" "$D"

D="$(case_dir mixed 'RBAC_IDENTITY_ENABLED=true\nRBAC_PERMISSIONS_ENABLED=false\n')"
run_secrets "$D"
eq "identity on, permissions off: identity kept" "$(val "$D" RBAC_IDENTITY_ENABLED)" "true"
eq "identity on, permissions off: permissions kept off" "$(val "$D" RBAC_PERMISSIONS_ENABLED)" "false"

D="$(case_dir governance-off 'RBAC_GOVERNANCE_ENABLED=false\n')"
run_secrets "$D"
eq "governance off by hand is kept" "$(val "$D" RBAC_GOVERNANCE_ENABLED)" "false"
eq "while the switches around it are written true" "$(val "$D" RBAC_SHARING_WRITE_ENABLED)" "true"

echo
echo "== any non-blank value is the operator's, read or not =="
for value in 0 no FALSE yes maybe '"false"'; do
    env_text=""; for s in "${SWITCHES[@]}"; do env_text+="$s=$value\n"; done
    D="$(case_dir "value-$RANDOM" "$env_text")"
    run_secrets "$D"
    for s in "${SWITCHES[@]}"; do eq "$s=$value is kept" "$(val "$D" "$s")" "$value"; done
done

echo
echo "== a blank value (an older .env.example) is set true where it stands =="
D="$(case_dir blank '# Root powers\nRBAC_IDENTITY_ENABLED=\n# Permission sets\nRBAC_PERMISSIONS_ENABLED=   \nRBAC_SHARING_ENABLED=\nRBAC_SHARING_WRITE_ENABLED=\nRBAC_GOVERNANCE_ENABLED=\n')"
run_secrets "$D"
eq "ensure_auth_secrets finishes under set -e (in-place path)" "$(finished "$D")" "yes"
eq "identity set true" "$(val "$D" RBAC_IDENTITY_ENABLED)" "true"
eq "permissions (blank but for spaces) set true" "$(val "$D" RBAC_PERMISSIONS_ENABLED)" "true"
eq "identity stays under its comment" "$(sed -n 2p "$D/.env")" "RBAC_IDENTITY_ENABLED=true"
eq "permissions stays under its comment" "$(sed -n 4p "$D/.env")" "RBAC_PERMISSIONS_ENABLED=true"
eq "the comments are kept" "$(grep -c '^# ' "$D/.env")" "2"
eq "a blank sharing switch is set true where it stands" "$(sed -n 5p "$D/.env")" "RBAC_SHARING_ENABLED=true"
eq "a blank write-sharing switch is set true where it stands" "$(sed -n 6p "$D/.env")" "RBAC_SHARING_WRITE_ENABLED=true"
eq "a blank governance switch is set true where it stands" "$(sed -n 7p "$D/.env")" "RBAC_GOVERNANCE_ENABLED=true"
for s in "${SWITCHES[@]}"; do eq "one $s line" "$(lines "$D" "$s")" "1"; done

D="$(case_dir quoted-blank "RBAC_IDENTITY_ENABLED=\"\"\nexport RBAC_PERMISSIONS_ENABLED=''\n")"
run_secrets "$D"
eq "an empty quoted value is blank" "$(val "$D" RBAC_IDENTITY_ENABLED)" "true"
eq "an empty quoted export is blank" "$(val "$D" RBAC_PERMISSIONS_ENABLED)" "true"
eq "the export line is replaced, not doubled" "$(lines "$D" RBAC_PERMISSIONS_ENABLED)" "1"

echo
echo "== compose reads the last line, and so does the check =="
D="$(case_dir last-blank 'RBAC_IDENTITY_ENABLED=false\nOTHER=1\nRBAC_IDENTITY_ENABLED=\n')"
run_secrets "$D"
eq "a blank last line reads blank: written true" "$(val "$D" RBAC_IDENTITY_ENABLED)" "true"
eq "the dead earlier line is dropped" "$(lines "$D" RBAC_IDENTITY_ENABLED)" "1"
eq "the true takes the last line's place" "$(sed -n 2p "$D/.env")" "RBAC_IDENTITY_ENABLED=true"
D="$(case_dir last-false 'RBAC_IDENTITY_ENABLED=\nRBAC_IDENTITY_ENABLED=false\nRBAC_PERMISSIONS_ENABLED=false\n')"
run_secrets "$D"
eq "a false last line is the operator's: kept" "$(val "$D" RBAC_IDENTITY_ENABLED)" "false"
eq "and both identity lines are left as they were" "$(sed -n 1,2p "$D/.env" | tr '\n' '|')" "RBAC_IDENTITY_ENABLED=|RBAC_IDENTITY_ENABLED=false|"

echo
echo "== an 'export' line counts as present =="
D="$(case_dir exported 'export RBAC_IDENTITY_ENABLED=false\n')"
run_secrets "$D"
eq "the export is kept" "$(grep -c '^export RBAC_IDENTITY_ENABLED=false$' "$D/.env")" "1"
eq "no plain identity line added beside the export" "$(lines "$D" RBAC_IDENTITY_ENABLED)" "1"
eq "the missing permissions line is added true" "$(val "$D" RBAC_PERMISSIONS_ENABLED)" "true"

echo
echo "== only .env counts, not this shell =="
D="$(case_dir shell)"
( for s in "${SWITCHES[@]}"; do export "$s=false"; done; run_secrets "$D" )
for s in "${SWITCHES[@]}"; do
    eq "a false $s exported in the shell does not stop the write" "$(val "$D" "$s")" "true"
done

echo
echo "== a last line without a newline is not glued to =="
D="$(case_dir no-newline 'OTHER=1')"
run_secrets "$D"
eq "the operator's last line is intact" "$(val "$D" OTHER)" "1"
eq "identity on its own line" "$(val "$D" RBAC_IDENTITY_ENABLED)" "true"

echo
echo "== redamon.sh reads the identity switch as compose does =="
# Compose takes the LAST line of a key and drops an unquoted value's " # comment"; the
# Root check must agree, or the webapp runs with identity on while update skips Root.
identity_on() {   # identity_on <dir>  -> on | off
    ( cd "$REPO_ROOT" && ENVDIR="$1" bash -c '
        source ./redamon.sh >/dev/null 2>&1
        set +e
        SCRIPT_DIR="$ENVDIR"
        _rbac_identity_on && echo on || echo off
    ' 2>/dev/null )
}
D="$(case_dir appended 'RBAC_IDENTITY_ENABLED=false\nRBAC_PERMISSIONS_ENABLED=false\nRBAC_IDENTITY_ENABLED=true\n')"
eq "a =true appended below a false is on" "$(identity_on "$D")" "on"
D="$(case_dir reverted 'RBAC_IDENTITY_ENABLED=true\nRBAC_IDENTITY_ENABLED=false\n')"
eq "a =false appended below a true is off" "$(identity_on "$D")" "off"
D="$(case_dir commented 'RBAC_IDENTITY_ENABLED=true   # turned on for the pilot\n')"
eq "an inline comment does not hide true" "$(identity_on "$D")" "on"
D="$(case_dir quoted 'RBAC_IDENTITY_ENABLED="YES"\n')"
eq "a quoted, upper-case YES is on" "$(identity_on "$D")" "on"
D="$(case_dir written)"
run_secrets "$D"
eq "the true that install writes is on" "$(identity_on "$D")" "on"
D="$(case_dir absent '')"
eq "no line is off" "$(identity_on "$D")" "off"

echo
echo "== .env.example ships all five on =="
for var in "${SWITCHES[@]}"; do
    eq ".env.example has $var=true" "$(grep -cx "${var}=true" "$REPO_ROOT/.env.example")" "1"
done

echo
echo "== the webapp reads all five; compose falls back to false without a line =="
# The webapp has no env_file: a switch set only in .env must be in its environment
# block. The fallback stays false so a bare `docker compose up` on a .env without
# the line fails safe; redamon.sh is what writes them on.
WEBAPP_BLOCK="$(awk '/^  webapp:/{f=1} f&&/^  [a-z_-]+:$/&&!/^  webapp:/{f=0} f' "$COMPOSE")"
for var in "${SWITCHES[@]}"; do
    if grep -qE "^[[:space:]]+${var}: \\\$\\{${var}:-false\\}" <<<"$WEBAPP_BLOCK"; then
        ok "$var reaches the webapp, fallback false"
    else
        bad "$var reaches the webapp, fallback false" "absent or another default" "\${$var:-false}"
    fi
done

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
