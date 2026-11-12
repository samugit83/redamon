#!/usr/bin/env bash
# =============================================================================
# The single-host nginx keeps the internal-only routes off the public edge
# (RBAC step 2.4, NF-13, F-23).
# Run:  bash tests/deploy_rbac_nginx_test.sh
#
# WHY THIS MATTERS: the deploy proxies all of /api/ to the webapp. Every
# /api/internal/ route answers only the internal or scanner key, the tunnel
# credentials (/api/global/tunnel-config) only the internal key, and the tunnel
# sync only the kali-sandbox's bearer. Their callers (the recon orchestrator, the
# agent, the kali-sandbox, the capture ingest worker) use the container network
# names, never the edge; nginx forwards the headers those routes authenticate
# with, so without a deny the internet could probe those checks. The plugin
# platform's three denies (tests/deploy_plugins_nginx_test.sh) stay as they are.
#
# Static checks on both templates, then the rendered configs under a real nginx
# (Docker): `nginx -t`, and requests for every path, URL-encoded, double-slash
# and trailing-slash variants included, answered 404 by nginx itself, while an
# ordinary /api/ path, and a path that only starts like an internal one, still
# reach the proxy. Self-skips the nginx part without Docker.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
skip() { printf '  skip %s (%s)\n' "$1" "$2"; }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

DENIES=(
    'location ^~ /api/internal/ { return 404; }'
    'location = /api/global/tunnel-config { return 404; }'
    'location ^~ /api/global/tunnel-config/ { return 404; }'
)
PLUGIN_DENIES=(
    'location ^~ /api/plugin-gateway/ { return 404; }'
    'location ^~ /api/plugin-runner/ { return 404; }'
    'location ^~ /api/internal/plugins/ { return 404; }'
)

echo "== both templates block the three paths, before location /api/, beside the plugin denies =="
for t in redamon.conf.tmpl redamon-http.conf.tmpl; do
    f="$DEPLOY/nginx/$t"
    api_line="$(grep -n '^    location /api/ {' "$f" | head -1 | cut -d: -f1)"
    for d in "${DENIES[@]}" "${PLUGIN_DENIES[@]}"; do
        line="$(grep -nF "    $d" "$f" | head -1 | cut -d: -f1)"
        if [[ -z "$line" ]]; then
            bad "$t: $d" "absent" "present"
        elif [[ -n "$api_line" && "$line" -lt "$api_line" ]]; then
            ok "$t: $d before location /api/"
        else
            bad "$t: $d before location /api/" "line $line" "before $api_line"
        fi
    done
done

# render <template>: the config modules/nginx.sh would install (ip_allowlist gate
# admitting loopback, so an ordinary /api/ request passes the gate inside the test).
render() {
    ( cd "$REPO_ROOT" && \
      GATE_MODE=ip_allowlist MCP_EDGE_ALLOW_BEARER=false MCP_CLIENT_CIDRS="" MCP_SERVER_ENABLED=false \
      OPERATOR_ALLOW_CIDRS="127.0.0.1/32" HTTP_PORT=8080 \
      SERVER_NAME=redamon.example SSL_CERT_REMOTE=/c.pem SSL_KEY_REMOTE=/k.pem \
      CSP_CONNECT="'self'" CSP_HEADER_NAME=Content-Security-Policy \
      WS_AUTH_REQUEST="" REDIRECT_HOST=redamon.example TLS_MODE=selfsigned \
      _NGINX_MOD="$DEPLOY/modules/nginx.sh" _TMPL="$1" \
      bash -c '
        set -uo pipefail
        is_true() { [[ "$(printf "%s" "${1:-}" | tr "[:upper:]" "[:lower:]")" == "true" || "${1:-}" == "1" ]]; }
        source "$_NGINX_MOD"
        _render_template "$_TMPL"
      ' 2>/dev/null )
}

echo
echo "== the rendered configs carry the denies =="
for t in redamon.conf.tmpl redamon-http.conf.tmpl; do
    r="$(render "$DEPLOY/nginx/$t")"
    for d in "${DENIES[@]}" "${PLUGIN_DENIES[@]}"; do
        eq "$t renders: $d" "$(grep -cF "$d" <<<"$r")" "1"
    done
done

# Requests answered 404 by nginx itself; then paths that must still reach the proxy (the
# gate passes loopback; the upstream 127.0.0.1:3000 does not exist in the container: 502).
BLOCKED=(
    /api/internal/capture-config /api/internal/job-queue/candidates
    /api/internal/scan-schedules/due /api/internal/plugins/reconcile
    /api/%69nternal/capture-config /api//internal/capture-config
    /api/global/tunnel-config /api/global/tunnel-config?x=1 /api/global/tunnel-config/
    /api/global//tunnel-config /api/global/tunnel-config/sync /api/global/tunnel-config/sync/
    /api/global/%74unnel-config/sync /api/global/tunnel-config/./sync
)
PASSED=(/api/health /api/internals /api/global/tunnel-status)

echo
echo "== under a real nginx =="
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    skip "nginx runs of the rendered configs" "docker unavailable"
else
    # The session scratchpad is not bind-mountable by every Docker CLI; stage in the repo.
    WORK="$REPO_ROOT/.rbac-nginx-check.$$"
    mkdir -p "$WORK/snip"
    trap 'rm -rf "$WORK"' EXIT
    render "$DEPLOY/nginx/redamon.conf.tmpl" > "$WORK/tls.conf"
    render "$DEPLOY/nginx/redamon-http.conf.tmpl" > "$WORK/http.conf"
    for _s in "$DEPLOY"/nginx/snippets/*.conf; do cp "$_s" "$WORK/snip/redamon-$(basename "$_s")"; done
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
        -days 1 -subj "/CN=test" >/dev/null 2>&1
    printf '%s\n' "${BLOCKED[@]}" "${PASSED[@]}" > "$WORK/paths"
    OUT="$(docker run --rm -v "$WORK:/s:ro" --entrypoint sh nginx:alpine -c '
        mkdir -p /etc/nginx/snippets /var/www/certbot && cp /s/snip/*.conf /etc/nginx/snippets/
        cp /s/c.pem /c.pem && cp /s/k.pem /k.pem && touch /etc/nginx/.redamon_htpasswd
        for f in tls http; do
            cp /s/$f.conf /etc/nginx/conf.d/redamon.conf
            if nginx -t >/dev/null 2>&1; then echo "$f nginx-t OK"; else echo "$f nginx-t FAIL"; continue; fi
            nginx
            if [ $f = tls ]; then base="https://127.0.0.1:443"; else base="http://127.0.0.1:8080"; fi
            while read -r p; do
                for m in GET POST; do
                    code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: redamon.example" \
                           --path-as-is -X $m "$base$p")
                    echo "$f $m $p $code"
                done
            done < /s/paths
            nginx -s stop; sleep 0.5
            rm -f /etc/nginx/conf.d/redamon.conf
        done' 2>/dev/null)"
    for f in tls http; do
        eq "$f: nginx -t passes" "$(grep -c "^$f nginx-t OK" <<<"$OUT")" "1"
        for p in "${BLOCKED[@]}"; do
            for m in GET POST; do
                eq "$f: $m $p is refused by nginx" "$(grep -F "$f $m $p " <<<"$OUT" | awk '{print $4}')" "404"
            done
        done
        for p in "${PASSED[@]}"; do
            code="$(grep -F "$f GET $p " <<<"$OUT" | awk '{print $4}')"
            [[ -n "$code" && "$code" != "404" ]] && ok "$f: $p still reaches the proxy ($code)" \
                || bad "$f: $p still reaches the proxy" "${code:-none}" "not 404"
        done
    done
fi

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
