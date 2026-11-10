#!/bin/sh
# Smoke checks, run INSIDE the lab network by up.sh (iphn-tools container at
# 192.88.98.250): they ask the lab DNS directly and reach the hosts over the lab
# bridge, so they prove the lab itself, not the host's resolver or route.
#
#   docker run --rm -i --network redamon_iphn_lab --ip 192.88.98.250 \
#       -e INTRA_IP=<addr> -e MOVED=10 iphn-tools:local sh -s < smoke.sh
#
# Never touches the outsider except one marked request at the end (the capture
# check). Exit 1 on the first failure.
set -u
NS=192.88.98.53
fail=0

ok()  { echo "[+][Smoke] $1"; }
bad() { echo "[!][Smoke] $1"; fail=1; }

# expect_dns <type> <name> <expected answers, space separated, sorted>
expect_dns() {
    got=$(dig +short +time=3 +tries=2 @"$NS" "$2" "$1" | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "$3" ]; then ok "dig $1 $2 -> ${got:-<none>}"; else bad "dig $1 $2 -> '${got}', expected '$3'"; fi
}

expect_rcode() {
    got=$(dig +time=3 +tries=2 @"$NS" "$2" "$1" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
    if [ "$got" = "$3" ]; then ok "dig $1 $2 -> $got"; else bad "dig $1 $2 -> status '$got', expected $3"; fi
}

# expect_body <url> <expected body> [curl args...]
expect_body() {
    url=$1; want=$2; shift 2
    got=$(curl -sk -m 5 "$@" "$url" | tr -d '\r\n')
    if [ "$got" = "$want" ]; then ok "$url $* -> $got"; else bad "$url $* -> '$got', expected '$want'"; fi
}

echo "[*][Smoke] DNS on $NS"
expect_dns A app.example-a.test "192.88.98.10"
expect_dns A web.example-a.test "192.88.98.10"
expect_dns A hidden.example-a.test "192.88.98.10"
expect_dns A shop.example-b.test "192.88.98.10"
expect_dns A api.lab-c.example "192.88.98.10"
expect_dns A portal.lab-agency.gov "192.88.98.10"
expect_dns A moved.example-a.test "192.88.98.${MOVED:-10}"
expect_dns A split.example-a.test "192.88.98.13 192.88.98.99"
expect_dns A mismatch.example-b.test "192.88.98.99"
expect_dns A outside.example-b.test "192.88.98.99"
expect_dns A gone.example-a.test "192.88.98.99"
expect_dns A cdn1.example-a.test "192.88.98.40"
expect_dns A cdn2.example-b.test "192.88.98.40"
expect_rcode A nodns.example-a.test NXDOMAIN
expect_dns PTR 10.98.88.192.in-addr.arpa "app.example-a.test. web.example-a.test."
expect_rcode PTR 11.98.88.192.in-addr.arpa NXDOMAIN
expect_dns PTR 12.98.88.192.in-addr.arpa "mismatch.example-b.test."
expect_rcode PTR 13.98.88.192.in-addr.arpa NXDOMAIN
expect_dns PTR 40.98.88.192.in-addr.arpa "edge-40.example-b.test."
# Authoritative only: a real name must be refused, never resolved.
expect_rcode A example.com REFUSED
if [ -n "${INTRA_IP:-}" ]; then
    expect_dns A intra.example-a.test "$INTRA_IP"
else
    echo "[-][Smoke] iphn-intra not running: intra.example-a.test not checked (row E10 unavailable)"
fi

echo "[*][Smoke] .10 SNI vhosts (marker = the vhost that answered)"
for name in web.example-a.test app.example-a.test shop.example-b.test api.lab-c.example \
            hidden.example-a.test portal.lab-agency.gov moved.example-a.test; do
    expect_body "https://$name/" "VHOST=$name" --resolve "$name:443:192.88.98.10"
done
expect_body "https://192.88.98.10/" "VHOST=_default"
expect_body "http://192.88.98.10/" "VHOST=app.example-a.test" -H "Host: app.example-a.test"

echo "[*][Smoke] .10 default certificate (no SNI)"
sans=$(echo | openssl s_client -connect 192.88.98.10:443 -noservername 2>/dev/null \
       | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/.*DNS://p' | sort | tr '\n' ' ')
want="*.wild.example-a.test api.lab-c.example app.example-a.test moved.example-a.test nodns.example-a.test outside.example-b.test portal.lab-agency.gov shop.example-b.test web.example-a.test "
if [ "$sans" = "$want" ]; then ok "default SANs: $sans"; else bad "default SANs '$sans', expected '$want'"; fi
case "$sans" in *hidden*) bad "hidden.example-a.test leaked into the default certificate" ;; esac

echo "[*][Smoke] .11 .12 .13"
expect_body "http://192.88.98.11/" "VHOST=_default"
expect_body "http://192.88.98.12/" "VHOST=_default"
expect_body "https://split.example-a.test/" "VHOST=split.example-a.test" --resolve "split.example-a.test:443:192.88.98.13"
if curl -sk -m 3 -o /dev/null "https://192.88.98.11/"; then bad ".11 answers HTTPS (it must be plain HTTP only)"; else ok ".11 has no HTTPS"; fi

echo "[*][Smoke] .40 CDN-like edge"
hdr=$(curl -sk -m 5 -D - -o /dev/null --resolve cdn1.example-a.test:443:192.88.98.40 https://cdn1.example-a.test/ | tr -d '\r')
echo "$hdr" | grep -qi '^server: cloudflare$' && ok ".40 Server: cloudflare" || bad ".40 lacks Server: cloudflare"
echo "$hdr" | grep -qi '^cf-ray: ' && ok ".40 cf-ray" || bad ".40 lacks cf-ray"
expect_body "https://cdn2.example-b.test/" "VHOST=cdn2.example-b.test" --resolve "cdn2.example-b.test:443:192.88.98.40"
expect_body "https://192.88.98.40/" "error code: 1003"
issuer=$(echo | openssl s_client -connect 192.88.98.40:443 -servername cdn1.example-a.test 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
case "$issuer" in *Cloudflare*) ok ".40 issuer: $issuer" ;; *) bad ".40 issuer '$issuer' does not name Cloudflare" ;; esac

echo "[*][Smoke] .30 urlscan stub"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://192.88.98.30/__lab/health)
[ "$code" = 200 ] && ok ".30 health 200" || bad ".30 health -> $code"
found=$(curl -s -m 5 'http://192.88.98.30/api/v1/search/?q=page.domain:example-a.test&size=100' \
        | grep -o '"domain": *"[a-z0-9.-]*"' | sed 's/.*"\([a-z0-9.-]*\)"$/\1/' | sort -u | tr '\n' ' ')
[ "$found" = "gone.example-a.test hidden.example-a.test " ] && ok ".30 page.domain:example-a.test -> $found" \
    || bad ".30 page.domain:example-a.test -> '$found'"
curl -s -m 5 -X POST http://192.88.98.30/__lab/reset >/dev/null

echo "[*][Smoke] outsider: one marked request for the capture check"
expect_body "http://192.88.98.99/smoke" "VHOST=_outsider" -A iphn-smoke

exit $fail
