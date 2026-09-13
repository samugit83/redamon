#!/bin/sh
# Serve TLS on NON-HTTP ports only. That is the whole point of this harness:
# httpx never dials 993/636, so before tlsx these certificates were invisible
# and the ports carried nothing but a static IANA label.
set -eu
CERTS=/certs
mkdir -p "$CERTS"

# 1. IMAPS (993): self-signed, multi-SAN. One SAN is deliberately OUT OF SCOPE
#    so the SAN feedback path's apex allow-list can be proven on real data.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$CERTS/imaps.key" -out "$CERTS/imaps.crt" \
  -subj "/CN=mail.tlslab.test/O=RedAmon TLS Lab" \
  -addext "subjectAltName=DNS:mail.tlslab.test,DNS:imap.tlslab.test,DNS:outsider.example-evil.test" \
  >/dev/null 2>&1

# 2. LDAPS (636): EXPIRED. Before the fix an already-expired certificate
#    produced ZERO findings -- the most severe case was the one dropped.
openssl req -x509 -newkey rsa:2048 -nodes \
  -not_before 20240101000000Z -not_after 20240201000000Z \
  -keyout "$CERTS/ldaps.key" -out "$CERTS/ldaps.crt" \
  -subj "/CN=ldap.tlslab.test/O=RedAmon TLS Lab" \
  -addext "subjectAltName=DNS:ldap.tlslab.test" \
  >/dev/null 2>&1

# 3. POP3S (995): TLS 1.0 ONLY, so the NEGOTIATED version is weak.
#    Verified reachable: tlsx's Go client does negotiate tls10 and reports
#    tls_version=tls10, which is what `tls_weak_version` reads. AES is offered
#    on purpose -- see the cipher note in README.md for why a weak *cipher*
#    cannot be reached through tlsx at all.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$CERTS/pop3s.key" -out "$CERTS/pop3s.crt" \
  -subj "/CN=legacy.tlslab.test/O=RedAmon TLS Lab" \
  -addext "subjectAltName=DNS:legacy.tlslab.test" \
  >/dev/null 2>&1

# 4. SMTPS (465): wildcard certificate naming 23 SANs, over the 20-SAN
#    _WILDCARD_SAN_OVERBROAD threshold, so `tls_wildcard_overbroad` fires.
#    The CN must stay a `*.` name: that is what tlsx reports as
#    wildcard_certificate, and the check needs both the flag and the count.
WILD="DNS:*.wild.tlslab.test"
i=1
while [ "$i" -le 22 ]; do
  WILD="$WILD,DNS:h$i.wild.tlslab.test"
  i=$((i + 1))
done
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$CERTS/smtps.key" -out "$CERTS/smtps.crt" \
  -subj "/CN=*.wild.tlslab.test/O=RedAmon TLS Lab" \
  -addext "subjectAltName=$WILD" \
  >/dev/null 2>&1

echo "[tls_target] IMAPS 993 (self-signed, 3 SANs) + LDAPS 636 (expired)"
echo "[tls_target] POP3S 995 (TLS 1.0 only) + SMTPS 465 (wildcard, 23 SANs) ready"

# -naccept bounds each s_server; the loop makes the listener effectively
# permanent so a scan's retries and a later partial-recon run both work.
while true; do
  openssl s_server -accept 993 -cert "$CERTS/imaps.crt" -key "$CERTS/imaps.key" \
    -naccept 50 -quiet >/dev/null 2>&1 || true
done &
while true; do
  openssl s_server -accept 636 -cert "$CERTS/ldaps.crt" -key "$CERTS/ldaps.key" \
    -naccept 50 -quiet >/dev/null 2>&1 || true
done &
# @SECLEVEL=0 is required: OpenSSL 3.5 refuses TLS 1.0 at the default security
# level, and the listener would exit instead of serving a weak handshake.
while true; do
  openssl s_server -accept 995 -cert "$CERTS/pop3s.crt" -key "$CERTS/pop3s.key" \
    -min_protocol TLSv1 -max_protocol TLSv1 -cipher 'AES128-SHA@SECLEVEL=0' \
    -naccept 50 -quiet >/dev/null 2>&1 || true
done &
while true; do
  openssl s_server -accept 465 -cert "$CERTS/smtps.crt" -key "$CERTS/smtps.key" \
    -naccept 50 -quiet >/dev/null 2>&1 || true
done &
wait
