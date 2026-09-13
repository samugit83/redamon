# tls_target — TLS Certificate Grab (tlsx) harness

Validates the **GROUP 3.6 tlsx** module and every consumer that reads a
certificate, against real TLS handshakes rather than fixtures.

```bash
cd testing/guinea_pigs/tls_target && docker compose up -d --build
# target: 192.88.98.10   (IMAPS 993, LDAPS 636, POP3S 995, SMTPS 465)
docker compose down
```

## Why this target serves no HTTP

tlsx exists because httpx only grabs certificates on the five HTTPS ports it
dials. A host whose TLS lives on 993/636 was found "open", labelled from a
static IANA table, and never inspected again. Serving **no HTTP at all** is the
honest reproduction of that gap: `http_probe` finds nothing here, so every
`Certificate` node in the graph after a run demonstrably came from tlsx.

## Why 192.88.98.10 and not 127.0.0.1

`_build_tlsx_targets` filters every candidate through `is_non_routable_ip()`
before a packet is sent, and `merge_discovered_hostnames` resolve-checks each
SAN name the same way. Loopback, RFC1918 and every TEST-NET range are rejected,
so a lab on `127.0.0.1` yields **zero** tlsx targets and proves nothing.

`192.88.98.0/24` is in the deprecated 6to4 relay block (RFC 7526), which
Python's `ipaddress` reports as global — so the SSRF control stays **armed** and
the run exercises the real production path. Nothing leaves the host. A distinct
/24 from `supply_chain_target`'s `192.88.99.0/24` so both labs can run at once
(Docker refuses overlapping subnets).

## What each port exercises

| Port | Certificate | Pipeline step it proves |
|---|---|---|
| 993 | self-signed, valid, SAN: `mail.tlslab.test`, `imap.tlslab.test`, **`outsider.example-evil.test`** | cert grab on a non-HTTP port; `Service.tls_service_hint = imaps`; `COVERS_HOST` for in-scope SANs only (domain mode; IP mode fails closed, see Expected result); the out-of-scope SAN must never be injected as a scan target; `tls_self_signed` finding |
| 636 | **expired** (notAfter 2024-02-01) | `tls_expired` at `high`. Before the fix an already-expired certificate produced **zero** findings — the most severe case was the one dropped; `Service.tls_service_hint = ldaps` |
| 995 | valid, single SAN, served over **TLS 1.0 only** | `tls_weak_version` on the NEGOTIATED version, plus `tls_weak_version_supported` from `version_enum` when `-ve` is on; `Service.tls_service_hint = pop3s` |
| 465 | **wildcard** `*.wild.tlslab.test` naming **23 SANs** | `tls_wildcard_overbroad` (threshold is 20). Needs both the wildcard flag and the count, so the CN must stay a `*.` name; `Service.tls_service_hint = smtps` |

### Why no port serves a weak cipher

`tls_weak_cipher` cannot be reached through tlsx, and no lab port pretends
otherwise. tlsx is a Go binary and Go's TLS client has dropped RC4 and 3DES, so:

* against a server offering **only** 3DES, tlsx fails the handshake entirely and
  reports `probe_status: false` — no certificate, no finding;
* against a server offering 3DES **alongside** AES, tlsx negotiates AES, so the
  negotiated cipher is strong;
* `-ce -ct weak` returns an envelope per version with an **empty** cipher map,
  because it can only enumerate what it is able to negotiate.

Both verified live. The check is kept because a future cert source may report
ciphers from its own scanner, and its logic is pinned by
`recon/tests/test_tls_enum_checks.py` using tlsx's real output shape.

The out-of-scope SAN is the point of the harness, not decoration: a SAN list is
chosen by the scanned host, so it is attacker-controlled input. This lab proves
the apex allow-list holds against a certificate that actually carries a foreign
name.

## Expected result

Verified against a real IP-mode pipeline run (target `192.88.98.10`):

```
[+][Tlsx] grabbed 4 cert(s) from 4 target(s)

Certificates      mail.tlslab.test, ldap.tlslab.test (expired),
                  legacy.tlslab.test (tls10), *.wild.tlslab.test (23 SANs)
                  source=tlsx  observed_by=['tlsx']     <- nothing here serves HTTP
IP HAS_CERTIFICATE  4
Subdomain nodes   1, the reverse-DNS placeholder        <- no SAN name was promoted

Findings (7)      tls_expired                x1  high     <- 636
                  tls_self_signed            x4  medium
                  tls_weak_version           x1  medium   <- 995, negotiated tls10
                  tls_wildcard_overbroad     x1  low      <- 465, 23 SANs
                  tls_hostname_mismatch      x0           <- see below, H5
                + tls_weak_version_supported x1  medium   <- only with -ve on
```

Plus the `Service` rows, one per port:

```
Service 993   name=imaps  tls=true  tls_version=tls13  tls_service_hint=imaps
Service 636   name=ldaps  tls=true  tls_version=tls13  tls_service_hint=ldaps
Service 995   name=pop3s  tls=true  tls_version=tls10  tls_service_hint=pop3s
Service 465   name=urd    tls=true  tls_version=tls13  tls_service_hint=smtps
```

Two results look like failures and are not.

**`tls_hostname_mismatch` is 0 for an IP target.** tlsx compares the certificate
against whatever it dialled, so on a bare IP it reports `mismatched: true` for
every correctly configured host -- a certificate names hostnames, never the IP.
Trusting that flag made an IP-mode scan raise a bogus mismatch on every TLS port
it found (H5). Dial a hostname the certificate does not name and the finding
appears as it should; pinned by
`recon/tests/test_tls_mismatch_ip_target.py`.

**`COVERS_HOST` is 0 in IP mode.** SAN promotion is scope-contained behind an
apex allow-list, and IP mode has no apex, so it fails closed: `discovered_hostnames`
lists all four SAN names and none becomes a `Subdomain`. The edges only appear
when a root domain is in scope (domain mode), which needs `*.tlslab.test` to
resolve. The graph write itself is covered by `tests/test_tlsx_graph_live.py`.

This harness is also what exposed the reverse-DNS gap in the port scan: naabu
omits the `host` field for a bare IP with no PTR, `by_host` is the only source
of `Port` and `Service` nodes, and so an IP-mode scan of a PTR-less target used
to produce neither -- leaving tlsx's `tls_service_hint` with nothing to attach
to. Fixed in `port_scan.py`, pinned by `recon/tests/test_port_scan_bare_ip.py`.

`name` is set from the IANA registry by the port scan, and tlsx never touches
it: `name` is part of the Service MERGE key, so a tlsx run that "corrected" it
would orphan the node the port scan created and silently duplicate the service.

**Port 465 is the reason the hint exists.** IANA officially registers 465 as
`urd` (URL Rendezvous Directory), so the port scan labels the service `urd`
while the thing actually listening is SMTPS. `tls_service_hint=smtps` records
what the handshake says without renaming the node -- precisely the "found open,
labelled from a static table, never inspected again" gap this harness exists to
reproduce.

**Findings need the master switch.** The six TLS toggles sit behind the Security
Checks master toggle (`securityCheckEnabled`). With it off there are certificates
and zero findings, which looks identical to a broken check.

> ⚠️ Intentionally weak certificates. Local/trusted Docker host only.
