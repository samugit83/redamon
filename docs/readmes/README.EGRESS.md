# Egress routing for scan tools

How RedAmon tool traffic reaches the internet, and what to do when you need it
to come from somewhere else (a VPN exit, a corporate proxy, a specific country).

Related issue: [#237](../../issues/237).

## What exists today

**Tool containers share the host network.** Recon and agent tools run as
`docker run --rm --net=host <tool-image> ...`, so their traffic leaves through
the Docker host's default route — the same path as any other process on that
machine.

**There is no per-tool upstream proxy setting.** The old Tor/proxychains
anonymity feature (`USE_TOR_FOR_RECON`, `HTTP_PROXY` project keys,
proxychains prefixes) was removed deliberately, and a regression suite
(`recon/tests/test_tor_removal_regression.py`) fails the build if any of it
creeps back. Stale `HTTP_PROXY` / `USE_TOR_FOR_RECON` values in an old project
database are ignored on purpose: an unnoticed proxy value silently redirecting
scan traffic somewhere unexpected was judged worse than no proxy support.

**Do not confuse the capture proxy with an egress proxy.**
`CAPTURE_PROXY_ENABLED` routes the eight captured recon tools and eight agent
HTTP tools through the built-in mitmproxy on `127.0.0.1:8888` so their traffic
can be attributed, searched and replayed. That proxy *records* traffic and
forwards it from the same host network — it does not change where traffic
exits from.

## Routing tool egress today

Because tool containers use the host network, host-level routing affects every
tool without touching RedAmon:

1. **VPN / default route (simplest).** Bring up a VPN on the Docker host.
   Every tool container inherits the new default route. Verify with the tool
   of your choice against an IP-echo endpoint.
2. **Transparent redirect (iptables).** For a proxy that cannot be a default
   route, redirect outbound 80/443 to a local transparent proxy. Exclude at
   least:
   - the loopback range (the capture proxy publishes on `127.0.0.1:8888`),
   - the Docker bridge ranges the stack itself uses (postgres, neo4j, the
     webapp), so internal traffic never leaves the host.
3. **Socks-heavy setups.** Run the whole stack behind a network-level exit
   (a VM or box whose own egress is the proxy) and point RedAmon at it like
   any other host.

Whatever the mechanism, apply it before starting a scan; tools that already
resolved DNS or opened keep-alive connections keep using the old path.

## If you need a first-class per-project proxy

A native implementation would follow the capture-routing pattern in
`recon/helpers/proxy_routing.py`: a per-project setting, probed for
reachability at scan start with a fail-open fallback, and each tool invoked
with its own proxy flag (`nuclei -proxy`, `katana -proxy`, `ffuf -x`, `-x` for
curl) instead of environment variables, together with the same tag-leak guard
the capture path has. That is a deliberate feature decision for the
maintainers — this document only describes today's behaviour.
