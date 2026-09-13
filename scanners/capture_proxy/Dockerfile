# redamon-capture-proxy — one image, two roles (mitmdump proxy OR ingest worker).
# The role is selected by the compose `command:` + env + network, not the image,
# so isolation comes from placement (proxy: pentest-net, no DB creds; ingest:
# redamon-network, scoped INSERT-only role), per plan §15.2 / §15.10.
FROM python:3.12-slim

# Pinned deps (§15.10: the proxy parses untrusted target responses — keep patched).
# mitmproxy for the capture proxy; psycopg3 (already the stack's PG driver) for ingest.
RUN pip install --no-cache-dir "mitmproxy~=11.1" "psycopg[binary]~=3.2"

# Non-root, least-privilege user (§15.10). Spool + bodies volumes are the only
# writable paths at runtime (compose mounts them; root fs is read-only).
RUN useradd -m -u 10001 -s /usr/sbin/nologin capture

# Block privilege escalation by STRIPPING setuid/setgid bits from every binary,
# rather than the `no-new-privileges` flag — which breaks execve for non-root
# users on this project's snap-Docker/AppArmor hosts (see container_manager.py
# "no-new-privileges ... breaks execve"). Same approach the codefix sandbox uses.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app
COPY scanners/capture_proxy/redamon_ctx.py \
     scanners/capture_proxy/egress.py \
     scanners/capture_proxy/capture_lib.py \
     scanners/capture_proxy/capture_addon.py \
     scanners/capture_proxy/ingest_worker.py \
     scanners/capture_proxy/ioc_match.py \
     scanners/capture_proxy/session_extract.py \
     /app/
# Bundle the hard-guardrail so the proxy can enforce it WITHOUT any secret or
# network access (static domain blocklist). Kept in sync with the other copies.
COPY recon_orchestrator/hard_guardrail.py /app/hard_guardrail.py
# The resolved-IP denylist is shared verbatim with the orchestrator's own egress
# guards (TruffleHog start). Copied from the canonical file rather than
# duplicated in this tree, so the two can never drift apart.
COPY recon_orchestrator/ip_denylist.py /app/ip_denylist.py

# Pre-create the mount points owned by the runtime user. Docker copies this
# ownership onto an EMPTY named volume on first mount, so the non-root process
# can write the spool / body store / CA dir without a root init step.
RUN mkdir -p /spool /bodies /ca && chown -R capture:capture /spool /bodies /ca

USER capture

# Default command is the capture proxy; the ingest service overrides it in compose.
# --listen-port is provided at runtime; --set stream_large_bodies bounds memory.
# connection_strategy=lazy defers the upstream connection until AFTER the request
# hook, so the addon's DNS-rebinding IP pin (server_conn.address) actually applies.
CMD ["mitmdump", "--quiet", "--set", "connection_strategy=lazy", \
     "--set", "stream_large_bodies=5m", \
     "--listen-port", "8888", "-s", "/app/capture_addon.py"]
