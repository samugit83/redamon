"""
redamon-capture-proxy — mitmdump addon (plan §11.1, §11.2).

The target-facing, CREDENTIAL-FREE capture component. It runs `mitmdump -s
capture_addon.py` on pentest-net. Responsibilities:

  request hook:
    - lift the opaque `X-Redamon-Ctx` tag off the request and DELETE the header
      so it never leaks to the target (§7.2). The proxy carries it verbatim; it
      holds NO signing key and never decodes/verifies it (that's traffic-ingest).
    - enforce the egress guard (§15.3, §20.5): resolve the host, refuse internal
      IPs / hard-guardrail domains, pin the resolved IP. Blocked requests get a
      403 and a `blocked=true` spool record; they are NOT forwarded.

  response hook:
    - assemble the transaction, apply body inline/offload + dedup, stamp cheap
      passive signals, and append it to the append-only spool as one
      atomically-renamed file (concurrency-safe under many coroutines).

  backpressure:
    - a bounded queue drained by a writer thread; if it backs up, drop-and-count
      (never block the proxy data path).

Everything the LLM/analyst eventually sees is stamped from the VERIFIED tag by
traffic-ingest, never from anything this proxy or a target controls.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timezone

from mitmproxy import http

from capture_lib import (
    build_record, classify_family, decide_body, ensure_dir_writable,
    normalize_headers, parse_body_rules, sha256_hex,
)
from egress import check_egress, policy_from_dict, policy_from_env

try:
    from hard_guardrail import is_hard_blocked  # bundled into the image
except Exception:  # pragma: no cover - guardrail must exist in the image
    def is_hard_blocked(domain):
        return (False, "")


def _hard_blocked(host: str) -> bool:
    blocked, _ = is_hard_blocked(host)
    return blocked


def _host_in_recording_scope(host: str, scope_hosts) -> bool:
    """Exact host or ``*.suffix`` match for the operator-recording window.

    Deliberately narrow: no wildcards implied, apex not matched by ``*.``. The
    webapp already resolves scope from the project target, so this only enforces.
    """
    if not host or not scope_hosts:
        return False
    h = host.strip().rstrip(".").lower()
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    for entry in scope_hosts:
        entry = str(entry).strip().rstrip(".").lower()
        if not entry:
            continue
        if entry.startswith("*."):
            if h.endswith(entry[1:]):
                return True
        elif h == entry:
            return True
    return False


def _recording_expired(expires_at) -> bool:
    """True if the recording window has lapsed. Unparseable/absent => treat as
    NOT expired (the webapp only emits an unexpired window; the reconciler drops
    the block within one poll of stop), so a clock/format mismatch can't wedge a
    live recording. The bound is enforced authoritatively webapp-side."""
    if not expires_at:
        return False
    try:
        from datetime import datetime, timezone
        s = str(expires_at).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


def _num_env(name: str, default, cast):
    """Parse a numeric env var, falling back to `default` on missing/empty/garbage.
    Kept fail-safe because this runs in RedamonCapture.__init__, which is OUTSIDE
    the response-hook exception guard: a bad value here would crash-load the addon
    and silently kill all capture."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return cast(raw)
    except (ValueError, TypeError):
        return default


class RedamonCapture:
    CTX_HEADER = "X-Redamon-Ctx"

    def __init__(self) -> None:
        self.spool_dir = os.environ.get("CAPTURE_SPOOL_DIR", "/spool")
        self.bodies_dir = os.environ.get("CAPTURE_BODIES_DIR", "/bodies")
        # --- Reloadable runtime config: egress guard + body-storage policy -------
        # SINGLE SOURCE OF TRUTH is the DB (Global Settings > TrafficMind). The
        # trusted control plane (orchestrator) materialises those DB settings to a
        # JSON file on the shared spool volume; THIS proxy only READS that file and
        # HOT-RELOADS it on change. The proxy never connects to the DB — it is the
        # credential-free, target-facing component (§11.1). Env vars are ONLY the
        # pre-file cold-start default, and every one is fail-safe (block/keep), so a
        # missing or partially-written file can never open the egress guard.
        self.config_file = os.environ.get(
            "CAPTURE_CONFIG_FILE", os.path.join(self.spool_dir, ".capture-config.json"))
        self._config_sig = None
        self._config_lock = threading.Lock()
        self.active_recording = None     # set by _apply_config when a recording is live
        raw, sig = self._read_config()
        self._apply_config(raw)          # sets egress_policy + all body-storage knobs
        self._config_sig = sig
        self._cfg_watcher = threading.Thread(
            target=self._config_watch, name="config-watch", daemon=True)
        self._cfg_watcher.start()
        self.tmp_dir = os.path.join(self.spool_dir, ".tmp")
        ensure_dir_writable(self.tmp_dir)
        ensure_dir_writable(self.bodies_dir)
        # The bodies store is shared with the webapp (different uid) which reads
        # + ref-counted-GCs blobs, so make it group/other writable. Internal
        # volume only; blobs are never served by raw path (§15.7).
        try:
            os.chmod(self.bodies_dir, 0o777)
        except OSError:
            pass

        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=int(os.environ.get("CAPTURE_QUEUE_MAX", "2000")))
        self.dropped = 0
        self._writer = threading.Thread(target=self._drain, name="spool-writer", daemon=True)
        self._writer.start()

    # ---- reloadable config (DB -> control-plane file -> hot-reload) --------
    @staticmethod
    def _as_bool(v, default: bool = True) -> bool:
        """Fail-safe truthiness for file/env values. Missing/None/empty -> default
        (block/keep). Only an explicit false-like value turns a toggle OFF."""
        if v is None:
            return default
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s == "":
            return default
        return s not in ("false", "0", "no", "off")

    def _read_config(self):
        """Return (raw_dict_or_None, signature). No file -> (None, None). Present but
        unreadable/invalid -> ({}, signature): fall back to fail-safe defaults rather
        than keep a possibly stale-open policy.

        The signature is the raw file BYTES, so change detection is exact — no reliance
        on mtime resolution (float precision / coarse-granularity or network volumes),
        and a rewrite with identical content is correctly treated as no-change."""
        try:
            with open(self.config_file, "rb") as f:
                data = f.read()
        except OSError:
            return None, None
        try:
            raw = json.loads(data.decode("utf-8"))
            return (raw if isinstance(raw, dict) else {}), data
        except ValueError:  # JSONDecodeError + UnicodeDecodeError are both ValueError
            return {}, data

    def _apply_config(self, raw) -> None:
        """Build the reloadable settings from the file (authoritative when present)
        or, per section, from env (cold-start fallback), then assign atomically.
        The egress guard NEVER relaxes from a malformed file: policy_from_dict /
        policy_from_env both default every check to block."""
        raw = raw if isinstance(raw, dict) else {}
        egress = raw.get("egress")
        if isinstance(egress, dict):
            policy, esrc = policy_from_dict(egress), "file"
        else:
            policy, esrc = policy_from_env(os.environ), "env"

        body = raw.get("body")
        if isinstance(body, dict):
            store_bodies = self._as_bool(body.get("store_bodies"), True)
            store_req = self._as_bool(body.get("store_req_bodies"), True)
            store_resp = self._as_bool(body.get("store_resp_bodies"), True)
            try:
                max_body_kb = int(body.get("max_body_kb") or 64)
            except (ValueError, TypeError):
                max_body_kb = 64
            try:
                _msm = body.get("max_store_mb")
                max_store_mb = float(_msm if _msm is not None else 5.0)
            except (ValueError, TypeError):
                max_store_mb = 5.0
            body_rules = parse_body_rules(body.get("body_rules") or "")
            bsrc = "file"
        else:
            store_bodies = os.environ.get("CAPTURE_PROXY_STORE_BODIES", "true").lower() != "false"
            store_req = os.environ.get("CAPTURE_STORE_REQ_BODIES", "true").lower() != "false"
            store_resp = os.environ.get("CAPTURE_STORE_RESP_BODIES", "true").lower() != "false"
            max_body_kb = _num_env("CAPTURE_PROXY_MAX_BODY_KB", 64, int)
            max_store_mb = _num_env("CAPTURE_MAX_STORE_MB", 5.0, float)
            body_rules = parse_body_rules(os.environ.get("CAPTURE_BODY_RULES", ""))
            bsrc = "env"

        # The RedAmon-service IP denylist is a SECURITY invariant, NOT a DB-tunable
        # knob: it is ALWAYS sourced from env CAPTURE_BLOCKED_IPS and can never be
        # relaxed by the config file (egress.is_internal_ip enforces it un-gated).
        extra_blocked = [ip for ip in os.environ.get("CAPTURE_BLOCKED_IPS", "").split(",") if ip.strip()]

        # Operator-recording window (Phase 2): when the webapp is recording a
        # login for a project, the reconciled config carries a pre-signed
        # `operator` tag + its scope + expiry. The proxy mints NOTHING; it stamps
        # this verbatim tag onto UNTAGGED, in-scope requests (see request()).
        # A malformed/absent block => no injection (fail closed).
        ar = raw.get("active_recording")
        active_recording = None
        if isinstance(ar, dict) and ar.get("tag"):
            scope = ar.get("scope_hosts")
            active_recording = {
                "tag": str(ar["tag"]),
                "scope_hosts": [str(h).strip().lower() for h in scope if str(h).strip()] if isinstance(scope, list) else [],
                "expires_at": ar.get("expires_at"),
            }

        with self._config_lock:
            self.egress_policy = policy
            self.store_bodies = store_bodies
            self.store_req_bodies = store_req
            self.store_resp_bodies = store_resp
            self.max_body_bytes = int(max_body_kb) * 1024
            self.max_store_bytes = int(max_store_mb * 1024 * 1024) if max_store_mb > 0 else 0
            self.extra_blocked_ips = extra_blocked
            self.body_rules = body_rules
            self.active_recording = active_recording
        print(f"[capture] config applied: egress<-{esrc} body<-{bsrc} "
              f"block_private={policy.block_private} store_bodies={store_bodies} "
              f"max_body_bytes={self.max_body_bytes} extra_blocked={len(extra_blocked)}", flush=True)

    def _config_watch(self) -> None:
        """Poll the config file; re-read + re-apply whenever its CONTENT changes. Any
        error keeps the current (already-applied) settings — a bad write never crashes
        capture."""
        interval = _num_env("CAPTURE_CONFIG_POLL_SEC", 5.0, float) or 5.0
        while True:
            time.sleep(interval)
            try:
                raw, sig = self._read_config()
                if sig != self._config_sig:
                    self._apply_config(raw)
                    self._config_sig = sig
            except Exception as e:  # never let the watcher die
                print(f"[capture] config-watch error (keeping current config): {e}", flush=True)

    # ---- mitmproxy hooks ---------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        # Lift + strip the internal tag BEFORE anything can forward it upstream.
        token = flow.request.headers.pop(self.CTX_HEADER, None)

        # Operator recording (Phase 2): only when there is NO real tag (never
        # override a scanner/agent tag) AND a recording window is active AND the
        # request host is in the recording scope, stamp the pre-signed operator
        # tag. Out-of-scope operator browsing stays untagged -> rejected at ingest,
        # so it never lands in the corpus. The proxy mints nothing.
        if token is None:
            ar = getattr(self, "active_recording", None)
            if ar and not _recording_expired(ar.get("expires_at")) \
                    and _host_in_recording_scope(flow.request.pretty_host, ar.get("scope_hosts") or []):
                token = ar["tag"]

        flow.metadata["redamon_ctx"] = token
        flow.metadata["redamon_started"] = time.time()

        try:
            allowed, pinned_ip, reason = check_egress(
                flow.request.pretty_host, hard_blocked=_hard_blocked,
                extra_blocked_ips=self.extra_blocked_ips,
                policy=self.egress_policy,
            )
        except Exception as e:
            # On a guard-internal error: fail CLOSED (block) by default. The
            # operator can flip this to fail-open via the "Fail closed on guard
            # error" toggle; dangerous, but exposed for completeness. Fail-open
            # forwards WITHOUT IP pinning (mitmproxy resolves + connects normally).
            if self.egress_policy.fail_closed_on_error:
                allowed, pinned_ip, reason = (False, None, f"guard-error:{e}")
            else:
                allowed, pinned_ip, reason = (True, None, f"guard-error-failopen:{e}")

        if not allowed:
            # Refuse: do not forward. Record the attempt for the scope audit.
            print(f"[capture] BLOCKED {flow.request.pretty_host} ({reason})", flush=True)
            flow.metadata["redamon_blocked"] = reason
            flow.response = http.Response.make(
                403, b"blocked by redamon capture proxy egress guard\n",
                {"Content-Type": "text/plain"},
            )
            self._emit_blocked(flow, reason)
            return

        flow.metadata["redamon_pinned_ip"] = pinned_ip
        # Pin the upstream connection to the vetted IP so mitmproxy does NOT
        # re-resolve the hostname and get a rebound internal IP between the guard
        # check and the connection (DNS-rebinding TOCTOU, §20.5). We set the server
        # connection address ONLY (not request.host), so the Host header + TLS SNI
        # keep the original hostname and vhosts/HTTPS still work.
        if pinned_ip and pinned_ip != flow.request.host:
            try:
                flow.server_conn.address = (pinned_ip, flow.request.port)
            except Exception as e:
                print(f"[capture] pin failed for {flow.request.pretty_host}: {e}", flush=True)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("redamon_blocked"):
            return  # already emitted in request hook
        try:
            self._emit(flow)
        except Exception as e:  # never break the proxy path
            print(f"[capture] emit failed: {e}", flush=True)

    # ---- internals ---------------------------------------------------------
    def _emit_blocked(self, flow: http.HTTPFlow, reason: str) -> None:
        req_headers = normalize_headers(flow.request.headers.items(multi=True))
        rec = build_record(
            ctx_token=flow.metadata.get("redamon_ctx"),
            method=flow.request.method, scheme=flow.request.scheme,
            host=flow.request.pretty_host, port=flow.request.port,
            path=flow.request.path.split("?", 1)[0],
            query=flow.request.path.split("?", 1)[1] if "?" in flow.request.path else "",
            req_headers=req_headers, resp_headers={}, status_code=None,
            req_body_inline=None, req_body_ref=None, req_body_size=0, req_body_sha=None,
            resp_body_inline=None, resp_body_ref=None, resp_body_size=0, resp_body_sha=None,
            http_version=None, is_tls=flow.request.scheme == "https", tls_version=None,
            target_ip=None, response_time_ms=None,
            started_at=datetime.now(timezone.utc).isoformat(),
            blocked=True, in_scope=False, error_text=f"egress:{reason}",
        )
        self._enqueue(rec)

    def _emit(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        req_headers = normalize_headers(req.headers.items(multi=True))
        resp_headers = normalize_headers(resp.headers.items(multi=True)) if resp else {}

        req_raw = req.raw_content if req and req.raw_content else None
        resp_raw = resp.raw_content if resp and resp.raw_content else None

        # Classify each body into a storage family (content-type, with a URL
        # filename-extension fallback that rescues octet-stream-mislabeled files).
        req_family = classify_family(req_headers.get("content-type"), path=req.path)
        resp_family = classify_family(resp_headers.get("content-type"), path=req.path)
        rb_inline, rb_ref, rb_size, rb_sha = decide_body(
            req_raw, family=req_family, rules=self.body_rules,
            inline_cap_bytes=self.max_body_bytes, max_store_bytes=self.max_store_bytes,
            store=self.store_bodies and self.store_req_bodies)
        sb_inline, sb_ref, sb_size, sb_sha = decide_body(
            resp_raw, family=resp_family, rules=self.body_rules,
            inline_cap_bytes=self.max_body_bytes, max_store_bytes=self.max_store_bytes,
            store=self.store_bodies and self.store_resp_bodies)

        # Offload bodies to the content-addressed store (dedup by sha).
        if rb_ref and req_raw is not None:
            self._offload(rb_ref, req_raw)
        if sb_ref and resp_raw is not None:
            self._offload(sb_ref, resp_raw)

        started = flow.metadata.get("redamon_started")
        rt_ms = int((time.time() - started) * 1000) if started else None
        path = req.path.split("?", 1)[0]
        query = req.path.split("?", 1)[1] if "?" in req.path else ""

        rec = build_record(
            ctx_token=flow.metadata.get("redamon_ctx"),
            method=req.method, scheme=req.scheme, host=req.pretty_host, port=req.port,
            path=path, query=query, req_headers=req_headers, resp_headers=resp_headers,
            status_code=resp.status_code if resp else None,
            req_body_inline=rb_inline, req_body_ref=rb_ref, req_body_size=rb_size, req_body_sha=rb_sha,
            resp_body_inline=sb_inline, resp_body_ref=sb_ref, resp_body_size=sb_size, resp_body_sha=sb_sha,
            http_version=getattr(resp, "http_version", None) if resp else None,
            is_tls=req.scheme == "https", tls_version=None,
            target_ip=flow.metadata.get("redamon_pinned_ip"),
            response_time_ms=rt_ms, started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._enqueue(rec)

    def _offload(self, sha: str, raw: bytes) -> None:
        dest = os.path.join(self.bodies_dir, sha)
        if os.path.exists(dest):
            return  # dedup
        # The temp file MUST live in bodies_dir so os.replace is a SAME-FILESYSTEM
        # rename. /spool and /bodies are separate mounts, so staging the temp in
        # /spool/.tmp made os.replace raise EXDEV ("cross-device link") — which the
        # old bare `except OSError` swallowed silently, dropping every offloaded
        # blob while the DB ref was still written (dangling resp_body_ref rows).
        tmp = os.path.join(self.bodies_dir, f".tmp-{uuid.uuid4().hex}")
        try:
            with open(tmp, "wb") as f:
                f.write(raw)
            os.replace(tmp, dest)  # atomic within bodies_dir (same filesystem)
        except OSError as e:
            print(f"[capture] body offload failed (sha={sha[:12]}): {e}", flush=True)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _enqueue(self, rec: dict) -> None:
        try:
            self._q.put_nowait(rec)
        except queue.Full:
            self.dropped += 1
            if self.dropped % 100 == 1:
                print(f"[capture] spool queue full, dropped={self.dropped}", flush=True)

    def _drain(self) -> None:
        while True:
            rec = self._q.get()
            try:
                self._write_spool(rec)
            except Exception as e:
                print(f"[capture] spool write failed: {e}", flush=True)
            finally:
                self._q.task_done()

    def _write_spool(self, rec: dict) -> None:
        name = f"{time.time_ns()}-{uuid.uuid4().hex}.json"
        tmp = os.path.join(self.tmp_dir, name)
        final = os.path.join(self.spool_dir, name)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False)
        os.replace(tmp, final)  # atomic publish; ingest only ever sees complete files


addons = [RedamonCapture()]
