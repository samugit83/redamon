"""AI-planner helpers that delegate small LLM classification calls to the agent.

D3: these callers must present the scanner key so the agent's guarded
``/llm/*`` and ``/jev/*`` endpoints accept the request, and since step 1.16 the
scan's job credential beside it, from which the agent takes the user.
"""

from recon.helpers.scan_auth import scan_auth_headers


def internal_key_headers() -> dict:
    """The headers of an agent /llm/* or /jev/* call: the scanner key and the job credential."""
    return scan_auth_headers()


# One breaker shared by every agent /llm/* hook: they all reach the same agent,
# so a dead agent should stop being called after a few failures rather than
# costing each hook its 20-30s timeout per item. Threshold 3 (INTERNAL): the
# agent fails as a unit. The gate sits AFTER each hook's cache check, so a cache
# hit still answers while the breaker is open; when open, each hook returns its
# own existing fallback (SAFE_FALLBACK / current_tags), never raising.
def agent_llm_gate():
    """A one-shot gate for one agent /llm/* call. `.allowed` is False while the
    shared agent_llm breaker is open; feed the outcome back with `.record`."""
    from recon.helpers import circuit_breaker as cb

    class _Gate:
        def __init__(self):
            self._cb = cb
            self._breaker = cb.get_breaker("agent_llm", label="Agent-LLM",
                                           threshold=cb.INTERNAL_THRESHOLD)
            self.allowed = self._breaker.allow()
            self._epoch = self._breaker.epoch()

        def record(self, resp=None, exc=None):
            try:
                if exc is not None:
                    self._breaker.record(self._cb.Outcome.TRANSIENT, type(exc).__name__,
                                         epoch=self._epoch)
                    return
                outcome = self._cb.classify_http(resp, keyed=True)
                self._breaker.record(outcome, self._cb.http_detail(resp, outcome, keyed=True),
                                     epoch=self._epoch)
            except Exception:  # noqa: BLE001 - recording must never break a scan
                pass

    return _Gate()


# A SEPARATE breaker for the agent /jev/* endpoints. It must not be the
# agent_llm one: the LLM breaker marks 401/402/403 FATAL for the whole run, and
# a Jev auth/credit failure recorded there would silence the LLM hooks too.
# Jev failures arrive as 503 with an `error_type` in the body (the agent never
# leaks the TypeSafe status), so the outcome is read from that field.
_JEV_FATAL_ERRORS = frozenset({
    "jev_not_configured", "jev_auth", "jev_no_credit", "jev_forbidden",
})


def agent_jev_gate():
    """A one-shot gate for one agent /jev/* call, on the `agent_jev` breaker."""
    from recon.helpers import circuit_breaker as cb

    class _Gate:
        def __init__(self):
            self._cb = cb
            self._breaker = cb.get_breaker("agent_jev", label="Agent-Jev",
                                           threshold=cb.INTERNAL_THRESHOLD)
            self.allowed = self._breaker.allow()
            self._epoch = self._breaker.epoch()

        def record(self, resp=None, exc=None):
            try:
                if exc is not None:
                    self._breaker.record(self._cb.Outcome.TRANSIENT, type(exc).__name__,
                                         epoch=self._epoch)
                    return
                error_type = None
                # 503 for a Jev-side failure; 403 for jev_forbidden (a project that is
                # not this user's). Both carry the agent's fixed error_type body.
                if getattr(resp, "status_code", None) in (403, 503):
                    try:
                        error_type = (resp.json() or {}).get("error_type")
                    except Exception:  # noqa: BLE001
                        error_type = None
                if error_type is not None:
                    if error_type in _JEV_FATAL_ERRORS:
                        self._breaker.record(self._cb.Outcome.FATAL, error_type, epoch=self._epoch)
                    elif error_type == "jev_rate_limited":
                        retry_after = None
                        try:
                            retry_after = (resp.json() or {}).get("retry_after")
                        except Exception:  # noqa: BLE001
                            retry_after = None
                        self._breaker.record(self._cb.Outcome.RATE_LIMIT, error_type,
                                             retry_after=retry_after, epoch=self._epoch)
                    else:
                        self._breaker.record(self._cb.Outcome.TRANSIENT, error_type, epoch=self._epoch)
                    return
                outcome = self._cb.classify_http(resp, keyed=True)
                self._breaker.record(outcome, self._cb.http_detail(resp, outcome, keyed=True),
                                     epoch=self._epoch)
            except Exception:  # noqa: BLE001 - recording must never break a scan
                pass

    return _Gate()
