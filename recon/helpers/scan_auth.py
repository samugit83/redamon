"""
The headers a scan container authenticates its calls back with (step 1.16).

The webapp's scanner routes (project settings, the owner's settings, the traffic
ingest) and the agent's /llm/* and /jev/* accept the scoped SCANNER_API_KEY only
together with the job credential the webapp minted for this scan, which the
orchestrator puts in the environment as REDAMON_JOB_CREDENTIAL. Every such call
builds its headers here, so none can forget the credential.
"""
import os


def scan_auth_headers() -> dict:
    # INTERNAL_API_KEY reaches no scan container any more; it is left for a CLI run
    # of the pipeline by an operator who holds the master key.
    headers = {"X-Internal-Key": os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY") or ""}
    job = os.environ.get("REDAMON_JOB_CREDENTIAL", "")
    if job:
        headers["X-Redamon-Job"] = job
    return headers
