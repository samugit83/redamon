"""TruffleHog over the JavaScript JS Recon analyses: stage, run, parse, map, merge.

js_recon keeps its own rules for everything JavaScript-specific. This module runs
TruffleHog (`redamon-trufflehog:latest`, 3.96.0) in a hardened sidecar over the
same files, local copies only: downloaded bundles, files recovered from source
maps, uploads. Its results are merged into js_recon's, one finding per key:

* a key both engines find keeps js_recon's identity (id, name, matched text),
  so mutes and verdicts survive, and gains `TruffleHog:<Detector>` in
  `alternate_names` plus `validation.trufflehog`;
* a key only TruffleHog finds becomes a finding with
  `detection_method: 'trufflehog'`, its id built by js_recon's own formula.

Three rules from measuring the binary decide the rest:

* V1. Only `Verified: true` changes a status (to `validated`). With no network
  a provider check swallows the error and answers `Verified: false` exactly as
  for a dead key, so TruffleHog never writes `rejected`; js_recon's own
  validators stay the only source of it.
* V2. A detector whose verifier dials a host taken from the scanned text, or
  sends the key to a third party, is always excluded: the text is hostile, and
  with verification on it would make the sidecar an SSRF probe.
* M1. TruffleHog's `line` is right but a minified bundle is one line, so each
  key is located here, by searching its `Raw` in the file. A `Raw` that is not
  in the file literally was decoded (base64 in `atob()`, `\\uXXXX`).

Every docker call goes through `subprocess` with `env=None`: the inherited
DOCKER_HOST and DOCKER_CONFIG make the broker stamp the run's labels on the
sidecar, so a pause or stop of the run reaches it. A raw value, `RawV2` or
`SecretParts` is never logged; the key and its pair's other half are stored
only in the display fields (`secret_value`, `paired_secret`, `raw_context`).
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from recon.helpers.js_recon import patterns

TRUFFLEHOG_IMAGE = "redamon-trufflehog:latest"
VERIFY_NETWORK = "redamon-trufflehog-net"
STAGE_ROOT = "/tmp/redamon"
STAGE_PREFIX = "js_recon_th_"
CONTAINER_PREFIX = "redamon-jsth-"
#: The resource governor's key for this sidecar (not the Secret Multiscanner's).
ENVELOPE_TOOL = "trufflehog_js"
#: The uid of the image's `trufflehog` user; staged files must be readable by it.
SIDECAR_USER = "10001:10001"

#: TruffleHog 3.96.0 detectors never run over target JS (rule V2), reviewed
#: per detector from its source. The flag matches names case-insensitively,
#: drops every version of a name, and REFUSES an unknown name (exit 1, no
#: results), so a TruffleHog upgrade needs this list re-reviewed.
TRUFFLEHOG_EXCLUDED_DETECTORS = frozenset({
    # Databases, brokers, directories, file servers: the driver dials the host
    # written in the connection string.
    "Postgres", "MongoDB", "JDBC", "SQLServer", "Redis", "RabbitMQ", "LDAP", "FTP",
    # Generic URLs and issuers: the verifier fetches a URL taken from the
    # credential itself (the URI host, a JWT's `iss`, a service account's
    # `token_uri`, a docker config's registry).
    "URI", "JWT", "GCP", "Docker",
    # Self-hosted products: the base-URL capture accepts any host (JiraToken v2
    # posts to every domain in the chunk).
    "BitbucketDataCenter", "ConfluenceDataCenter", "JiraDataCenterPAT", "JiraToken",
    "Metabase", "Portainer", "PortainerToken",
    # A provider-looking host regex the text can escape (`#`, `/`, `?`, an
    # unescaped dot or a missing one before the provider domain).
    "AzureBatch", "AzureSearchQueryKey", "HashiCorpVaultToken", "HashiCorpVaultBatchToken",
    "HashiCorpVaultAuth", "Auth0oauth", "Repairshopr", "Sugester", "Vouchery", "SauceLabs",
    "MattermostPersonalToken", "Mite", "Snowflake",
    # Third party: the key fingerprint goes to keychecker.trufflesecurity.com.
    "PrivateKey",
})

#: What the result filter (`JS_RECON_TRUFFLEHOG_RESULTS`) can keep.
RESULT_CLASSES = ("verified", "unknown", "unverified")

#: The `ExtraData` keys kept; the rest can carry hosts, emails or ARNs.
EXTRA_DATA_ALLOWLIST = ("account", "resource_type", "token_type", "version", "rotation_guide")

_STAGE_MAX_BYTES = 256 * 1024 * 1024
_STDOUT_MAX_BYTES = 64 * 1024 * 1024
_STDOUT_MAX_LINES = 20_000
_TICK_S = 2.0
#: A recon pause freezes this process, which then sees one large clock jump;
#: no tick counts for more than this, so a pause never spends the budget.
_TICK_CAP_S = 4.0
_STDERR_TAIL_LINES = 5
_STDERR_LINE_MAX = 300

#: TruffleHog DetectorName -> (Raw prefix, js_recon secret_type), first match
#: wins; checked against the 3.96.0 binary on invented keys. A detector with
#: no entry (or no matching prefix) keeps its own DetectorName as the type.
_DETECTOR_NAMES = {
    "AWS": (("AKIA", "AWS Access Key ID"),),
    "AWSSessionKey": (("ASIA", "AWS Session Key"),),
    "Stripe": (("sk_live_", "Stripe Secret Key"), ("rk_live_", "Stripe Restricted Key"),
               ("sk_test_", "Stripe Test Key")),
    "Github": (("github_pat_", "GitHub Fine-grained Token"), ("ghp_", "GitHub Token Classic"),
               ("gho_", "GitHub OAuth Token"), ("ghu_", "GitHub App Token"),
               ("ghs_", "GitHub App Token"), ("ghr_", "GitHub Refresh Token")),
    "Slack": (("xoxb-", "Slack Bot Token"), ("xoxp-", "Slack User Token"),
              ("xapp-", "Slack App Token"), ("xoxo-", "Slack Legacy Token"),
              ("xoxs-", "Slack Legacy Token")),
    "OpenAI": (("sk-proj-", "OpenAI Project Key"), ("", "OpenAI API Key")),
    "Anthropic": (("sk-ant-admin01-", "Anthropic Admin Key"), ("", "Anthropic API Key")),
    # Public by design; a verified one takes the unrestricted-key path.
    "GoogleGeminiAPIKey": (("AIza", "GCP API Key"),),
    "SendGrid": (("SG.", "SendGrid API Key"),),
    "Mailgun": (("key-", "Mailgun API Key"),),
    "Twilio": (("AC", "Twilio Account SID"),),
    "Gitlab": (("glpat-", "GitLab PAT"),),
    "DigitalOceanV2": (("dop_v1_", "DigitalOcean Token"), ("doo_v1_", "DigitalOcean OAuth"),
                       ("dor_v1_", "DigitalOcean Refresh Token")),
    "Shopify": (("shpat_", "Shopify Access Token"), ("shpca_", "Shopify Custom Access Token"),
                ("shppa_", "Shopify Private App Token"), ("shpss_", "Shopify Shared Secret")),
    "HuggingFace": (("api_org_", "HuggingFace Org Token"), ("hf_", "HuggingFace Access Token")),
    "TelegramBotToken": (("", "Telegram Bot Token"),),
    "DiscordBotToken": (("", "Discord Bot Token"),),
    "TravisCI": (("", "Travis CI Token"),),
}

#: Detectors whose `Raw` is the key joined to something else; the key is the
#: leading match, which is what the file holds.
_RAW_KEY = {
    "Shopify": re.compile(r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"),
}

_PATTERN_BY_NAME = {p["name"]: p for p in patterns.JS_SECRET_PATTERNS}


# --------------------------------------------------------------------------- staging

@dataclass
class Staging:
    dir: str
    #: staged file name -> {"url", "content"}
    manifest: dict = field(default_factory=dict)
    bytes: int = 0
    skipped: int = 0


def run_id() -> str:
    """The run this process belongs to, safe for a path and a container name."""
    raw = os.environ.get("RECON_RUN_ID") or os.environ.get("PARTIAL_RECON_RUN_ID") or "local"
    return re.sub(r"[^A-Za-z0-9_-]", "_", raw)[:64] or "local"


def stage_files(js_files: list, run: str, root: str = STAGE_ROOT) -> Staging:
    """Write every file's content to its own stage dir, `f_00001.js` ...

    A separate dir, never js_recon's `work_dir`: the supply-chain stage reads
    that one as exactly the downloaded files. Source-map pseudo-files exist only
    in memory, so they are written here too. The dir removes itself when the
    run is stopped (a registered drain) or the process exits.
    """
    path = os.path.join(root, f"{STAGE_PREFIX}{run}_{uuid.uuid4().hex[:8]}")
    os.makedirs(path, mode=0o755, exist_ok=False)
    os.chmod(path, 0o755)
    staging = Staging(dir=path)
    _register_removal(path)
    n = 0
    for f in js_files:
        content = f.get("content") or ""
        url = f.get("url") or ""
        if not content.strip() or not url:
            continue
        size = len(content.encode("utf-8", errors="replace"))
        if staging.bytes + size > _STAGE_MAX_BYTES:
            staging.skipped += 1
            continue
        n += 1
        name = f"f_{n:05d}.js"
        target = os.path.join(path, name)
        with open(target, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content)
        os.chmod(target, 0o644)
        staging.manifest[name] = {"url": url, "content": content}
        staging.bytes += size
    return staging


def remove_stage(path: Optional[str]) -> None:
    if path:
        shutil.rmtree(path, ignore_errors=True)


def _register_removal(path: str) -> None:
    def drain(_deadline=None):
        remove_stage(path)
    try:
        from recon.helpers import shutdown
        shutdown.register_drain(drain)
    except Exception:  # noqa: BLE001 - outside a recon container there is no stopper
        pass
    atexit.register(remove_stage, path)


# --------------------------------------------------------------------------- argv

def sidecar_memory() -> Optional[str]:
    """`--memory` from the resource governor: the envelope x headroom, or the
    envelope itself when the governor has no cap to give."""
    try:
        try:
            from graph_db import resource_governor as rg
        except ImportError:
            import resource_governor as rg  # noqa: F401 - alt sys.path (tests)
        envelope = rg.tool_container_envelope(ENVELOPE_TOOL)
        cap = rg.container_cap(envelope)
        value = cap or envelope
        return str(int(value)) if value else None
    except Exception:  # noqa: BLE001 - no governor: the broker's flat ceiling applies
        return None


def build_argv(stage_dir: str, *, verify: bool, concurrency: int, validation_timeout: int,
               name: str, image: str = TRUFFLEHOG_IMAGE, network: Optional[str] = None,
               memory: Optional[str] = None) -> list:
    """The hardened `docker run` for one scan. No network at all when nothing is
    verified; the plain TruffleHog bridge (never `host`) when it is. The V2
    exclusions are passed in both modes, so the findings are the same either way."""
    argv = [
        "docker", "run", "--rm", "--name", name,
        "--cap-drop", "ALL", "--read-only",
        "--tmpfs", "/tmp:size=256m",
        "--pids-limit", "256", "--cpus", "2",
        "--user", SIDECAR_USER,
    ]
    memory = memory or sidecar_memory()
    if memory:
        argv += ["--memory", memory]
    argv += ["--network", (network or VERIFY_NETWORK) if verify else "none"]
    argv += [
        "-v", f"{stage_dir}:/scan:ro",
        "--entrypoint", "trufflehog", image,
        "filesystem", "/scan", "--json", "--no-update", "--fail-on-scan-errors",
        "--exclude-detectors=" + ",".join(sorted(TRUFFLEHOG_EXCLUDED_DETECTORS)),
    ]
    concurrency = max(1, int(concurrency or 1))
    if verify:
        # The verification cache stays on (one check per distinct key per run):
        # every check is a call to the key's provider.
        argv += [f"--detector-timeout={max(1, int(validation_timeout or 5))}s",
                 "--concurrency", str(min(concurrency, 4))]
    else:
        argv += ["--no-verification", "--concurrency", str(concurrency)]
    return argv


def container_name(run: str) -> str:
    return f"{CONTAINER_PREFIX}{run[:8]}-{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------------------------- docker

def _stop_requested() -> bool:
    try:
        from recon.helpers import shutdown
        return shutdown.stop_requested()
    except Exception:  # noqa: BLE001
        return False


def _is_launch_refused(exc: BaseException) -> bool:
    try:
        from recon.helpers.shutdown import ToolLaunchRefused
        return isinstance(exc, ToolLaunchRefused)
    except Exception:  # noqa: BLE001
        return False


def _docker(args: list, timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
    """A short docker CLI call; None when it could not run."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              timeout=timeout, check=False, env=None)
    except Exception:  # noqa: BLE001 - incl. ToolLaunchRefused while the run stops
        return None


def image_available(image: str = TRUFFLEHOG_IMAGE) -> bool:
    res = _docker(["image", "inspect", image], timeout=15)
    return bool(res) and res.returncode == 0


def ensure_verify_network(name: str = VERIFY_NETWORK) -> bool:
    """The plain bridge the orchestrator's TruffleHog scans use, created the
    same way when missing (ContainerManager._ensure_trufflehog_network)."""
    res = _docker(["network", "inspect", name], timeout=15)
    if res is not None and res.returncode == 0:
        return True
    res = _docker(["network", "create", "--driver", "bridge", name], timeout=30)
    if res is not None and res.returncode == 0:
        return True
    again = _docker(["network", "inspect", name], timeout=15)  # lost a create race
    return again is not None and again.returncode == 0


@dataclass
class SidecarResult:
    status: str  # ran | failed | timed_out | stopped | truncated
    reason: str = ""
    stdout: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    stderr_tail: list = field(default_factory=list)


def _classify_stderr(stderr: str) -> str:
    low = stderr.lower()
    if "denied by docker-broker" in low:
        return "broker_busy" if "count cap" in low else "broker_refused"
    if "no such image" in low or "unable to find image" in low or "pull access denied" in low:
        return "image_missing"
    return ""


def _tail(stderr: str) -> list:
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    # TruffleHog logs JSON lines on stderr; keep only the message of each.
    out = []
    for ln in lines[-_STDERR_TAIL_LINES:]:
        try:
            ln = str(json.loads(ln).get("msg") or ln)
        except (ValueError, AttributeError):
            pass
        out.append(ln[:_STDERR_LINE_MAX])
    return out


def run_sidecar(argv: list, *, name: str, budget_s: float,
                clock: Callable[[], float] = time.monotonic,
                sleep: Callable[[float], None] = time.sleep) -> SidecarResult:
    """Run the container and read its NDJSON. Never raises.

    The budget counts RUNNING time: every tick adds at most _TICK_CAP_S, so the
    clock jump a recon pause leaves behind costs one tick, not the pause.
    Spent -> `docker kill <name>` -> timed_out. A run being stopped -> stopped,
    with nothing killed here: the stopper SIGTERMs the docker CLI, which
    forwards it, and the orchestrator removes the run's tools.
    """
    started = clock()
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, errors="replace", env=None)
    except Exception as exc:  # noqa: BLE001
        if _is_launch_refused(exc) or _stop_requested():
            return SidecarResult("stopped", "run stopping")
        return SidecarResult("failed", f"launch: {type(exc).__name__}")

    out_lines: list = []
    out_state = {"bytes": 0, "over": False}
    err_chunks: list = []

    def read_out():
        for line in proc.stdout:
            if out_state["over"]:
                continue
            out_state["bytes"] += len(line)
            if out_state["bytes"] > _STDOUT_MAX_BYTES or len(out_lines) >= _STDOUT_MAX_LINES:
                out_state["over"] = True
                continue
            out_lines.append(line)

    def read_err():
        for line in proc.stderr:
            err_chunks.append(line)
            if len(err_chunks) > 200:
                del err_chunks[:100]

    readers = [threading.Thread(target=read_out, daemon=True),
               threading.Thread(target=read_err, daemon=True)]
    for t in readers:
        t.start()

    elapsed, last = 0.0, clock()
    status, reason = "", ""
    while proc.poll() is None:
        if _stop_requested():
            status, reason = "stopped", "run stopping"
            break
        if out_state["over"]:
            _docker(["kill", name], timeout=15)
            status, reason = "truncated", "output cap"
            break
        sleep(_TICK_S)
        now = clock()
        elapsed += min(max(0.0, now - last), _TICK_CAP_S)
        last = now
        if elapsed >= budget_s:
            _docker(["kill", name], timeout=15)
            status, reason = "timed_out", f"budget {int(budget_s)}s"
            break
    try:
        proc.wait(timeout=30)
    except Exception:  # noqa: BLE001
        pass
    for t in readers:
        t.join(timeout=5)

    stderr = "".join(err_chunks)
    result = SidecarResult(status or "ran", reason, "".join(out_lines), proc.returncode,
                           round(clock() - started, 1), _tail(stderr))
    if status:
        return result
    if out_state["over"]:
        result.status, result.reason = "truncated", "output cap"
    elif proc.returncode == 0:
        result.status = "ran"
    elif _stop_requested():
        result.status, result.reason = "stopped", "run stopping"
    else:
        result.status = "failed"
        result.reason = _classify_stderr(stderr) or f"exit {proc.returncode}"
    return result


# --------------------------------------------------------------------------- parse

@dataclass
class ThResult:
    detector: str
    verified: bool
    error: str  # "" when verification raised no error
    raw: str
    file: str  # staged file name
    line: Optional[int]
    extra: dict
    #: The other secret parts (an AWS pair's secret, a session token), to mask
    #: them in the reviewer-facing context. Never logged.
    mask_values: tuple = ()
    #: The pair's other half (an AWS secret access key) kept for the operator as
    #: `paired_secret`; "" when the detector has no second part.
    paired: str = ""


def parse_ndjson(stdout: str) -> tuple:
    """`(results, bad_lines)` from TruffleHog's stdout. Reads only what the merge
    needs; `RawV2` and `SecretParts` give the pair's other half (`paired`, kept
    for display) and the values to mask, and are dropped after."""
    results, bad = [], 0
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(obj, dict) or "DetectorName" not in obj:
            # A log line that reached stdout is not a result.
            if not (isinstance(obj, dict) and "level" in obj):
                bad += 1
            continue
        fs = ((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        raw = str(obj.get("Raw") or "")
        if not raw:
            bad += 1
            continue
        extra = obj.get("ExtraData") if isinstance(obj.get("ExtraData"), dict) else {}
        results.append(ThResult(
            detector=str(obj.get("DetectorName") or ""),
            verified=obj.get("Verified") is True,
            error=str(obj.get("VerificationError") or ""),
            raw=raw,
            file=os.path.basename(str(fs.get("file") or "")),
            line=fs.get("line") if isinstance(fs.get("line"), int) else None,
            extra={k: str(extra[k])[:200] for k in EXTRA_DATA_ALLOWLIST if extra.get(k) not in (None, "")},
            mask_values=_mask_values(obj, raw),
            paired=_paired_secret(obj, raw),
        ))
    return results, bad


def _paired_secret(obj: dict, raw: str) -> str:
    """The pair's other half: a `SecretParts` value whose name says secret, else
    the first other part of `RawV2` ("AKID:SECRET"). "" when there is none."""
    parts = obj.get("SecretParts")
    if isinstance(parts, dict):
        named = [v for k, v in parts.items() if isinstance(v, str) and v and v != raw
                 and "://" not in v and "secret" in str(k).lower()]
        if named:
            return named[0]
    others = _mask_values(obj, raw)
    return others[0] if others else ""


def _mask_values(obj: dict, raw: str) -> tuple:
    values = set()
    raw_v2 = str(obj.get("RawV2") or "")
    for part in re.split(r"[:\t]", raw_v2) if raw_v2 else ():
        if len(part) >= 8 and part != raw:
            values.add(part)
    parts = obj.get("SecretParts")
    if isinstance(parts, dict):
        for v in parts.values():
            if isinstance(v, str) and len(v) >= 8 and v != raw and "://" not in v:
                values.add(v)
    return tuple(sorted(values))


# --------------------------------------------------------------------------- map

def mapped_name(detector: str, raw: str) -> str:
    for prefix, name in _DETECTOR_NAMES.get(detector, ()):
        if raw.startswith(prefix):
            return name
    return detector


def key_of(detector: str, raw: str) -> str:
    extract = _RAW_KEY.get(detector)
    m = extract.match(raw) if extract else None
    return m.group(0) if m else raw


def error_class(error: str) -> str:
    """A short class for a VerificationError; the message itself can hold a URL."""
    low = (error or "").lower()
    if not low:
        return ""
    if "timeout" in low or "deadline" in low:
        return "timeout"
    if "no such host" in low or "dns" in low:
        return "dns"
    if "refused" in low or "reset" in low or "unreachable" in low or "dial tcp" in low or "eof" in low:
        return "network"
    m = re.search(r"\b([1-5]\d\d)\b", low)
    if m:
        return f"http_{m.group(1)}"
    return "error"


def result_class(r: ThResult) -> str:
    if r.verified:
        return "verified"
    return "unknown" if r.error else "unverified"


def validation_of(r: ThResult, *, verify: bool) -> dict:
    """js_recon's `validation` for a TruffleHog-only finding (rule V1)."""
    info = {"detector": r.detector, "verified": r.verified, "error_class": error_class(r.error),
            "extra": dict(r.extra)}
    if not verify:
        return {"status": "skipped", "trufflehog": info}
    if r.verified:
        return {"status": "validated", "valid": True, "checked_by": "trufflehog", "trufflehog": info}
    return {"status": "unknown", "checked_by": "trufflehog", "trufflehog": info}


def locate(raw: str, content: str) -> Optional[tuple]:
    """`(line, start, end)` of the first literal occurrence; None = decoded."""
    if not raw:
        return None
    start = content.find(raw)
    if start < 0:
        return None
    return content.count("\n", 0, start) + 1, start, start + len(raw)


def masked_context(content: str, start: int, end: int, secret_values) -> str:
    """At most CONTEXT_MAX_CHARS around the key, every known secret of the file
    (both engines) masked whole by `patterns.redact`."""
    side = patterns._CONTEXT_SIDE
    ws, we = max(0, start - side), min(len(content), end + side)
    spans = []
    for value in sorted({v for v in secret_values if v}, key=len, reverse=True):
        lo = max(0, ws - len(value))
        pos = content.find(value, lo)
        while 0 <= pos < we:
            spans.append((pos, pos + len(value)))
            pos = content.find(value, pos + 1)
    text, mark = patterns._render(content, ws, we, patterns._merge_spans(spans), focus=start)
    limit = patterns.CONTEXT_MAX_CHARS
    if len(text) > limit:
        centre = mark if mark >= 0 else 0
        cut = max(0, min(centre - limit // 2, len(text) - limit))
        text = text[cut:cut + limit]
    return text


def _pattern_meta(name: str) -> tuple:
    p = _PATTERN_BY_NAME.get(name)
    if p:
        return p["severity"], p["category"]
    return "high", "secret"


def map_result(r: ThResult, manifest: dict, *, verify: bool, secret_values=()) -> Optional[dict]:
    """js_recon's finding shape for one TruffleHog result, located by M1."""
    entry = manifest.get(r.file)
    if not entry:
        return None
    url, content = entry["url"], entry["content"]
    raw = key_of(r.detector, r.raw)
    name = mapped_name(r.detector, raw)
    severity, category = _pattern_meta(name)
    public = name in patterns.PUBLIC_CLIENT_KEY_NAMES
    where = locate(raw, content)
    if where:
        line, start, end = where
        context = masked_context(content, start, end, {raw, *r.mask_values, *secret_values})
        raw_context = masked_context(content, start, end, ())
    else:
        line, context, raw_context = r.line, "", ""
    return {
        "id": patterns._make_finding_id(name, raw, url),
        "name": name,
        "matched_text": raw,
        "secret_value": raw,
        "paired_secret": r.paired or None,
        "raw_context": raw_context,
        "redacted_value": patterns.redact(raw),
        "severity": "info" if public else severity,
        "public_client_key": public,
        "confidence": "high" if r.verified else "medium",
        "category": category,
        "line_number": line,
        "source_url": url,
        "validator_ref": None,
        "detection_method": "trufflehog",
        "context": context,
        "alternate_names": [],
        "validation": validation_of(r, verify=verify),
        "_th_class": result_class(r),
        "_th_detector": r.detector,
    }


# --------------------------------------------------------------------------- merge

@dataclass
class MergeStats:
    results: int = 0
    merged: int = 0
    new: int = 0
    validated: int = 0
    filtered: int = 0
    verify_errors: int = 0


def merge(regex_secrets: list, th_results: list, manifest: dict, *, verify: bool,
          keep: Optional[set] = None) -> tuple:
    """`(secrets, MergeStats)`: js_recon's secrets with TruffleHog's merged in.

    A result MATCHES a regex finding of the same file whose matched text holds
    its key: that finding keeps its id, name, severity and matched text, and
    gains `TruffleHog:<Detector>` and `validation.trufflehog`. Any other result
    is a new finding. `keep` (the result filter) drops only new findings, and
    only when something was verified; a match always enriches.
    """
    stats = MergeStats(results=len(th_results))
    by_url: dict = {}
    for s in regex_secrets:
        by_url.setdefault(s.get("source_url") or "", []).append(s)

    secret_values_by_url = {u: {s.get("matched_text") for s in ss if s.get("matched_text")}
                            for u, ss in by_url.items()}
    for r in th_results:
        entry = manifest.get(r.file)
        if entry:
            secret_values_by_url.setdefault(entry["url"], set()).update(
                {key_of(r.detector, r.raw), *r.mask_values})

    seen: set = set()
    new: list = []
    # One AWS ID is paired with every 40-character candidate in its chunk: of
    # the duplicates the verified one, then one without an error, is kept.
    for r in sorted(th_results, key=lambda x: (x.file, x.detector, x.raw, not x.verified, bool(x.error))):
        entry = manifest.get(r.file)
        if not entry:
            continue
        url = entry["url"]
        raw = key_of(r.detector, r.raw)
        name = mapped_name(r.detector, raw)
        dedup = (name, raw, url)
        if dedup in seen:
            continue
        seen.add(dedup)
        if r.error:
            stats.verify_errors += 1
        if r.verified:
            stats.validated += 1
        matches = [s for s in by_url.get(url, ()) if raw in (s.get("matched_text") or "")]
        if matches:
            stats.merged += 1
            info = validation_of(r, verify=verify)["trufflehog"]
            for s in matches:
                alt = s.setdefault("alternate_names", [])
                label = f"TruffleHog:{r.detector}"
                if label not in alt:
                    alt.append(label)
                if r.paired and not s.get("paired_secret"):
                    s["paired_secret"] = r.paired
                s.setdefault("validation", {})["trufflehog"] = _stronger(
                    (s.get("validation") or {}).get("trufflehog"), info)
            continue
        finding = map_result(r, manifest, verify=verify,
                             secret_values=secret_values_by_url.get(url, ()))
        if not finding:
            continue
        if verify and keep is not None and finding["_th_class"] not in keep:
            stats.filtered += 1
            continue
        new.append(finding)
    stats.new = len(new)
    for f in new:
        f.pop("_th_class", None)
        f.pop("_th_detector", None)
    return list(regex_secrets) + new, stats


def _stronger(old: Optional[dict], new: dict) -> dict:
    """Two results for one key (an AWS ID paired with two candidate secrets):
    a verified one wins, then one without an error."""
    if not old:
        return new
    rank = lambda i: (bool(i.get("verified")), not i.get("error_class"))  # noqa: E731
    return new if rank(new) > rank(old) else old


# --------------------------------------------------------------------------- run

@dataclass
class ThRun:
    status: str  # ran | skipped | failed | timed_out | stopped | truncated
    reason: str = ""
    network: str = "none"
    results: list = field(default_factory=list)
    manifest: dict = field(default_factory=dict)
    bad_lines: int = 0
    staged: int = 0
    staged_urls: list = field(default_factory=list)
    duration_s: float = 0.0
    stderr_tail: list = field(default_factory=list)


def run(js_files: list, *, verify: bool, concurrency: int, validation_timeout: int,
        budget_s: float, image: str = TRUFFLEHOG_IMAGE, root: str = STAGE_ROOT) -> ThRun:
    """Stage the files, run the sidecar, parse its output. Never raises; the
    stage dir is gone when this returns, on every path."""
    started = time.monotonic()
    out = _run(js_files, verify=verify, concurrency=concurrency,
               validation_timeout=validation_timeout, budget_s=budget_s, image=image, root=root)
    out.duration_s = round(time.monotonic() - started, 1)
    return out


def _run(js_files, *, verify, concurrency, validation_timeout, budget_s, image, root) -> ThRun:
    network = VERIFY_NETWORK if verify else "none"
    if _stop_requested():
        return ThRun("stopped", "run stopping", network)
    if not image_available(image):
        if _stop_requested():
            return ThRun("stopped", "run stopping", network)
        return ThRun("skipped", "image_missing", network)
    staging = None
    try:
        staging = stage_files(js_files, run_id(), root=root)
        out = ThRun("ran", network=network, manifest=staging.manifest, staged=len(staging.manifest),
                    staged_urls=[e["url"] for e in staging.manifest.values()])
        if not staging.manifest:
            out.status, out.reason = "skipped", "no_input"
            return out
        if verify and not ensure_verify_network():
            out.status, out.reason = "failed", "verify_network_unavailable"
            return out
        name = container_name(run_id())
        argv = build_argv(staging.dir, verify=verify, concurrency=concurrency,
                          validation_timeout=validation_timeout, name=name, image=image)
        side = run_sidecar(argv, name=name, budget_s=budget_s)
        out.status, out.reason, out.stderr_tail = side.status, side.reason, side.stderr_tail
        if side.stdout:
            out.results, out.bad_lines = parse_ndjson(side.stdout)
        return out
    except Exception as exc:  # noqa: BLE001 - TruffleHog never fails js_recon
        if _is_launch_refused(exc) or _stop_requested():
            return ThRun("stopped", "run stopping", network)
        return ThRun("failed", type(exc).__name__, network)
    finally:
        if staging is not None:
            remove_stage(staging.dir)
