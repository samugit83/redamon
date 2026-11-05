"""Jev questions for the recon hooks.

Two kinds. The four engine switches (FFuf extensions, Nuclei tags, WAF, takeover)
map their answers back to the existing `/llm/*` response shapes. The per-item
hooks (FFuf base paths, page type, tool health, crawl-seed order, serialized
blobs) have no LLM twin and return shapes of their own, which recon validates.

Containment here is code-enforced floors and closed answer sets, not prompt
wording: a Jev answer can only rank, tune or annotate, never drop coverage
below the static fallback. Target-derived bytes go into the `state` as data
(wrapped), never concatenated into an instruction; a per-item hook names an item
by its index, never by quoting it.

Question wording is versioned with the pinned model: a prompt change is a
deliberate edit alongside JEV_MODEL.
"""
from __future__ import annotations

import json
import re
from typing import Any

from prompt_safety import wrap_untrusted
import jev_client
from jev_client import JEV_MODEL, JevError

#: At most this many questions per request. The live API answers 1000 in under
#: a second (checked 2026-10-01), but a smaller cap keeps one scan well under
#: the per-account rate and bounds the request size; larger sets split.
JEV_MAX_QUESTIONS_PER_CALL = 200

#: Caps on target-derived text placed in the state. TypeSafe takes about 64k tokens
#: per request, and the endpoint accepts the same unbounded bodies as /llm/*, so one
#: oversized header or body would fail the call. Clipping keeps the verdict
#: available, and the tail of a header dump or body sample is the least useful part.
_HEADERS_CHARS = 16_000
_SAMPLE_CHARS = 8_000
_FINGERPRINT_CHARS = 8_000
_SHORT_CHARS = 2_000
#: More candidate tags than any real template set has; only bounds a pathological caller.
_MAX_CANDIDATES = 500

#: The only shape of a Nuclei tag recon accepts (its TAG_REGEX). A tag is written into
#: the question wording, so anything else is dropped here instead of becoming instruction
#: text: the endpoint takes whatever list its caller sends.
_TAG_RE = re.compile(r"[a-z0-9-]{2,30}")

#: Noul answers at or above this read as "yes". The recon thresholds (70/100)
#: are calibrated against this, so it moves with the pinned model.
_YES = 0.5


def _clip(value, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


def _noul(instructions: str, *, true: str = "", false: str = "") -> dict:
    q: dict[str, Any] = {"type": "noul", "instructions": instructions}
    if true or false:
        q["criteria"] = {"true": true, "false": false}
    return q


async def _ask(key: jev_client.JevProvider | str, state, questions: dict) -> dict:
    """One or more sequential requests, same state, all-or-nothing.

    Splitting is sequential (never concurrent) so one scan cannot burst the
    per-account rate. If any request fails the whole hook fails: a partial
    answer set would silently narrow coverage.
    """
    names = list(questions)
    answers: dict[str, Any] = {}
    chunks = [{n: questions[n] for n in names[i:i + JEV_MAX_QUESTIONS_PER_CALL]}
              for i in range(0, len(names), JEV_MAX_QUESTIONS_PER_CALL)]
    if isinstance(key, jev_client.JevProvider):
        # Check ALL batches before spending: oversized later state must not buy
        # partial decisions that the hook cannot safely return.
        for chunk in chunks:
            jev_client.validate_request_size(key, state, chunk)
    for chunk in chunks:
        result = await jev_client.system_one(key, JEV_MODEL, state, chunk)
        answers.update(result["answers"])
    return answers


# ---------------------------------------------------------------------------
# FFuf extensions
# ---------------------------------------------------------------------------

#: The fixed catalog Jev ranks over. Jev never invents an extension: it only
#: scores these. Every entry must pass recon's EXT_REGEX (a dot plus 1-8 of
#: a-z0-9), or recon drops it without an error; test_jev_catalog_contract.py
#: holds that line.
FFUF_JEV_CATALOG: tuple[str, ...] = (
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".html", ".htm", ".js",
    ".json", ".xml", ".txt", ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".sql", ".db", ".sqlite", ".log",
    ".conf", ".config", ".ini", ".env", ".yml", ".yaml", ".cfg", ".inc",
    ".cgi", ".pl", ".py", ".rb", ".map",
)

#: Always kept, whatever Jev says: these lead the FFuf static SAFE_FALLBACK, so
#: the Jev engine never discovers fewer backup files than no AI at all.
_FFUF_FLOOR = (".bak", ".old")


async def ffuf_extensions(key: jev_client.JevProvider | str, url: str, headers: dict, max_extensions: int) -> dict:
    """`{"extensions": [...]}` — the same shape as `/llm/ffuf-extensions`."""
    questions = {
        f"ext_{i}": _noul(
            f"Is the file extension `{ext}` likely to find real files on this server, "
            f"given its response headers and URL?")
        for i, ext in enumerate(FFUF_JEV_CATALOG)
    }
    state = {
        "url": wrap_untrusted(_clip(url, _SHORT_CHARS), label="TARGET_URL"),
        "headers": wrap_untrusted(_clip(json.dumps(headers), _HEADERS_CHARS), label="TARGET_HEADERS"),
    }
    answers = await _ask(key, state, questions)

    scored = sorted(
        ((answers[f"ext_{i}"]["noul"], ext) for i, ext in enumerate(FFUF_JEV_CATALOG)
         if answers[f"ext_{i}"]["noul"] >= _YES),
        reverse=True,
    )
    chosen: list[str] = []
    for ext in _FFUF_FLOOR:
        if ext not in chosen:
            chosen.append(ext)
    for _, ext in scored:
        if ext not in chosen:
            chosen.append(ext)
    return {"extensions": chosen[:max_extensions]}


# ---------------------------------------------------------------------------
# Nuclei tags
# ---------------------------------------------------------------------------

#: Kept whenever present in the candidates, whatever Jev says. The same
#: universal high-impact set the LLM prompt asks for (api.py:707-708), now
#: enforced in code so an injected fingerprint cannot strip them.
_NUCLEI_UNIVERSAL = ("cve", "exposure", "misconfig", "default-login", "kev", "oast", "takeover")


async def nuclei_tags(key: jev_client.JevProvider | str, technologies: list, servers: list,
                      candidates: list, max_tags: int) -> dict:
    """`{"tags": [...]}` — the same shape as `/llm/nuclei-tags`.

    Every candidate is a plain tag string the tool chose, so the question text
    is tool-controlled; the fingerprint is the only target-derived input and
    goes into the state.
    """
    all_candidates = [c for c in candidates if isinstance(c, str) and _TAG_RE.fullmatch(c)]
    # The floor is computed over the FULL list; only the questions are bounded.
    universal = {t for t in _NUCLEI_UNIVERSAL if t in all_candidates}
    valid_candidates = all_candidates[:_MAX_CANDIDATES]
    questions = {
        f"tag_{i}": _noul(
            f"Should the Nuclei template tag `{tag}` be included for a scan of a host "
            f"with the detected technology stack?")
        for i, tag in enumerate(valid_candidates)
    }
    state = {
        "technologies": wrap_untrusted(_clip(json.dumps(technologies), _FINGERPRINT_CHARS), label="TARGET_FINGERPRINT"),
        "servers": wrap_untrusted(_clip(json.dumps(servers), _FINGERPRINT_CHARS), label="TARGET_FINGERPRINT"),
    }
    answers = await _ask(key, state, questions) if questions else {}

    score = {tag: answers[f"tag_{i}"]["noul"] for i, tag in enumerate(valid_candidates)}
    # The floor is ordered by Jev's own ranking, so a max_tags below the number of
    # universal tags present drops the least relevant ones for THIS target, not
    # whichever sort last alphabetically.
    chosen = sorted(universal, key=lambda t: (-score.get(t, 0.0), t))
    ranked = sorted((t for t, v in score.items() if v >= _YES and t not in universal),
                    key=lambda t: (-score[t], t))
    return {"tags": (chosen + ranked)[:max_tags]}


# ---------------------------------------------------------------------------
# WAF classify
# ---------------------------------------------------------------------------

#: The 14 vendors the LLM prompt offers (api.py WAF prompt). Jev picks one when
#: it decides a WAF is present; the recon WAF_TYPE_REGEX accepts all of them.
_WAF_VENDORS = (
    "cloudflare", "akamai", "aws_waf", "imperva", "sucuri", "fastly",
    "azure_frontdoor", "cloudfront", "modsecurity", "f5", "fortinet",
    "barracuda", "stackpath", "custom",
)


async def waf_classify(key: jev_client.JevProvider | str, url: str, status_code: int, headers: dict,
                       body_sample: str, response_time_ms: int) -> dict:
    """The `/llm/waf-classify` shape: waf_detected, waf_type, confidence, reasoning, source."""
    questions = {
        "edge": _noul("A WAF or CDN edge produced this HTTP response."),
        "vendor": {
            "type": "choice",
            "instructions": "If a WAF or CDN edge produced this response, which vendor is it?",
            "criteria": {v: None for v in _WAF_VENDORS},
        },
    }
    state = {
        "url": wrap_untrusted(_clip(url, _SHORT_CHARS), label="TARGET_URL"),
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "headers": wrap_untrusted(_clip(json.dumps(headers), _HEADERS_CHARS), label="TARGET_HEADERS"),
        "body_sample": wrap_untrusted(_clip(body_sample, _SAMPLE_CHARS), label="TARGET_BODY"),
    }
    answers = await _ask(key, state, questions)

    noul = answers["edge"]["noul"]
    detected = noul >= _YES
    return {
        "waf_detected": detected,
        "waf_type": answers["vendor"]["choice"] if detected else None,
        "confidence": round(noul * 100),
        "reasoning": "",
        "source": "jev_classifier",
    }


# ---------------------------------------------------------------------------
# Takeover classify
# ---------------------------------------------------------------------------

async def takeover_classify(key: jev_client.JevProvider | str, hostname: str, expected_provider: str,
                            status_code: int, headers: dict, response_sample: str) -> dict:
    """The `/llm/takeover-classify` shape: is_waf_block, confidence, reason, source."""
    questions = {
        "waf_block": _noul(
            "This response is a WAF or edge block page, not the unclaimed-site page of the "
            "claimed third-party provider.",
            true="A WAF/edge block page (likely a fingerprint collision)",
            false="A genuine provider unclaimed-site page"),
    }
    state = {
        "hostname": wrap_untrusted(_clip(hostname, _SHORT_CHARS), label="TARGET_HOST"),
        "claimed_provider": _clip(expected_provider, _SHORT_CHARS),
        "status_code": status_code,
        "headers": wrap_untrusted(_clip(json.dumps(headers), _HEADERS_CHARS), label="TARGET_HEADERS"),
        "response_sample": wrap_untrusted(_clip(response_sample, _SAMPLE_CHARS), label="TARGET_BODY"),
    }
    answers = await _ask(key, state, questions)

    noul = answers["waf_block"]["noul"]
    is_block = noul >= _YES
    # Confidence in the verdict actually taken, so a 0.5 reads as low either way.
    confidence = round(max(noul, 1 - noul) * 100)
    return {
        "is_waf_block": is_block,
        "confidence": confidence,
        "reason": "",
        "source": "jev_classifier",
    }


# ---------------------------------------------------------------------------
# Per-item hooks: the items ARE the state
# ---------------------------------------------------------------------------

#: Item state per request. TypeSafe takes about 64k tokens per request; at about
#: four characters a token this leaves room for the questions and wrap markers.
_ITEM_STATE_CHARS = 120_000


async def _ask_items(key: jev_client.JevProvider | str, shared: dict, items: dict, questions: dict) -> dict:
    """Ask per-item questions, sending each request only its own items.

    `_ask` re-sends one state with every chunk, which is right for one header set
    and many questions, and wrong here: a scan's worth of items would exceed the
    request limit. `items` maps an item id to its state; `questions` maps the same
    id to that item's questions. A chunk closes at JEV_MAX_QUESTIONS_PER_CALL
    questions or _ITEM_STATE_CHARS of item state, whichever comes first (an item
    larger than the budget goes alone; the per-field clips bound it).
    Sequential and all-or-nothing, like `_ask`.
    """
    answers: dict[str, Any] = {}
    chunk_items: dict[str, Any] = {}
    chunk_questions: dict[str, Any] = {}
    chunk_chars = 0

    requests: list[tuple[dict, dict]] = []

    def flush():
        requests.append(({**shared, "items": chunk_items}, chunk_questions))

    for item_id, item_state in items.items():
        item_questions = questions[item_id]
        size = len(json.dumps(item_state))
        if chunk_questions and (
                len(chunk_questions) + len(item_questions) > JEV_MAX_QUESTIONS_PER_CALL
                or chunk_chars + size > _ITEM_STATE_CHARS):
            flush()
            chunk_items, chunk_questions, chunk_chars = {}, {}, 0
        chunk_items[item_id] = item_state
        chunk_questions.update(item_questions)
        chunk_chars += size
    if chunk_questions:
        flush()
    if isinstance(key, jev_client.JevProvider):
        for state, chunk in requests:
            jev_client.validate_request_size(key, state, chunk)
    for state, chunk in requests:
        result = await jev_client.system_one(key, JEV_MODEL, state, chunk)
        answers.update(result["answers"])
    return answers


# ---------------------------------------------------------------------------
# FFuf smart-fuzz base paths
# ---------------------------------------------------------------------------

#: Candidates per request body. A large crawl yields thousands of directories;
#: recon asks about at most this many and fills any slot left with its random pick.
FFUF_BASE_PATHS_MAX = 400
FFUF_BASE_PATH_CHARS = 200


async def ffuf_base_paths(key: jev_client.JevProvider | str, candidates: list, cap: int) -> dict:
    """Rank FFuf smart-fuzz base paths.

    Returns `{"ranked", "scores", "model"}`: `scores[i]` is the noul for
    `candidates[i]`, and `ranked` is at most `cap` candidates ordered by
    (-noul, path), so ties are deterministic. Every ranked string is one of the
    candidates; nothing is invented and nothing below the cap is dropped that the
    random pick would have kept, because the cap cuts the same number either way.

    The directory names come from the target's own links, so each one is state
    data named by index (`path_3`), never quoted in a question.
    """
    paths = list(candidates)[:FFUF_BASE_PATHS_MAX]
    items = {f"path_{i}": wrap_untrusted(_clip(p, FFUF_BASE_PATH_CHARS), label="TARGET_PATH")
             for i, p in enumerate(paths)}
    questions = {
        f"path_{i}": {f"path_{i}": _noul(
            f"Is the directory in item path_{i} likely to hold sensitive, administrative or "
            f"application content, rather than static assets?")}
        for i in range(len(paths))
    }
    answers = await _ask_items(key, {}, items, questions) if paths else {}

    scores = [answers[f"path_{i}"]["noul"] for i in range(len(paths))]
    order = sorted(range(len(paths)), key=lambda i: (-scores[i], paths[i]))
    return {
        "ranked": [paths[i] for i in order[:max(cap, 0)]],
        "scores": scores,
        "model": JEV_MODEL,
    }


# ---------------------------------------------------------------------------
# Page type
# ---------------------------------------------------------------------------

#: The closed label set. "app" is not asked: it is what a page is when no other
#: class reaches PAGE_CLASS_THRESHOLD, so an unsure answer fails toward scanning.
PAGE_CLASSES = ("login_only", "parked", "default", "placeholder", "error")

#: A class wins only at or above this noul. Higher than _YES because a label says
#: what a page IS; a 0.55 "maybe parked" is left as an app.
PAGE_CLASS_THRESHOLD = 0.70

_PAGE_QUESTIONS = {
    "login_only": ("only a login or single-sign-on wall, with no application content "
                   "reachable without credentials"),
    "parked": "a domain-parking or domain-for-sale page",
    "default": ("a web server's or vendor's default landing page left in place, such as a "
                "fresh nginx, Apache or IIS install page"),
    "placeholder": ("a placeholder such as a 'coming soon' or empty holding page, with no "
                    "application behind it"),
    "error": ("an error page rather than real content: a soft 404, an access-denied wall, "
              "or an error page returned with a 200 status"),
}

_PAGE_BODY_CHARS = 4_000
_PAGE_HEADERS_CHARS = 2_000
_PAGE_URL_CHARS = 500
_PAGE_FIELD_CHARS = 300


def _page_state(page: dict) -> dict:
    """One page's state: our own numbers plain, every target-derived string wrapped."""
    def wrapped(field, limit, label):
        return wrap_untrusted(_clip(page.get(field), limit), label=label)

    return {
        "status_code": page.get("status_code", 0),
        "content_length": page.get("content_length", 0),
        "word_count": page.get("word_count", 0),
        "line_count": page.get("line_count", 0),
        "response_time_ms": page.get("response_time_ms", 0),
        "is_cdn": bool(page.get("is_cdn", False)),
        "url": wrapped("url", _PAGE_URL_CHARS, "TARGET_URL"),
        "host": wrapped("host", _PAGE_FIELD_CHARS, "TARGET_HOST"),
        "cname": wrapped("cname", _PAGE_FIELD_CHARS, "TARGET_DNS"),
        "title": wrapped("title", _PAGE_FIELD_CHARS, "TARGET_TITLE"),
        "server": wrapped("server", _PAGE_FIELD_CHARS, "TARGET_SERVER"),
        "headers": wrap_untrusted(_clip(json.dumps(page.get("headers") or {}), _PAGE_HEADERS_CHARS),
                                  label="TARGET_HEADERS"),
        "body": wrapped("body", _PAGE_BODY_CHARS, "TARGET_BODY"),
    }


async def page_type(key: jev_client.JevProvider | str, pages: list) -> dict:
    """Label each page: `{"labels": [{"page_class", "confidence"}], "model"}`.

    One request per page, sequential and all-or-nothing, with five nouls about
    "the page in the state". Not batched by index like the other per-item hooks:
    measured live on jev-1.13.0, a login page in a request with other pages scored
    0.55 for login_only and 0.92 alone. A page's state has a dozen fields, and the
    answers blur across items.

    A page takes the class with the highest noul at or above PAGE_CLASS_THRESHOLD
    (ties go to the earlier class), else "app". Confidence is in the label taken:
    the winning noul, or for "app" one minus the highest noul, so a 0.65 "maybe
    parked" reads as a weak app.
    """
    questions = {cls: _noul(f"The page in the state is {_PAGE_QUESTIONS[cls]}.") for cls in PAGE_CLASSES}
    labels = []
    for page in pages:
        answers = await _ask(key, {"page": _page_state(page)}, questions)
        nouls = {cls: answers[cls]["noul"] for cls in PAGE_CLASSES}
        best = max(PAGE_CLASSES, key=lambda c: (nouls[c], -PAGE_CLASSES.index(c)))
        if nouls[best] >= PAGE_CLASS_THRESHOLD:
            labels.append({"page_class": best, "confidence": round(nouls[best] * 100)})
        else:
            labels.append({"page_class": "app", "confidence": round((1 - nouls[best]) * 100)})
    return {"labels": labels, "model": JEV_MODEL}


# ---------------------------------------------------------------------------
# Tool health
# ---------------------------------------------------------------------------

#: The tools whose empty result recon may ask about. Trusted: recon names the tool
#: it ran, from this list; the endpoint refuses any other value.
TOOL_HEALTH_TOOLS = ("katana", "hakrawler", "gau", "paramspider", "kiterunner",
                     "ffuf", "arjun", "jsluice")
_STDERR_CHARS = 4_000


async def tool_health(key: jev_client.JevProvider | str, tool: str, return_code: int, elapsed_s: float,
                      seed_count: int, stderr: str) -> dict:
    """Is an empty result's error output transient? `{"transient", "confidence", "model"}`.

    stderr is not trusted: crawlers echo target URLs into it. Recon redacts header
    values before sending; here it is clipped and wrapped like any target bytes.
    """
    questions = {
        "transient": _noul(
            "The tool's error output in the state describes a transient failure (a timeout, "
            "a network or rate-limit error, a crashed or killed container) rather than a "
            "permanent one (a bad option, a missing file, an invalid or refused target).",
            true="A transient failure: running the tool again could succeed",
            false="A permanent failure, or no failure at all"),
    }
    state = {
        "tool": tool,
        "return_code": return_code,
        "elapsed_s": elapsed_s,
        "seed_count": seed_count,
        "stderr": wrap_untrusted(_clip(stderr, _STDERR_CHARS), label="TOOL_STDERR"),
    }
    answers = await _ask(key, state, questions)
    noul = answers["transient"]["noul"]
    return {
        "transient": noul >= _YES,
        "confidence": round(max(noul, 1 - noul) * 100),
        "model": JEV_MODEL,
    }


# ---------------------------------------------------------------------------
# Crawl-seed order
# ---------------------------------------------------------------------------

#: Hosts per request body; recon scores at most this many per scan and keeps the
#: rest in alphabetical order after the scored ones.
CRAWL_SEED_HOSTS_MAX = 400


def _host_state(host: dict) -> dict:
    return {
        "status_code": host.get("status_code", 0),
        "content_length": host.get("content_length", 0),
        "word_count": host.get("word_count", 0),
        "line_count": host.get("line_count", 0),
        "url_count": host.get("url_count", 0),
        "hostname": wrap_untrusted(_clip(host.get("hostname"), _PAGE_FIELD_CHARS), label="TARGET_HOST"),
        "title": wrap_untrusted(_clip(host.get("title"), _PAGE_FIELD_CHARS), label="TARGET_TITLE"),
        "server": wrap_untrusted(_clip(host.get("server"), _PAGE_FIELD_CHARS), label="TARGET_SERVER"),
    }


async def crawl_seed_order(key: jev_client.JevProvider | str, hosts: list) -> dict:
    """Score each host for crawl order: `{"scores": [noul per host], "model"}`.

    Ordering only: recon sorts by (-score, hostname) and never drops a host, so
    the answer changes which hosts a crawler reaches first under its URL cap,
    never which hosts it may crawl.
    """
    hosts = list(hosts)[:CRAWL_SEED_HOSTS_MAX]
    items = {f"host_{i}": _host_state(h) for i, h in enumerate(hosts)}
    questions = {
        f"host_{i}": {f"host_{i}": _noul(
            f"Is the host in item host_{i} likely to have a rich web application surface "
            f"(many pages, forms, APIs or an admin area) rather than a thin or static site?")}
        for i in range(len(hosts))
    }
    answers = await _ask_items(key, {}, items, questions) if hosts else {}
    return {"scores": [answers[f"host_{i}"]["noul"] for i in range(len(hosts))],
            "model": JEV_MODEL}


# ---------------------------------------------------------------------------
# Serialized-object assessment
# ---------------------------------------------------------------------------

#: The closed format set: recon's deser_format vocabulary
#: (serialized_assess.FORMATS) plus "none", for a blob that is not a serialized
#: object. test_jev_item_contract.py holds the two equal, or recon would
#: reject every answer naming a format it does not know.
SERIALIZED_FORMATS = (
    "native_java", "jackson_json", "fastjson", "xmldecoder", "xstream", "snakeyaml",
    "hessian", "php_serialize", "phar", "python_pickle", "dotnet_binaryformatter",
    "viewstate", "ruby_marshal", "none",
)
SERIALIZED_TRANSPORTS = ("cookie", "header", "param", "body")
SERIALIZED_LAYERS = ("url", "base64", "gzip", "zlib", "hex", "truncated")

#: Tool-controlled wording, so it may sit in the instructions; the blob itself is
#: only ever state data.
_SERIALIZED_FORMAT_GUIDE = (
    "native_java = Java ObjectInputStream binary (AC ED 00 05, base64 rO0AB); "
    "jackson_json = JSON naming a Java class in an @class key (Jackson, json-io, Genson); "
    "fastjson = Alibaba FastJSON naming a type in an @type key; "
    "xmldecoder = java.beans.XMLDecoder XML (<java version=, <object class=); "
    "xstream = XStream XML whose elements are fully-qualified Java classes; "
    "snakeyaml = YAML with a !! Java type tag; "
    "hessian = Hessian or Burlap binary RPC serialization; "
    "php_serialize = PHP serialize() output (O:<n>:\"Class\" or a:<n>:{); "
    "phar = a PHP PHAR archive or a phar:// reference; "
    "python_pickle = a Python pickle opcode stream; "
    "dotnet_binaryformatter = a .NET BinaryFormatter stream (00 01 00 00 00 FF FF FF FF); "
    "viewstate = an ASP.NET __VIEWSTATE (LosFormatter / ObjectStateFormatter); "
    "ruby_marshal = Ruby Marshal (04 08); "
    "none = not a serialized object at all (an opaque token, an id or plain data)"
)

_BLOB_SNIPPET_CHARS = 200

#: Where the scanner saw the blob, keyed by recon's transport, so the reachability
#: answer can tell a value the client sends from one it only receives.
_SERIALIZED_OBSERVED_IN = {
    "cookie": "a Set-Cookie value in a response, which the client sends back on later requests",
    "header": "a response header, which a client does not normally send back",
    "param": "a request parameter or form field, which the client sends to the server",
    "body": "a request body field, which the client sends to the server",
}


def _blob_state(blob: dict) -> dict:
    """One blob's state: recon's closed values plain, every target-derived string wrapped.

    Evidence only. Recon never sends the format its signatures matched, nor their
    label for it, so the format answer is Jev's own reading of the blob.
    """
    transport = blob.get("transport")
    transport = transport if transport in SERIALIZED_TRANSPORTS else ""
    layers = blob.get("encoding_layers") if isinstance(blob.get("encoding_layers"), list) else []
    return {
        "transport": transport,
        "observed_in": _SERIALIZED_OBSERVED_IN.get(transport, "unknown"),
        "encoding_layers": [x for x in layers if x in SERIALIZED_LAYERS],
        "location": wrap_untrusted(_clip(blob.get("location"), _PAGE_FIELD_CHARS), label="TARGET_PARAM"),
        "snippet": wrap_untrusted(_clip(blob.get("snippet"), _BLOB_SNIPPET_CHARS), label="TARGET_BLOB"),
    }


async def serialized_classify(key: jev_client.JevProvider | str, blobs: list) -> dict:
    """Assess each blob: `{"labels": [{"format", "format_confidence", "exploitability"}], "model"}`.

    One request per blob, sequential and all-or-nothing, like `page_type`:
    measured live on jev-1.13.0, per-item answers blur when several items share
    one state. Two questions per blob: which format it is (a choice over the
    closed set, carrying its own confidence) and whether it is likely an
    attacker-reachable deserialization sink (a noul). Recon only annotates and
    ranks with these; it never drops a candidate or rewrites its format.
    """
    questions = {
        "format": {
            "type": "choice",
            "instructions": ("Which serialization format is the blob in the state? "
                             + _SERIALIZED_FORMAT_GUIDE + "."),
            "criteria": {fmt: None for fmt in SERIALIZED_FORMATS},
        },
        "exploitable": _noul(
            "The serialized object in the state is likely to reach a server-side "
            "deserializer from input an attacker controls. The state's observed_in says "
            "where it was seen: a value the client sends to the server (a request "
            "parameter, a form field, a cookie it sends back) can be tampered with, while "
            "a response header the client never sends back rarely reaches a deserializer. "
            "Its format must also be able to carry attacker-chosen types or objects, which "
            "a blob that is not a serialized object at all cannot.",
            true="An attacker-reachable deserialization sink",
            false="Not attacker-reachable, or not deserialized on the server"),
    }
    labels = []
    for blob in blobs:
        answers = await _ask(key, {"blob": _blob_state(blob)}, questions)
        labels.append({
            "format": answers["format"]["choice"],
            "format_confidence": round(answers["format"]["confidence"] * 100),
            "exploitability": round(answers["exploitable"]["noul"] * 100),
        })
    return {"labels": labels, "model": JEV_MODEL}


# ---------------------------------------------------------------------------
# Route exposure: route privacy rank
# ---------------------------------------------------------------------------

#: Routes per request body; recon asks about its highest prior scores first.
ROUTE_PRIVACY_MAX = 400
ROUTE_PATH_CHARS = 200


def _route_state(route: dict) -> dict:
    return {
        "path": wrap_untrusted(_clip(route.get("path"), ROUTE_PATH_CHARS), label="TARGET_PATH"),
        "method": route.get("method", "GET"),
        "category": route.get("category", "other"),
        "openapi_secured": bool(route.get("openapi_secured")),
        "declared_only": bool(route.get("declared_only")),
        "js_only": bool(route.get("js_only")),
        "host_internal": bool(route.get("host_internal")),
    }


async def route_privacy_rank(key: jev_client.JevProvider | str, routes: list) -> dict:
    """Score each route for privacy: `{"scores": [noul per route], "model"}`.

    Ranking only: recon spends its request budget floor first, so the answer can
    reorder what fills the rest, never drop a floor route or add one. The flags
    are recon's own closed values; the path is target text, named by index.
    """
    routes = list(routes)[:ROUTE_PRIVACY_MAX]
    items = {f"route_{i}": _route_state(r) for i, r in enumerate(routes)}
    questions = {
        f"route_{i}": {f"route_{i}": _noul(
            f"Is the route in item route_{i} meant only for logged-in, internal or administrative "
            f"callers, rather than for the public? openapi_secured means the site's own API "
            f"description requires credentials for it; declared_only means only that description "
            f"names it; js_only means only the site's JavaScript names it; host_internal means the "
            f"host name itself reads as internal.",
            true="Meant for logged-in, internal or administrative callers",
            false="Public content or a public API")}
        for i in range(len(routes))
    }
    answers = await _ask_items(key, {}, items, questions) if routes else {}
    return {"scores": [answers[f"route_{i}"]["noul"] for i in range(len(routes))],
            "model": JEV_MODEL}


# ---------------------------------------------------------------------------
# Route exposure: lead assessment
# ---------------------------------------------------------------------------

#: recon's KINDS (route_exposure_assess.py); test_jev_item_contract.py holds them
#: equal, or recon would reject every label naming a kind it does not know.
ROUTE_EXPOSURE_KINDS = ("internal_api", "debug_management", "admin_function", "data_export",
                        "old_version", "uploaded_content", "public_content")

_ROUTE_KIND_GUIDE = (
    "internal_api = an API for the application's own back office or other services, not its "
    "public clients; debug_management = a debugging, monitoring or management interface "
    "(health, metrics, environment, heap or thread dumps, a debug console); "
    "admin_function = an administrative page or API; data_export = a bulk export, report or "
    "download of records; old_version = an older version of an API or page left reachable; "
    "uploaded_content = a file a user uploaded; public_content = content meant for anyone"
)

_ROUTE_KEY_CHARS = 4_000


def _candidate_state(candidate: dict) -> dict:
    """One lead's evidence: recon's closed values plain, target-derived text wrapped."""
    return {
        "path": wrap_untrusted(_clip(candidate.get("path"), ROUTE_PATH_CHARS), label="TARGET_PATH"),
        "method": candidate.get("method", "GET"),
        "anon_status": candidate.get("anon_status", 0),
        "authed_status": candidate.get("authed_status"),
        "content_class": candidate.get("content_class", "other"),
        "size_bucket": candidate.get("size_bucket", "<1k"),
        "bodies_match": candidate.get("bodies_match"),
        "key_paths": wrap_untrusted(_clip(json.dumps(candidate.get("key_paths") or []), _ROUTE_KEY_CHARS),
                                    label="TARGET_KEYS"),
        "max_array_len": candidate.get("max_array_len", 0),
        "det_signals": list(candidate.get("det_signals") or []),
        "auth_expected_by": list(candidate.get("auth_expected_by") or []),
        "generated_by": candidate.get("generated_by", "found"),
    }


async def route_exposure_assess(key: jev_client.JevProvider | str, candidates: list) -> dict:
    """Assess each lead: `{"labels": [{"kind", "kind_confidence", "sensitivity"}], "model"}`.

    One request per lead, sequential and all-or-nothing, like `serialized_classify`:
    rich items blur when several share one state. Two questions per lead: which kind
    of route it is (a choice over the closed set, with its own confidence) and
    whether what it returns without credentials is sensitive (a noul). Recon only
    orders and annotates with these; it never drops a lead or rewrites its class.
    """
    questions = {
        "kind": {
            "type": "choice",
            "instructions": ("Which kind of route is the one in the state? " + _ROUTE_KIND_GUIDE + "."),
            "criteria": {kind: None for kind in ROUTE_EXPOSURE_KINDS},
        },
        "sensitive": _noul(
            "What the route in the state returns to a caller who sent no credentials is "
            "sensitive: personal data about people other than the caller, credentials or keys, "
            "internal records, or administrative data. anon_status is the status it answered "
            "without credentials and authed_status the status with them; bodies_match says "
            "whether both answers were the same; key_paths are the names of the fields in the "
            "answer (never their values); det_signals are what a pattern scan found in it.",
            true="Sensitive data reachable without credentials",
            false="Public or harmless content"),
    }
    labels = []
    for candidate in candidates:
        answers = await _ask(key, {"route": _candidate_state(candidate)}, questions)
        labels.append({
            "kind": answers["kind"]["choice"],
            "kind_confidence": round(answers["kind"]["confidence"] * 100),
            "sensitivity": round(answers["sensitive"]["noul"] * 100),
        })
    return {"labels": labels, "model": JEV_MODEL}


__all__ = [
    "JevError", "JEV_MAX_QUESTIONS_PER_CALL", "FFUF_JEV_CATALOG",
    "ffuf_extensions", "nuclei_tags", "waf_classify", "takeover_classify",
    "FFUF_BASE_PATHS_MAX", "PAGE_CLASSES", "TOOL_HEALTH_TOOLS", "CRAWL_SEED_HOSTS_MAX",
    "SERIALIZED_FORMATS", "SERIALIZED_TRANSPORTS", "SERIALIZED_LAYERS",
    "ffuf_base_paths", "page_type", "tool_health", "crawl_seed_order", "serialized_classify",
    "ROUTE_PRIVACY_MAX", "ROUTE_EXPOSURE_KINDS", "route_privacy_rank", "route_exposure_assess",
]
