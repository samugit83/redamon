"""
RedAmon - ZAP Ajax Spider Helpers for Resource Enumeration
==========================================================
Browser-driven resource discovery using OWASP ZAP's Ajax Spider.
"""

from __future__ import annotations

import html
import importlib.util
import os
import re
import shutil
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.parse import parse_qs, urlparse

from recon.helpers.docker_helpers import pull_image_or_use_local


SOURCE_NAME = "zap_ajax_spider"
ZAP_CONTEXT_NAME = "redamon-zap-ajax-context"
ZAP_ENVELOPE_TOOL = "zap_ajax"
_URL_RE = re.compile(r"https?://[^\s\"'<>,]+", re.IGNORECASE)
_DEBUG_ENV = "REDAMON_ZAP_AJAX_DEBUG"

# A ZAP Ajax container is a JVM plus a headless Firefox sharing one cgroup.
# Firefox's footprint does NOT scale with the container, so the heap cannot be a
# fraction of it: at 50% of a 2 GiB container the pair measured 1.87 GiB live
# (java 1.05 GiB + the firefox-esr and Isolated Web Content children 0.82 GiB),
# which is 93% of the ceiling, and the kernel SIGKILLed the JVM on every crawl.
# Reserve what Firefox and the JVM's non-heap memory actually cost, then give
# the JVM whatever is left.
_ZAP_BROWSER_RESERVE_MB = 1200   # firefox-esr + content processes, measured 0.82 GiB with room to grow
_ZAP_JVM_OVERHEAD_MB = 300       # metaspace, thread stacks, native allocations above -Xmx
_ZAP_SAFETY_FRACTION = 0.9       # never plan to use the whole cgroup: page cache needs some
_ZAP_HEAP_MIN_MB = 512
_ZAP_HEAP_MAX_MB = 3072
_DEFAULT_ZAP_CONTAINER_BYTES = 2147483648  # 2 GiB, the floor when the governor is unavailable

# A browser crawl of every discovered endpoint never finishes in scan time: each
# seed is a fresh ZAP container for up to maxDuration. Cap the seeds per run so a
# target that produces 100k endpoints still completes; 0 disables the cap.
ZAP_MAX_SEEDS_DEFAULT = 250


def _has_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _bundled_zap_seed_path(url: str) -> bool:
    """True when a URL is a path *stuffed inside another path*.

    A catch-all / reflective host echoes whatever path you ask for, so a
    discovered endpoint like `/static/js/..%5Cu003e%3Cfigcaption%3E` gets
    re-emitted as a whole new "path" by ffuf/katana/ZAP. Seeding those back into
    a browser crawl multiplies one dead seed into thousands: every one of them
    is a distinct string, so neither de-duplication nor the out-of-scope filter
    can collapse them, and each still costs a full per-seed ZAP run. Detected
    as an encoded angle-bracket/quote sequence, which is what a reflected
    payload leaves behind and what a real server path essentially never has.
    """
    lowered = str(url).lower()
    return any(token in lowered for token in (
        "%5cu003e", "%5cu003c", "%3c", "%3e", "\\u003e", "\\u003c",
    ))


def _is_valid_header_parts(raw_name: str, name: str, value: str) -> bool:
    return (
        raw_name == name
        and bool(name)
        and bool(value)
        and not any(char.isspace() for char in name)
        and not _has_control_chars(name)
        and not _has_control_chars(value)
    )


def parse_zap_ajax_header_lines(header_lines: List[str]) -> tuple[List[Dict[str, str]], List[str]]:
    """Parse custom header lines into ZAP replacer-ready header dictionaries."""
    parsed = []
    invalid = []

    for raw_line in header_lines or []:
        line = str(raw_line)
        if not line.strip():
            continue

        if ":" not in line:
            invalid.append(line)
            continue

        raw_name, value = line.split(":", 1)
        name = raw_name.strip()
        value = value.strip()

        if not _is_valid_header_parts(raw_name, name, value):
            invalid.append(line)
            continue

        parsed.append({"name": name, "value": value, "line": line})

    return parsed, invalid


def mask_zap_ajax_header_line(line: str) -> str:
    """Mask a header line for logging without exposing the raw value."""
    parsed, invalid = parse_zap_ajax_header_lines([line])
    if invalid or not parsed:
        return "***"
    return f"{parsed[0]['name']}: ***"


def build_zap_ajax_automation_plan(
    seed_url: str,
    export_file_name: str,
    headers: List[Dict[str, str]] | None = None,
    exclude_patterns: List[str] | None = None,
    max_duration: int = 10,
    max_crawl_depth: int = 5,
    max_crawl_states: int = 0,
    number_of_browsers: int = 1,
    browser_id: str = "firefox-headless",
    event_wait: int = 1000,
    reload_wait: int = 1000,
    click_default_elems: bool = True,
    click_elems_once: bool = True,
    random_inputs: bool = False,
    logout_avoidance: bool = True,
    scope_check: str = "Strict",
) -> str:
    """Build a ZAP automation framework plan for a single Ajax Spider seed."""
    headers = headers or []
    exclude_patterns = exclude_patterns or []
    context_url = _zap_context_url(seed_url)
    container_export_path = f"/zap/wrk/{Path(export_file_name).name}"

    for header in headers:
        name = str(header.get("name", ""))
        value = str(header.get("value", ""))
        if not _is_valid_header_parts(name, name, value):
            raise ValueError("Invalid ZAP Ajax header; name/value must not contain whitespace/control characters")

    def q(value) -> str:
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def b(value: bool) -> str:
        return "true" if bool(value) else "false"

    lines = [
        'name: "redamon-zap-ajax"',
        "env:",
        "  contexts:",
        f"    - name: {q(ZAP_CONTEXT_NAME)}",
        "      urls:",
        f"        - {q(context_url)}",
    ]

    if exclude_patterns:
        lines.extend(["      excludePaths:"])
        for pattern in exclude_patterns:
            lines.append(f"        - {q(pattern)}")

    lines.extend([
        "jobs:",
    ])

    lines.extend([
        '  - type: "replacer"',
        '    name: "redamon-zap-ajax-headers"',
    ])

    if not headers:
        lines.append("    rules: []")
    else:
        lines.append("    rules:")
        for header in headers:
            lines.extend([
                "      - matchType: req_header",
                f"        matchString: {q(header['name'])}",
                f"        replacementString: {q(header['value'])}",
            ])

    lines.extend([
        '  - type: "spiderAjax"',
        '    name: "redamon-zap-ajax-spider"',
        "    parameters:",
        f"      context: {q(ZAP_CONTEXT_NAME)}",
        f"      url: {q(seed_url)}",
        f"      maxDuration: {int(max_duration)}",
        f"      maxCrawlDepth: {int(max_crawl_depth)}",
        f"      maxCrawlStates: {int(max_crawl_states)}",
        f"      numberOfBrowsers: {int(number_of_browsers)}",
        "      inScopeOnly: true",
        f"      browserId: {q(browser_id)}",
        f"      eventWait: {int(event_wait)}",
        f"      reloadWait: {int(reload_wait)}",
        f"      clickDefaultElems: {b(click_default_elems)}",
        f"      clickElemsOnce: {b(click_elems_once)}",
        f"      randomInputs: {b(random_inputs)}",
        f"      logoutAvoidance: {b(logout_avoidance)}",
        f"      scopeCheck: {q(scope_check)}",
    ])

    lines.extend([
        '  - type: "passiveScan-wait"',
        '    name: "redamon-zap-passive-scan"',
        "    parameters:",
        # The crawl budget is the spider's; the pass that drains what it already
        # found needs its own, much smaller, ceiling. Reusing maxDuration here
        # doubled the seed's wall time and made the caller's per-seed timeout
        # fire on a crawl that had actually finished.
        f"      maxDuration: {_zap_passive_minutes(max_duration)}",
        '  - type: "export"',
        '    name: "redamon-zap-ajax-export"',
        "    parameters:",
        f"      context: {q(ZAP_CONTEXT_NAME)}",
        '      type: "url"',
        '      source: "all"',
        f"      fileName: {q(container_export_path)}",
    ])

    return "\n".join(lines) + "\n"


def parse_zap_ajax_export_urls(output_path: str | Path) -> List[str]:
    """Extract HTTP(S) URLs from a ZAP export artifact."""
    path = Path(output_path)
    if not path.exists():
        return []

    seen = set()
    urls = []
    content = html.unescape(path.read_text(encoding="utf-8", errors="ignore"))

    for match in _URL_RE.finditer(content):
        url = match.group(0).rstrip(").];")
        if url not in seen:
            seen.add(url)
            urls.append(url)

    return urls


def filter_zap_ajax_urls(
    urls: Iterable[str],
    allowed_hosts,
    exclude_patterns,
    max_urls,
) -> tuple[List[str], Dict]:
    """Validate, scope-filter, de-duplicate, and cap ZAP Ajax Spider URLs."""
    allowed = {str(host).lower() for host in (allowed_hosts or []) if host}
    exclude_regexes, invalid_excludes = _compile_exclude_patterns(exclude_patterns)
    limit = int(max_urls) if max_urls is not None else 0
    raw_urls = list(urls or [])
    meta = {
        "raw_urls": len(raw_urls),
        "in_scope_urls": 0,
        "duplicates": 0,
        "invalid": 0,
        "out_of_scope": 0,
        "excluded_by_pattern": 0,
        "invalid_exclude_patterns": len(invalid_excludes),
        "max_url_dropped": 0,
        "external_domains": [],
        "dropped_urls": [],
    }

    seen = set()
    filtered = []
    for raw_url in raw_urls:
        url = html.unescape(str(raw_url).strip())
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if parsed.scheme not in {"http", "https"} or not host:
            meta["invalid"] += 1
            meta["dropped_urls"].append({
                "reason": "invalid",
                "source": SOURCE_NAME,
                "url": "***",
            })
            continue

        if allowed and host not in allowed:
            meta["out_of_scope"] += 1
            meta["external_domains"].append({
                "domain": host,
                "source": SOURCE_NAME,
                "url": _safe_url_detail(url),
            })
            meta["dropped_urls"].append({
                "reason": "out_of_scope",
                "source": SOURCE_NAME,
                "domain": host,
                "url": _safe_url_detail(url),
            })
            continue

        if any(pattern.search(url) for pattern in exclude_regexes):
            meta["excluded_by_pattern"] += 1
            meta["dropped_urls"].append({
                "reason": "excluded_by_pattern",
                "source": SOURCE_NAME,
                "url": _safe_url_detail(url),
            })
            continue

        if url in seen:
            meta["duplicates"] += 1
            meta["dropped_urls"].append({
                "reason": "duplicate",
                "source": SOURCE_NAME,
                "url": _safe_url_detail(url),
            })
            continue

        seen.add(url)
        meta["in_scope_urls"] += 1
        if limit > 0 and len(filtered) >= limit:
            meta["max_url_dropped"] += 1
            meta["dropped_urls"].append({
                "reason": "max_urls",
                "source": SOURCE_NAME,
                "url": _safe_url_detail(url),
            })
            continue

        filtered.append(url)

    return filtered, meta


def merge_zap_ajax_into_by_base_url(
    zap_ajax_urls,
    existing_by_base_url,
) -> tuple[Dict, Dict]:
    """Merge ZAP Ajax Spider URLs into the raw resource_enum by_base_url shape."""
    try:
        from .classification import classify_endpoint, classify_parameter, infer_parameter_type
    except ImportError:
        classification_path = Path(__file__).resolve().parent / "classification.py"
        spec = importlib.util.spec_from_file_location("redamon_resource_enum_classification", classification_path)
        if spec is None or spec.loader is None:
            raise
        classification = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(classification)
        classify_endpoint = classification.classify_endpoint
        classify_parameter = classification.classify_parameter
        infer_parameter_type = classification.infer_parameter_type

    stats = {
        "zap_ajax_spider_total": len(zap_ajax_urls or []),
        "zap_ajax_spider_parsed": 0,
        "zap_ajax_spider_new": 0,
        "zap_ajax_spider_overlap": 0,
    }

    for url in zap_ajax_urls or []:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue

            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"
            methods = ["GET"]
            query_params = _query_parameters_from_url(parsed.query, classify_parameter, infer_parameter_type)
            stats["zap_ajax_spider_parsed"] += 1

            if base_url not in existing_by_base_url:
                existing_by_base_url[base_url] = {
                    "base_url": base_url,
                    "endpoints": {},
                    "summary": {
                        "total_endpoints": 0,
                        "total_parameters": 0,
                        "methods": {},
                        "categories": {},
                    },
                }

            base_entry = existing_by_base_url[base_url]
            endpoints = base_entry.setdefault("endpoints", {})
            if path in endpoints:
                stats["zap_ajax_spider_overlap"] += 1
                _merge_overlap_endpoint(endpoints[path], url, query_params, classify_endpoint)
                _recompute_summary(base_entry)
                continue

            stats["zap_ajax_spider_new"] += 1
            parameters = {"query": query_params, "body": [], "path": []}
            category = classify_endpoint(path, methods, parameters)
            endpoints[path] = {
                "path": path,
                "methods": methods,
                "full_url": url,
                "has_parameters": bool(query_params),
                "category": category,
                "sources": [SOURCE_NAME],
                "parameters": parameters,
                "parameter_count": _parameter_count(parameters),
                "sample_urls": [url],
                "urls_found": 1,
            }
            _recompute_summary(base_entry)
        except Exception:
            continue

    return existing_by_base_url, stats


def pull_zap_ajax_docker_image(docker_image: str) -> bool:
    """Pull the configured ZAP Docker image, or use the copy already on this host if the pull fails."""
    print(f"[*][ZAP Ajax] Pulling ZAP image: {docker_image}...")
    return pull_image_or_use_local(docker_image, "ZAP Ajax")


def run_zap_ajax_spider(
    target_urls,
    docker_image,
    allowed_hosts,
    custom_headers,
    exclude_patterns,
    max_urls,
    max_duration,
    max_crawl_depth,
    max_crawl_states,
    number_of_browsers,
    browser_id,
    event_wait,
    reload_wait,
    click_default_elems,
    click_elems_once,
    random_inputs,
    logout_avoidance,
    scope_check,
    parallelism=1,
    max_seeds=ZAP_MAX_SEEDS_DEFAULT,
) -> tuple[List[str], Dict]:
    """Run ZAP Ajax Spider for seed URLs and return filtered discovered URLs."""
    allowed = {str(host).lower() for host in (allowed_hosts or []) if host}
    seeds = []
    invalid_seed_urls = 0
    out_of_scope_seed_urls = 0
    bundled_path_seed_urls = 0
    dropped_seed_urls = []
    for target_url in target_urls or []:
        url = str(target_url).strip()
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host:
            invalid_seed_urls += 1
            dropped_seed_urls.append({
                "reason": "invalid",
                "source": SOURCE_NAME,
                "url": "***",
            })
            continue
        if allowed and host not in allowed:
            out_of_scope_seed_urls += 1
            dropped_seed_urls.append({
                "reason": "out_of_scope",
                "source": SOURCE_NAME,
                "domain": host,
                "url": _safe_url_detail(url),
            })
            continue
        if _bundled_zap_seed_path(url):
            bundled_path_seed_urls += 1
            continue
        seeds.append(url)

    if out_of_scope_seed_urls:
        print(f"[!][ZAP Ajax] Skipping {out_of_scope_seed_urls} out-of-scope seed URL(s)")
    if bundled_path_seed_urls:
        print(f"[!][ZAP Ajax] Skipping {bundled_path_seed_urls} seed URL(s) carrying "
              f"a reflected payload inside the path")

    headers, invalid_headers = parse_zap_ajax_header_lines(custom_headers or [])
    masked_headers = [
        mask_zap_ajax_header_line(str(line))
        for line in (custom_headers or [])
        if str(line).strip()
    ]

    for invalid in invalid_headers:
        print(f"[!][ZAP Ajax] Ignoring invalid custom header: {mask_zap_ajax_header_line(invalid)}")

    metadata = {
        "seed_urls": len(seeds),
        "seeds_attempted": len(seeds),
        "seeds_succeeded": 0,
        "seeds_failed": 0,
        "invalid_seed_urls": invalid_seed_urls,
        "out_of_scope_seed_urls": out_of_scope_seed_urls,
        "bundled_path_seed_urls": bundled_path_seed_urls,
        "failed_seeds": 0,
        "invalid_headers": len(invalid_headers),
        "masked_headers": masked_headers,
        "dropped_seed_urls": dropped_seed_urls,
        "errors": [],
        "raw_urls": 0,
    }
    debug_enabled = _zap_ajax_debug_enabled()

    # Skip a seed whose host another module already found unreachable: the ZAP
    # Ajax Spider otherwise spends its full per-seed run (up to ~780s) on a dead
    # host. Discovered URLs land under source 'resource_enum', so the skip is
    # reported per host and the prune keeps that host's endpoints.
    from recon.helpers import circuit_breaker as _cb
    _scope = _cb.scope((), label="ZAP Ajax", unit="seed(s)")
    kept_seeds = [s for s in seeds if not _scope.skip_if_down(s)]
    if len(kept_seeds) != len(seeds):
        metadata["seeds_skipped_unreachable"] = len(seeds) - len(kept_seeds)
        seeds = kept_seeds
        metadata["seed_urls"] = len(seeds)
        metadata["seeds_attempted"] = len(seeds)

    if not seeds:
        filtered, filter_meta = filter_zap_ajax_urls([], allowed_hosts, exclude_patterns, max_urls)
        metadata.update(filter_meta)
        _scope.finish("resource_enum", host_source="resource_enum")
        return filtered, metadata

    # One seed costs one ZAP container for up to its full crawl budget, so the
    # seed list is the phase's wall clock. Unbounded, a 100k-endpoint target (an
    # SPA behind a catch-all, or `base_urls_and_endpoints` over a big graph) is
    # days of crawling and looks exactly like a hung scan. Keep the cap over the
    # seeds that survive the filters, cheapest-host-first is not attempted: the
    # caller's ordering already puts base URLs before endpoint paths.
    capped_seeds = _cap_zap_seeds(seeds, max_seeds)
    if len(capped_seeds) != len(seeds):
        metadata["seeds_dropped_by_cap"] = len(seeds) - len(capped_seeds)
        metadata["seed_cap"] = int(max_seeds)
        print(f"[!][ZAP Ajax] Capping seeds at {int(max_seeds)} "
              f"({len(seeds) - len(capped_seeds)} dropped) - raise ZAP_AJAX_SPIDER_MAX_SEEDS to crawl more")
        seeds = capped_seeds
        metadata["seed_urls"] = len(seeds)
        metadata["seeds_attempted"] = len(seeds)

    work_dir = Path(f"/tmp/redamon/zap_ajax_{uuid.uuid4().hex[:8]}")
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    _chmod_best_effort(work_dir, 0o700)

    def crawl_seed(index: int, seed_url: str) -> tuple[List[str], bool, Dict | None]:
        plan_name = f"zap_ajax_plan_{index}.yaml"
        export_name = f"zap_ajax_urls_{index}.txt"
        plan_path = work_dir / plan_name
        export_path = work_dir / export_name
        plan = build_zap_ajax_automation_plan(
            seed_url=seed_url,
            export_file_name=export_name,
            headers=headers,
            exclude_patterns=exclude_patterns,
            max_duration=max_duration,
            max_crawl_depth=max_crawl_depth,
            max_crawl_states=max_crawl_states,
            number_of_browsers=number_of_browsers,
            browser_id=browser_id,
            event_wait=event_wait,
            reload_wait=reload_wait,
            click_default_elems=click_default_elems,
            random_inputs=random_inputs,
            click_elems_once=click_elems_once,
            logout_avoidance=logout_avoidance,
            scope_check=scope_check,
        )
        fd = os.open(str(plan_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as plan_file:
            plan_file.write(plan)
        _chmod_best_effort(plan_path, 0o600)

        proxy_port = _allocate_zap_proxy_port()
        # A name so a timed-out seed can be killed: `subprocess.run` on timeout
        # kills only the local `docker run` CLI, and the container it started is
        # left running. Each abandoned ZAP JVM is a ~700 MB Firefox+Java pair
        # that never exits (its plan already succeeded), so a couple of timed-out
        # seeds per crawl pile up until the host is out of memory -- which is
        # what then looks like "the scan froze".
        container_name = f"redamon-zap-ajax-{uuid.uuid4().hex[:12]}"
        # The ceiling this container gets, decided HERE and passed with --memory,
        # so the JVM's -Xmx below is sized from a limit that actually exists.
        # Before this the heap was derived from the governor's guess (2.25 GiB
        # for a tool with no envelope of its own) while the broker clamped the
        # container to 2 GiB -- so the JVM was sized for 2.25 GiB of headroom it
        # never had, and the kernel killed it (exit 137) on every crawl.
        container_bytes = _zap_container_bytes()
        cmd = [
            "docker", "run", "--rm", "--net=host", "--name", container_name,
            "--memory", str(container_bytes),
            *_docker_user_args(),
            "-v", f"{work_dir}:/zap/wrk",
            docker_image,
            "zap.sh", "-cmd",
            # zap.sh reads the *host* MemTotal on cgroup v2 (it still looks for
            # the v1 /sys/fs/cgroup/memory/memory.stat), so it sizes the heap at
            # a quarter of 64 GB = -Xmx16029m inside a small container. The JVM
            # then fails thread/heap allocation against the real limit. Passed
            # after `zap.sh` because zap.sh itself parses it and overrides its
            # own calculation.
            f"-Xmx{_zap_heap_mb(container_bytes)}m",
            "-port", str(proxy_port), "-autorun", f"/zap/wrk/{plan_name}",
        ]
        failed = False
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_zap_seed_timeout(max_duration),
            )
            failed = result.returncode != 0
            if failed:
                print(f"[!][ZAP Ajax] Seed failed with exit code {result.returncode}: {_safe_url_detail(seed_url)}")
                stdout_tail = _redact_sensitive_output(_tail_text(result.stdout), headers)
                stderr_tail = _redact_sensitive_output(_tail_text(result.stderr), headers)
                if stdout_tail:
                    print(f"[!][ZAP Ajax] stdout tail:\n{stdout_tail}")
                if stderr_tail:
                    print(f"[!][ZAP Ajax] stderr tail:\n{stderr_tail}")
                if debug_enabled:
                    print(f"[*][ZAP Ajax] Debug plan retained at: {plan_path}")
                    print(f"[*][ZAP Ajax] Debug export path: {export_path}")
                error = {
                    "type": "docker_exit",
                    "seed_url": _safe_url_detail(seed_url),
                    "exit_code": result.returncode,
                    "proxy_port": proxy_port,
                    "stdout_tail": stdout_tail,
                    "stderr_tail": stderr_tail,
                }
            else:
                error = None
        except subprocess.TimeoutExpired:
            failed = True
            # subprocess.run already killed the `docker run` CLI; the container
            # it launched survives that, so kill it by name. Without this every
            # timed-out seed leaks a ~700 MB ZAP JVM plus a Firefox for the rest
            # of the host's uptime, and a few of them exhaust memory.
            _kill_zap_container(container_name)
            print(f"[!][ZAP Ajax] Seed timed out: {_safe_url_detail(seed_url)}")
            error = {
                "type": "timeout",
                "seed_url": _safe_url_detail(seed_url),
            }
        except Exception as exc:
            failed = True
            print(f"[!][ZAP Ajax] Seed error for {_safe_url_detail(seed_url)}: {exc}")
            error = {
                "type": exc.__class__.__name__,
                "seed_url": _safe_url_detail(seed_url),
                "message": str(exc),
            }

        return parse_zap_ajax_export_urls(export_path), failed, error

    all_urls = []
    seeds_failed = 0
    workers = max(1, int(parallelism or 1))
    try:
        with ThreadPoolExecutor(max_workers=min(workers, len(seeds))) as executor:
            futures = {
                executor.submit(crawl_seed, index, seed): seed
                for index, seed in enumerate(seeds)
            }
            for future in as_completed(futures):
                try:
                    urls, failed, error = future.result()
                    all_urls.extend(urls)
                    if failed:
                        seeds_failed += 1
                    if error:
                        metadata["errors"].append(error)
                except Exception as exc:
                    seeds_failed += 1
                    print(f"[!][ZAP Ajax] Worker error: {exc}")
                    metadata["errors"].append({
                        "type": exc.__class__.__name__,
                        "seed_url": _safe_url_detail(futures[future]),
                        "message": str(exc),
                    })

        filtered, filter_meta = filter_zap_ajax_urls(
            all_urls,
            allowed_hosts,
            exclude_patterns,
            0,
        )
        filtered = sorted(filtered)
        limit = int(max_urls) if max_urls is not None else 0
        if limit > 0 and len(filtered) > limit:
            for url in filtered[limit:]:
                filter_meta["dropped_urls"].append({
                    "reason": "max_urls",
                    "source": SOURCE_NAME,
                    "url": _safe_url_detail(url),
                })
            filter_meta["max_url_dropped"] = len(filtered) - limit
            filtered = filtered[:limit]
        metadata.update(filter_meta)
        metadata["seeds_failed"] = seeds_failed
        metadata["seeds_succeeded"] = len(seeds) - seeds_failed
        metadata["failed_seeds"] = seeds_failed
        return filtered, metadata
    finally:
        _scope.finish("resource_enum", host_source="resource_enum")
        if debug_enabled:
            print(f"[*][ZAP Ajax] Debug work directory retained: {work_dir}")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


def _query_parameters_from_url(query: str, classify_parameter, infer_parameter_type) -> List[Dict]:
    params = []
    for name, values in parse_qs(query, keep_blank_values=True).items():
        sample_values = [value for value in values if value][:5]
        params.append({
            "name": name,
            "sample_values": sample_values,
            "type": infer_parameter_type(name, sample_values),
            "category": classify_parameter(name),
            "position": "query",
        })
    return params


def _safe_url_detail(url: str) -> str:
    """Return a URL detail safe for metadata by dropping query values."""
    try:
        parsed = urlparse(str(url))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "***"

        safe = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        query_names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
        if query_names:
            safe = f"{safe}?{','.join(query_names)}"
        return safe
    except Exception:
        return "***"


def _zap_context_url(seed_url: str) -> str:
    parsed = urlparse(str(seed_url))
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return str(seed_url)


def _compile_exclude_patterns(exclude_patterns) -> tuple[List[re.Pattern], List[str]]:
    compiled = []
    invalid = []
    for raw_pattern in exclude_patterns or []:
        pattern = str(raw_pattern).strip()
        if not pattern:
            continue
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            invalid.append(pattern)
    return compiled, invalid


def _zap_ajax_debug_enabled() -> bool:
    return str(os.environ.get(_DEBUG_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}


def _allocate_zap_proxy_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# The passive-scan wait is a queue drain, not a crawl: it only has to let ZAP
# process what the spider already fetched. Giving it the crawl's own maxDuration
# doubles every seed's wall time for no extra coverage.
PASSIVE_SCAN_MAX_MINUTES = 2


def _zap_passive_minutes(max_duration: int) -> int:
    return max(1, min(int(max_duration), PASSIVE_SCAN_MAX_MINUTES))


def _zap_seed_timeout(max_duration: int) -> int:
    """Wall-clock budget for one seed's `docker run`, in seconds.

    The plan runs spiderAjax for up to `max_duration` minutes and then the
    passive-scan wait for its own budget, so a timeout of `max_duration * 60 +
    180` cut the seed off before the plan could finish and counted a healthy
    crawl as a failure.
    """
    return (int(max_duration) + _zap_passive_minutes(max_duration)) * 60 + 180


def _zap_container_bytes() -> int:
    """Memory ceiling to give one ZAP container, in bytes.

    The resource governor owns the per-tool envelope so a spawn from the recon
    container agrees with what the broker and the orchestrator budget for the
    same tool. Falling back to a fixed 1.5 GB keeps this working when the
    governor is unavailable.
    """
    try:
        try:
            from graph_db import resource_governor as rg
        except ImportError:
            import resource_governor as rg  # noqa: F401 - alt sys.path (tests)
        envelope = rg.tool_container_envelope(ZAP_ENVELOPE_TOOL)
        cap = rg.container_cap(envelope)
        value = cap or envelope
        if value and value > 0:
            return int(value)
    except Exception:  # noqa: BLE001 - no governor: use the fixed envelope
        pass
    return _DEFAULT_ZAP_CONTAINER_BYTES


def _zap_heap_mb(container_bytes: int | None = None) -> int:
    """JVM heap for one ZAP container, sized from that container's ceiling.

    zap.sh derives -Xmx from MemTotal -- it only consults the cgroup **v1**
    memory.stat, which does not exist on a cgroup v2 host -- so inside a 2 GB
    container it asked for a quarter of the host's 64 GB (-Xmx16029m). The JVM
    is then killed, or fails thread and heap allocation against the real limit,
    which is why seeds "timed out" while doing nothing.

    The heap is what is LEFT after Firefox and the JVM's own non-heap memory
    are reserved, not a fraction of the ceiling. A fraction is wrong here
    because Firefox's cost does not scale with the container: at 50% of 2 GiB
    the pair measured 1.87 GiB live and the kernel SIGKILLed the JVM (exit 137)
    on every seed of a real crawl. Reserving first makes a too-small ceiling
    fail as a small heap instead of an OOM kill, and gives a large ceiling a
    heap that actually fits.
    """
    limit = int(container_bytes or _zap_container_bytes())
    usable_mb = int(limit * _ZAP_SAFETY_FRACTION) // (1024 * 1024)
    heap_mb = usable_mb - _ZAP_BROWSER_RESERVE_MB - _ZAP_JVM_OVERHEAD_MB
    return max(_ZAP_HEAP_MIN_MB, min(_ZAP_HEAP_MAX_MB, heap_mb))


def _cap_zap_seeds(seeds: List[str], max_seeds) -> List[str]:
    """Trim the seed list to the configured cap, spreading the pick across hosts.

    A cap applied to the raw list would take the first N strings, which for
    `base_urls_and_endpoints` means every endpoint of the first host and nothing
    of the rest. Round-robin by host so a capped crawl still covers the estate.
    """
    try:
        limit = int(max_seeds)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0 or len(seeds) <= limit:
        return list(seeds)

    by_host: Dict[str, List[str]] = {}
    for url in seeds:
        host = (urlparse(url).netloc or "").lower()
        by_host.setdefault(host, []).append(url)

    picked: List[str] = []
    cursor = {host: 0 for host in by_host}
    hosts = sorted(by_host)
    while len(picked) < limit:
        progressed = False
        for host in hosts:
            if len(picked) >= limit:
                break
            index = cursor[host]
            if index < len(by_host[host]):
                picked.append(by_host[host][index])
                cursor[host] = index + 1
                progressed = True
        if not progressed:
            break
    return picked


def _kill_zap_container(name: str) -> None:
    """Remove one ZAP container by name. Never raises, never blocks a scan."""
    if not name:
        return
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except Exception as exc:  # noqa: BLE001 - cleanup must not fail the seed
        print(f"[!][ZAP Ajax] Could not remove container {name}: {type(exc).__name__}")


def _tail_text(value: str | None, max_chars: int = 4000) -> str:
    text = (value or "").strip()
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def _redact_sensitive_output(text: str, headers: List[Dict[str, str]]) -> str:
    redacted = text or ""
    for header in headers or []:
        value = str(header.get("value", ""))
        if value:
            redacted = redacted.replace(value, "***")
    return redacted


def _docker_user_args() -> List[str]:
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        return []
    try:
        return ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]
    except Exception:
        return []


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _merge_overlap_endpoint(endpoint: Dict, url: str, query_params: List[Dict], classify_endpoint) -> None:
    sources = endpoint.setdefault("sources", [])
    if SOURCE_NAME not in sources:
        sources.append(SOURCE_NAME)

    parameters = endpoint.setdefault("parameters", {"query": [], "body": [], "path": []})
    parameters.setdefault("query", [])
    parameters.setdefault("body", [])
    parameters.setdefault("path", [])

    existing_by_name = {param.get("name"): param for param in parameters["query"]}
    for param in query_params:
        existing = existing_by_name.get(param["name"])
        if existing:
            samples = existing.setdefault("sample_values", [])
            for value in param.get("sample_values", []):
                if value and value not in samples and len(samples) < 5:
                    samples.append(value)
        else:
            parameters["query"].append(param)

    endpoint["parameter_count"] = _parameter_count(parameters)
    endpoint["has_parameters"] = endpoint["parameter_count"]["total"] > 0
    endpoint["urls_found"] = int(endpoint.get("urls_found", 0)) + 1
    samples = endpoint.setdefault("sample_urls", [])
    if len(samples) < 3 and url not in samples:
        samples.append(url)
    endpoint["category"] = classify_endpoint(
        endpoint.get("path", urlparse(url).path or "/"),
        endpoint.get("methods", ["GET"]),
        parameters,
    )


def _parameter_count(parameters: Dict) -> Dict[str, int]:
    query = len(parameters.get("query", []))
    body = len(parameters.get("body", []))
    path = len(parameters.get("path", []))
    return {"query": query, "body": body, "path": path, "total": query + body + path}


def _recompute_summary(base_entry: Dict) -> None:
    summary = {
        "total_endpoints": 0,
        "total_parameters": 0,
        "methods": {},
        "categories": {},
    }

    for endpoint in base_entry.get("endpoints", {}).values():
        summary["total_endpoints"] += 1
        count = endpoint.get("parameter_count") or _parameter_count(endpoint.get("parameters", {}))
        summary["total_parameters"] += count.get("total", 0)
        for method in endpoint.get("methods", []):
            summary["methods"][method] = summary["methods"].get(method, 0) + 1
        category = endpoint.get("category")
        if category:
            summary["categories"][category] = summary["categories"].get(category, 0) + 1

    base_entry["summary"] = summary
