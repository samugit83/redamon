import io
import json
import logging
import tarfile
import yaml
from pathlib import Path

from knowledge_base.chunking import ChunkStrategy
from knowledge_base.curation.base_client import BaseClient
from knowledge_base.curation.file_cache import (
    YAMLTooComplexError,
    bounded_tar_iter,
    bounded_yaml_load,
    diff_files,
    load_file_hashes,
    safe_relative_path,
    safe_write_text,
    save_file_hashes,
)
from knowledge_base.curation.safe_http import MAX_TARBALL_BYTES, safe_get

logger = logging.getLogger(__name__)

NUCLEI_TEMPLATES_TARBALL_URL = (
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz"
)


class NucleiClient(BaseClient):
    """Fetches and parses Nuclei template metadata from GitHub."""

    SOURCE = "nuclei"
    NODE_LABEL = "NucleiChunk"

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path(__file__).parent.parent / "data" / "cache" / "nuclei"
        )

    def fetch(self, **kwargs) -> list[dict]:
        """
        Download nuclei-templates tarball, diff against file cache, parse changed files.

        Returns list of dicts: [{id, name, severity, tags, cve_ids, protocol}]
        Only returns entries for new/changed templates. Unchanged files are skipped.
        Pass _return_all=True in kwargs to return all entries (for full rebuild).
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        old_hashes = load_file_hashes(self.cache_dir)
        return_all = kwargs.get("_return_all", False)

        # Download tarball (~30-40 MB, single request, generous timeout)
        try:
            logger.info("Downloading nuclei-templates repo tarball...")
            resp = safe_get(
                NUCLEI_TEMPLATES_TARBALL_URL,
                timeout=300,
                max_bytes=MAX_TARBALL_BYTES,
            )
            resp.raise_for_status()
            tarball_bytes = resp.content
            logger.info(f"Downloaded {len(tarball_bytes)} bytes")
        except Exception as e:
            logger.error(f"Failed to download nuclei-templates tarball: {e}")
            return self._load_all_from_cache() if return_all else []

        # Walk the tarball and collect template YAML content keyed by relative
        # path (stripped of the top-level archive dir, e.g. "nuclei-templates-main/").
        # Only regular .yaml / .yml files are considered; everything else is skipped.
        all_files: dict[str, str] = {}
        skipped_unsafe = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
                for member in bounded_tar_iter(tar, label="nuclei-templates"):
                    name = member.name
                    if not (name.endswith(".yaml") or name.endswith(".yml")):
                        continue

                    # Strip leading "nuclei-templates-main/" so hash keys are
                    # stable across archive re-generations.
                    parts = name.split("/", 1)
                    rel_path = parts[1] if len(parts) == 2 else name
                    if not rel_path:
                        continue

                    # Skip non-template files
                    if rel_path.startswith(".github/"):
                        continue
                    if rel_path == ".pre-commit-config.yaml" or rel_path == ".pre-commit-config.yml":
                        continue

                    if safe_relative_path(rel_path, self.cache_dir) is None:
                        skipped_unsafe += 1
                        logger.warning(
                            f"Nuclei: skipping unsafe tar member {name!r} "
                            f"(rel_path={rel_path!r})"
                        )
                        continue

                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    try:
                        content = f.read().decode("utf-8", errors="replace")
                    except Exception as e:
                        logger.warning(f"Skipping unreadable tar member {name!r}: {e}")
                        continue
                    all_files[rel_path] = content
        except Exception as e:
            logger.error(f"Failed to extract nuclei-templates tarball: {e}")
            return self._load_all_from_cache() if return_all else []

        if skipped_unsafe:
            logger.warning(f"Nuclei: skipped {skipped_unsafe} unsafe tar members")

        # Diff against file cache
        changed_files, updated_hashes = diff_files(all_files, old_hashes)

        # Write changed files to cache dir (paths re-validated)
        for rel_path, content in changed_files.items():
            safe_dest = safe_relative_path(rel_path, self.cache_dir)
            if safe_dest is None:
                logger.error(
                    f"Nuclei: refusing to write unsafe cache path {rel_path!r}"
                )
                continue
            safe_dest.parent.mkdir(parents=True, exist_ok=True)
            safe_write_text(safe_dest, content, encoding="utf-8")

        # Save updated file hashes
        save_file_hashes(self.cache_dir, updated_hashes)

        logger.info(
            f"Nuclei: {len(all_files)} total YAMLs, {len(changed_files)} changed, "
            f"{len(all_files) - len(changed_files)} unchanged"
        )

        # Parse only changed files (or all if return_all)
        files_to_parse = all_files if return_all else changed_files
        results: list[dict] = []
        skipped = 0
        errors = 0

        for rel_path, content in files_to_parse.items():
            try:
                data = bounded_yaml_load(content, label=f"nuclei:{rel_path}")
            except YAMLTooComplexError as e:
                errors += 1
                logger.warning(f"Nuclei: rejecting hostile YAML {rel_path}: {e}")
                continue
            except Exception as e:
                errors += 1
                logger.debug(f"Failed to parse {rel_path}: {e}")
                continue

            if not isinstance(data, dict) or not data.get("id"):
                skipped += 1
                continue

            parsed = self._normalize_template(data)
            if parsed:
                parsed["source_path"] = f"knowledge_base/data/cache/nuclei/{rel_path}"
                results.append(parsed)

        logger.info(
            f"Nuclei: parsed {len(results)} templates "
            f"({skipped} skipped, {errors} parse errors)"
        )
        return results

    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """
        Convert Nuclei template metadata to chunks.

        One chunk per template. Content is assembled to maximize embedding
        signal: prose (description/impact/remediation), classifiers (tags,
        CVEs, protocol), and the actual implementation body (flow,
        variables, code/tcp/javascript blocks).
        """
        chunks = []
        for entry in raw_data:
            template_id = entry.get("id", "unknown")
            name = entry.get("name", "")
            severity = entry.get("severity", "info")
            tags = entry.get("tags", [])
            codes = entry.get("codes", [])
            cve_id = entry.get("cve_id")
            cvss_score = entry.get("cvss_score")
            epss_score = entry.get("epss_score")
            protocol = entry.get("protocol", "")
            description = entry.get("description", "")
            impact = entry.get("impact", "")
            remediation = entry.get("remediation", "")
            metadata = entry.get("metadata", {})
            flow = entry.get("flow", "")
            variables = entry.get("variables", {})
            http_blocks = entry.get("http_blocks", [])
            dns_blocks = entry.get("dns_blocks", [])
            code_blocks = entry.get("code_blocks", [])
            tcp_blocks = entry.get("tcp_blocks", [])
            js_blocks = entry.get("javascript_blocks", [])

            if name:
                content = f"{name} ({severity})"
            else:
                content = f"{template_id} ({severity})"

            if description:
                content += f"\n\n{description.strip()}"

            if variables:
                var_lines = ", ".join(f"{k}={v}" for k, v in variables.items())
                content += f"\n\nVariables: {var_lines}"

            if flow:
                content += f"\n\nFlow:\n{flow.strip()}"

            for i, block in enumerate(http_blocks, start=1):
                method = block.get("method", "")
                paths = block.get("paths", [])
                body = block.get("body", "")
                raw_reqs = block.get("raw", [])
                payloads = block.get("payloads", "")
                label = f"HTTP step {i}" if len(http_blocks) > 1 else "HTTP"

                if raw_reqs:
                    for r in raw_reqs:
                        content += f"\n\n{label} (raw):\n{r}"
                else:
                    line = f"\n\n{label}:"
                    if method and paths:
                        line += f" {method} {'; '.join(paths)}"
                    elif method:
                        line += f" {method}"
                    elif paths:
                        line += f" {'; '.join(paths)}"
                    content += line
                    if body:
                        content += f"\nBody: {body}"
                if payloads:
                    content += f"\nPayloads: {payloads}"

            for i, block in enumerate(dns_blocks, start=1):
                qname = block.get("name", "")
                qtype = block.get("type", "")
                qclass = block.get("class", "")
                label = f"DNS query {i}" if len(dns_blocks) > 1 else "DNS query"
                line = f"\n\n{label}: {qname}"
                if qtype:
                    line += f" ({qtype}"
                    if qclass:
                        line += f"/{qclass}"
                    line += ")"
                content += line

            for i, block in enumerate(code_blocks, start=1):
                engine = block.get("engine", "")
                source = block.get("source", "").strip()
                if not source:
                    continue
                label = f"Code step {i}" if len(code_blocks) > 1 else "Code"
                if engine:
                    label += f" ({engine})"
                content += f"\n\n{label}:\n{source}"

            for i, block in enumerate(tcp_blocks, start=1):
                port = block.get("port", "")
                inputs = block.get("inputs", [])
                label = f"TCP probe {i}" if len(tcp_blocks) > 1 else "TCP probe"
                if port:
                    label += f" (port {port})"
                if inputs:
                    inputs_str = "; ".join(inputs)
                    content += f"\n\n{label}: {inputs_str}"
                else:
                    content += f"\n\n{label}"

            for i, block in enumerate(js_blocks, start=1):
                code = block.get("code", "").strip()
                payloads = block.get("payloads", "")
                if not code:
                    continue
                label = f"JavaScript step {i}" if len(js_blocks) > 1 else "JavaScript"
                content += f"\n\n{label}:\n{code}"
                if payloads:
                    content += f"\nPayloads: {payloads}"

            chunk_id = ChunkStrategy.generate_chunk_id(self.SOURCE, template_id)
            metadata_json = json.dumps(metadata, ensure_ascii=False) if metadata else ""

            chunks.append({
                "chunk_id": chunk_id,
                "content": content,
                "title": f"{template_id} — {name}",
                "source": self.SOURCE,
                "template_id": template_id,
                "severity": severity,
                "tags": tags,
                "codes": codes,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "protocol": protocol,
                "description": description,
                "impact": impact,
                "remediation": remediation,
                "metadata": metadata_json,
                "source_path": entry.get("source_path", ""),
            })

        logger.info(f"Created {len(chunks)} Nuclei template chunks")
        return chunks

    _PROTOCOL_KEYS = (
        "http", "dns", "tcp", "network", "code", "file",
        "ssl", "websocket", "javascript", "whois", "headless",
        "workflows",
    )

    def _normalize_template(self, data: dict) -> dict | None:
        """Normalize a parsed template YAML dict to our standard format."""
        template_id = data.get("id") or data.get("template-id") or data.get("ID")
        if not template_id:
            return None

        info = data.get("info", data)
        if not isinstance(info, dict):
            info = {}
        name = info.get("name", "")
        severity = info.get("severity", "info")
        description = self._as_str(info.get("description"))
        impact = self._as_str(info.get("impact"))
        remediation = self._as_str(info.get("remediation"))

        tags_raw = info.get("tags", "")
        if isinstance(tags_raw, str):
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        elif isinstance(tags_raw, list):
            tags = [str(t) for t in tags_raw]
        else:
            tags = []

        codes: list[str] = []

        def _add_code(value):
            if value is None:
                return
            if isinstance(value, list):
                for v in value:
                    _add_code(v)
                return
            s = str(value).strip()
            if not s:
                return

            up = s.upper()
            if up.startswith("CVE-") or up.startswith("CWE-"):
                s = up
            if s not in codes:
                codes.append(s)

        for t in tags:
            if t.upper().startswith("CVE-"):
                _add_code(t)

        classification = info.get("classification", {})
        if isinstance(classification, dict):
            _add_code(classification.get("cve-id") or classification.get("cve_id"))
            _add_code(classification.get("cwe-id") or classification.get("cwe_id"))

        cve_id = next((c for c in codes if c.startswith("CVE-")), None)

        cvss_score = self._as_float(
            classification.get("cvss-score") if isinstance(classification, dict) else None
        )
        epss_score = self._as_float(
            classification.get("epss-score") if isinstance(classification, dict) else None
        )

        protocol = ""
        for key in self._PROTOCOL_KEYS:
            if key in data:
                protocol = key
                break

        metadata_raw = info.get("metadata", {})
        metadata: dict = {}
        if isinstance(metadata_raw, dict):
            for k, v in metadata_raw.items():
                if v is None:
                    continue
                metadata[str(k)] = v

        flow = self._as_str(data.get("flow"))
        variables_raw = data.get("variables")
        variables: dict = {}
        if isinstance(variables_raw, dict):
            variables = {str(k): str(v) for k, v in variables_raw.items()}

        http_blocks = self._extract_http_blocks(data.get("http"))
        dns_blocks = self._extract_dns_blocks(data.get("dns"))
        code_blocks = self._extract_code_blocks(data.get("code"))
        tcp_blocks = self._extract_tcp_blocks(
            data.get("tcp") or data.get("network")
        )
        javascript_blocks = self._extract_javascript_blocks(data.get("javascript"))

        return {
            "id": template_id,
            "name": name,
            "severity": severity,
            "tags": tags,
            "codes": codes,
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "epss_score": epss_score,
            "protocol": protocol,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "metadata": metadata,
            "flow": flow,
            "variables": variables,
            "http_blocks": http_blocks,
            "dns_blocks": dns_blocks,
            "code_blocks": code_blocks,
            "tcp_blocks": tcp_blocks,
            "javascript_blocks": javascript_blocks,
        }

    @staticmethod
    def _as_str(value) -> str:
        """Coerce a YAML field to a stripped string. Handles None and non-strings."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return str(value).strip()

    @staticmethod
    def _as_float(value) -> float | None:
        """
        Coerce a YAML field to a float, returning None if not coercible.

        Some templates store numeric scores as floats, some as ints, and a
        few as strings ("9.3"). All three should round-trip cleanly.
        """
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None

    @staticmethod
    def _extract_http_blocks(raw) -> list[dict]:
        """
        Pull request payloads from a top-level `http:` block.

        Two template forms are supported:
          1. method/path form (most common):
             http:
               - method: GET
                 path:
                   - '{{BaseURL}}/api/foo'
                 body: '{"x":1}'
                 payloads: { user: [admin], pass: [admin] }
          2. raw form (full HTTP request as a string):
             http:
               - raw:
                   - |
                     POST /api HTTP/1.1
                     Host: {{Hostname}}
                     ...
                     {"x":1}

        Detection logic (matchers, extractors, redirects, attack mode,
        cookie-reuse, max-redirects) is intentionally dropped.

        Returns:
            [
              {"method": "GET",
               "paths": ["{{BaseURL}}/api/foo", ...],
               "body": "...",
               "raw": ["..."],
               "payloads": "user=admin; pass=admin"},
              ...
            ]
        """
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for step in raw:
            if not isinstance(step, dict):
                continue

            method = step.get("method")
            method = str(method).upper() if isinstance(method, str) else ""

            path_raw = step.get("path")
            paths: list[str] = []
            if isinstance(path_raw, list):
                paths = [str(p) for p in path_raw if p]
            elif isinstance(path_raw, str) and path_raw:
                paths = [path_raw]

            body = step.get("body")
            body_str = str(body).strip() if isinstance(body, str) else ""

            raw_reqs_in = step.get("raw")
            raw_reqs: list[str] = []
            if isinstance(raw_reqs_in, list):
                raw_reqs = [str(r).strip() for r in raw_reqs_in if isinstance(r, str) and r.strip()]

            payloads_raw = step.get("payloads")
            payload_parts: list[str] = []
            if isinstance(payloads_raw, dict):
                for k, v in payloads_raw.items():
                    if isinstance(v, list):
                        v_str = ",".join(str(x) for x in v)
                    else:
                        v_str = str(v)
                    payload_parts.append(f"{k}={v_str}")
            payloads = "; ".join(payload_parts)

            if not (method or paths or body_str or raw_reqs):
                continue

            out.append({
                "method": method,
                "paths": paths,
                "body": body_str,
                "raw": raw_reqs,
                "payloads": payloads,
            })
        return out

    @staticmethod
    def _extract_dns_blocks(raw) -> list[dict]:
        """
        Pull query name + type from a top-level `dns:` block.

        Format:
            dns:
              - name: "_dmarc.{{FQDN}}"
                type: TXT
                class: inet

        Detection logic (matchers, extractors) and runtime config
        (recursion, retries) are dropped.

        Returns: [{"name": "...", "type": "TXT", "class": "inet"}, ...]
        """
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for step in raw:
            if not isinstance(step, dict):
                continue
            name = step.get("name")
            qtype = step.get("type")
            qclass = step.get("class")
            if not isinstance(name, str) or not name:
                continue
            out.append({
                "name": name,
                "type": str(qtype).upper() if isinstance(qtype, str) else "",
                "class": str(qclass) if isinstance(qclass, str) else "",
            })
        return out

    @staticmethod
    def _extract_code_blocks(raw) -> list[dict]:
        """
        Pull engine + source from a top-level `code:` block.

        Format:
            code:
              - engine: [sh, bash]
                source: |
                  az monitor ...
              - engine: [...]
                source: |
                  ...
        Returns: [{"engine": "sh,bash", "source": "..."}, ...]
        """
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for step in raw:
            if not isinstance(step, dict):
                continue
            engine_raw = step.get("engine")
            if isinstance(engine_raw, list):
                engine = ",".join(str(e) for e in engine_raw)
            elif isinstance(engine_raw, str):
                engine = engine_raw
            else:
                engine = ""
            source = step.get("source")
            if not isinstance(source, str):
                continue
            out.append({"engine": engine, "source": source})
        return out

    @staticmethod
    def _extract_tcp_blocks(raw) -> list[dict]:
        """
        Pull port + input data from a top-level `tcp:` (or `network:`) block.

        Returns: [{"port": int|str, "inputs": ["data1", "data2"]}, ...]
        """
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for step in raw:
            if not isinstance(step, dict):
                continue
            port_raw = step.get("port")
            if isinstance(port_raw, list):
                port = str(port_raw[0]) if port_raw else ""
            elif port_raw is not None:
                port = str(port_raw)
            else:
                port = ""

            inputs_raw = step.get("inputs")
            inputs: list[str] = []
            if isinstance(inputs_raw, list):
                for inp in inputs_raw:
                    if isinstance(inp, dict):
                        data = inp.get("data")
                        if isinstance(data, str) and data:
                            inputs.append(data)
            out.append({"port": port, "inputs": inputs})
        return out

    @staticmethod
    def _extract_javascript_blocks(raw) -> list[dict]:
        """
        Pull code + payloads from a top-level `javascript:` block.

        Returns: [{"code": "...", "payloads": "user=admin; pass=admin"}, ...]
        Detection logic (matchers, extractors, args, attack mode) is dropped.
        """
        if not isinstance(raw, list):
            return []
        out: list[dict] = []
        for step in raw:
            if not isinstance(step, dict):
                continue
            code = step.get("code")
            if not isinstance(code, str):
                continue

            payloads_raw = step.get("payloads")
            payload_parts: list[str] = []
            if isinstance(payloads_raw, dict):
                for k, v in payloads_raw.items():
                    if isinstance(v, list):
                        v_str = ",".join(str(x) for x in v)
                    else:
                        v_str = str(v)
                    payload_parts.append(f"{k}={v_str}")
            payloads = "; ".join(payload_parts)

            out.append({"code": code, "payloads": payloads})
        return out

    def _load_all_from_cache(self) -> list[dict]:
        """
        Load all cached template files (fallback when download fails).

        Walks cache dir recursively since nuclei templates are nested
        (e.g. cves/2024/CVE-2024-12345.yaml), unlike GTFOBins' flat layout.
        """
        if not self.cache_dir.exists():
            return []

        results: list[dict] = []
        skipped = 0
        errors = 0

        yaml_files = sorted(
            list(self.cache_dir.rglob("*.yaml"))
            + list(self.cache_dir.rglob("*.yml"))
        )
        for cached_file in yaml_files:
            if cached_file.name.startswith("."):
                continue
            try:
                content = cached_file.read_text(encoding="utf-8")
                data = bounded_yaml_load(content, label=f"nuclei:{cached_file.name}")
            except YAMLTooComplexError as e:
                errors += 1
                logger.warning(f"Nuclei: rejecting hostile cached YAML {cached_file}: {e}")
                continue
            except Exception as e:
                errors += 1
                logger.debug(f"Failed to parse cached {cached_file}: {e}")
                continue

            if not isinstance(data, dict) or not data.get("id"):
                skipped += 1
                continue

            parsed = self._normalize_template(data)
            if parsed:
                rel_path = cached_file.relative_to(self.cache_dir).as_posix()
                parsed["source_path"] = f"knowledge_base/data/cache/nuclei/{rel_path}"
                results.append(parsed)

        logger.info(
            f"Loaded {len(results)} Nuclei templates from cache "
            f"({skipped} skipped, {errors} parse errors)"
        )
        return results
