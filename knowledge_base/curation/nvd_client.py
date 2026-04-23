import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from knowledge_base.kb_config import load_kb_config
from knowledge_base.atomic_io import atomic_write_json
from knowledge_base.chunking import ChunkStrategy
from knowledge_base.curation.base_client import BaseClient
from knowledge_base.curation.safe_http import MAX_NVD_PAGE_BYTES, safe_get

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
MAX_DATE_RANGE_DAYS = 120  # NVD API limit
# Rate limits: 5 req/30s without key, 50 req/30s with key
RATE_LIMIT_DELAY_NO_KEY = 6.5  # seconds between requests
RATE_LIMIT_DELAY_WITH_KEY = 0.65

# Allowed profiles
ALLOWED_PROFILES = ("standard", "full")

# Unified cache filename
UNIFIED_CACHE_FILENAME = "nvd_cache.json"

# The source_path value that every NVD chunk carries. Every CVE chunk
# shares the same path because the cache is one unified file.
NVD_SOURCE_PATH = f"knowledge_base/data/cache/nvd/{UNIFIED_CACHE_FILENAME}"


class NVDClient(BaseClient):
    """Fetches CVE data from the NVD REST API."""

    SOURCE = "nvd"
    NODE_LABEL = "NVDChunk"
    DEFAULT_LOOKBACK_DAYS = 90

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path(__file__).parent.parent / "data" / "cache" / "nvd"
        )

    def fetch(
        self,
        profile: str = "standard",
        nvd_api_key: str = None,
        since: str = None,
        nvd_days: int = None,
        nvd_min_cvss: float = None,
        **kwargs,
    ) -> list[dict]:
        """
        Fetch CVE data from NVD API.

        Args:
            profile: 'standard' (date window + CVSS floor) or 'full' (date
                window only, all severities). The date window applies to
                BOTH profiles — the only difference is whether the CVSS
                floor is enforced. To pull the entire historical NVD corpus,
                pass an arbitrarily large nvd_days (e.g. 10000 ≈ 27 years).
            nvd_api_key: Optional NVD API key for higher rate limits.
            since: ISO timestamp for incremental updates (lastModStartDate).
                When set, overrides nvd_days and uses lastModStartDate
                rather than pubStartDate.
            nvd_days: Lookback window in days. Always applies to both
                profiles. Overrides DEFAULT_LOOKBACK_DAYS. Falls back to
                NVD_LOOKBACK_DAYS env var, then kb_config.yaml.
            nvd_min_cvss: Minimum CVSS score for the 'standard' profile.
                Ignored for the 'full' profile. Overrides default. Falls
                back to NVD_MIN_CVSS env var, then kb_config.yaml
                `ingestion.nvd_min_cvss` (default 7.0).

        Returns:
            List of normalized CVE dicts.
        """

        # Validate profile
        if profile not in ALLOWED_PROFILES:
            raise ValueError(
                f"Invalid NVD profile: {profile!r}. "
                f"Allowed: {', '.join(ALLOWED_PROFILES)}"
            )

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        delay = RATE_LIMIT_DELAY_WITH_KEY if nvd_api_key else RATE_LIMIT_DELAY_NO_KEY

        headers = {}
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key

        # Resolve lookback window: kwarg → env var → kb_config.yaml → default
        if nvd_days is None:
            env_val = os.getenv("NVD_LOOKBACK_DAYS")
            if env_val is not None:
                nvd_days = int(env_val)
            else:
                try:
                    nvd_days = load_kb_config().ingestion.nvd_lookback_days
                except Exception:
                    nvd_days = self.DEFAULT_LOOKBACK_DAYS

        # Resolve min CVSS threshold
        if nvd_min_cvss is None:
            env_val = os.getenv("NVD_MIN_CVSS")
            if env_val is not None:
                try:
                    nvd_min_cvss = float(env_val)
                except ValueError:
                    logger.warning(f"Invalid NVD_MIN_CVSS env var: {env_val!r}, using 7.0")
                    nvd_min_cvss = 7.0
            else:
                try:
                    nvd_min_cvss = load_kb_config().ingestion.nvd_min_cvss
                except Exception:
                    nvd_min_cvss = 7.0

        # Determine date range and CVSS filter
        now = datetime.now(timezone.utc)
        min_cvss = None

        # Date window selection
        if since:
            start_date = datetime.fromisoformat(since)
            if start_date.tzinfo is None:
                start_date = start_date.replace(tzinfo=timezone.utc)
            end_date = now
            date_key = "lastModStartDate"
            date_key_end = "lastModEndDate"
        else:
            start_date = now - timedelta(days=nvd_days)
            end_date = now
            date_key = "pubStartDate"
            date_key_end = "pubEndDate"
            if profile == "standard":
                min_cvss = nvd_min_cvss
                logger.info(
                    f"NVD standard profile: fetching last {nvd_days} days "
                    f"({start_date.strftime('%Y-%m-%d')} → {end_date.strftime('%Y-%m-%d')}), "
                    f"CVSS >= {min_cvss}"
                )
            else:
                logger.info(
                    f"NVD full profile: fetching last {nvd_days} days "
                    f"({start_date.strftime('%Y-%m-%d')} → {end_date.strftime('%Y-%m-%d')}), "
                    f"all CVSS severities"
                )

        cache_by_id: dict[str, dict] = self._load_unified_cache()
        initial_cache_size = len(cache_by_id)

        # Track whether the API call succeeded
        api_ok = False
        new_or_updated = 0

        # Generate 120-day windows
        windows = self._date_windows(start_date, end_date)
        total_windows = len(windows)

        for win_idx, (win_start, win_end) in enumerate(windows):
            logger.info(
                f"NVD window {win_idx + 1}/{total_windows}: "
                f"{win_start.strftime('%Y-%m-%d')} → {win_end.strftime('%Y-%m-%d')}"
            )

            start_index = 0
            while True:
                params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
                if date_key:
                    params[date_key] = win_start.strftime("%Y-%m-%dT%H:%M:%S")
                    params[date_key_end] = win_end.strftime("%Y-%m-%dT%H:%M:%S")

                try:
                    resp = safe_get(
                        NVD_API_BASE,
                        params=params,
                        headers=headers,
                        timeout=60,
                        max_bytes=MAX_NVD_PAGE_BYTES,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    api_ok = True
                except Exception as e:
                    msg = str(e)
                    if nvd_api_key:
                        msg = msg.replace(nvd_api_key, "[REDACTED]")
                    logger.error(f"NVD API error: {msg}")
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve = self._normalize_cve(vuln)
                    if not cve:
                        continue
                    cve_id = cve.get("cve_id")
                    if not cve_id:
                        continue

                    cache_by_id[cve_id] = cve
                    new_or_updated += 1

                total_results = data.get("totalResults", 0)
                start_index += RESULTS_PER_PAGE

                logger.info(
                    f"  NVD: {start_index}/{total_results} CVEs in window, "
                    f"{len(cache_by_id)} in unified cache "
                    f"({new_or_updated} added/updated this run)"
                )

                if start_index >= total_results:
                    break

                time.sleep(delay)

        # ─────────────────────────────────────────────────────────────────
        # Post-fetch handling
        # ─────────────────────────────────────────────────────────────────
        if not api_ok and initial_cache_size == 0:
            # API unreachable AND no pre-existing cache → nothing to return.
            logger.error("NVD API unreachable and unified cache is empty")
            return []

        if not api_ok:
            logger.warning(
                f"NVD API unreachable — falling back to unified cache "
                f"({initial_cache_size} entries)"
            )

        self._write_unified_cache(cache_by_id)
        self._cleanup_legacy_profile_files()

        all_entries = list(cache_by_id.values())
        if profile == "standard":
            filtered = [
                cve for cve in all_entries
                if (cve.get("cvss_score") or 0) >= nvd_min_cvss
            ]
        else:
            filtered = all_entries

        # Stamp source_path on each returned entry so to_chunks can pass
        # it through to the chunk dict.
        for cve in filtered:
            cve["source_path"] = NVD_SOURCE_PATH

        logger.info(
            f"NVD fetch complete: profile={profile}, "
            f"cache={len(cache_by_id)}, returned={len(filtered)}"
        )
        return filtered

    def _unified_cache_path(self) -> Path:
        """Path to the unified NVD cache file."""
        return self.cache_dir / UNIFIED_CACHE_FILENAME

    def _load_unified_cache(self) -> dict[str, dict]:
        """
        Load the unified cache as ``{cve_id: entry}``.

        On first run after upgrade (unified file doesn't exist yet), merges
        legacy ``nvd_cache_standard.json`` and ``nvd_cache_full.json`` into a
        single dict. ``full`` wins on conflicts because it has strictly more
        complete data (standard is a CVSS-filtered subset of full).

        Returns an empty dict if nothing is on disk.
        """
        unified_path = self._unified_cache_path()

        # Fast path — unified cache already exists
        if unified_path.exists():
            try:
                payload = json.loads(unified_path.read_text())
                entries = payload.get("entries", {})
                # Support both shapes: dict (new) and list (very old / partial
                # manual edit). List form gets converted to dict on load.
                if isinstance(entries, list):
                    entries = {
                        e["cve_id"]: e for e in entries
                        if isinstance(e, dict) and e.get("cve_id")
                    }
                    logger.info(
                        f"NVD: converted list-form unified cache to dict "
                        f"({len(entries)} entries)"
                    )
                logger.debug(f"NVD unified cache loaded: {len(entries)} entries")
                return entries
            except Exception as e:
                logger.warning(
                    f"NVD: unified cache at {unified_path} is corrupt ({e}); "
                    f"starting from empty cache"
                )
                return {}

        # Migration path — load legacy profile files if present
        migrated: dict[str, dict] = {}
        for profile in ALLOWED_PROFILES:
            legacy_path = self.cache_dir / f"nvd_cache_{profile}.json"
            if not legacy_path.exists():
                continue
            try:
                payload = json.loads(legacy_path.read_text())
                legacy_entries = payload.get("entries", [])
                if not isinstance(legacy_entries, list):
                    continue
                # Merge keyed by cve_id
                for entry in legacy_entries:
                    if isinstance(entry, dict) and entry.get("cve_id"):
                        migrated[entry["cve_id"]] = entry
                logger.info(
                    f"NVD migration: loaded {len(legacy_entries)} entries "
                    f"from legacy {legacy_path.name}"
                )
            except Exception as e:
                logger.warning(
                    f"NVD migration: failed to read {legacy_path.name}: {e}"
                )

        if migrated:
            logger.info(
                f"NVD migration: merged {len(migrated)} unique entries from "
                f"legacy profile files → {unified_path.name}"
            )

        return migrated

    def _write_unified_cache(self, entries_by_id: dict[str, dict]) -> None:
        """
        Atomically write the unified cache dict to disk.

        File structure:
            {
              "schema_version": 1,
              "fetched_at": "2026-04-08T12:00:00Z",
              "count": 70842,
              "entries": {
                "CVE-2024-12345": {...},
                ...
              }
            }
        """
        payload = {
            "schema_version": 1,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "count": len(entries_by_id),
            "entries": entries_by_id,
        }
        atomic_write_json(self._unified_cache_path(), payload)
        logger.debug(
            f"NVD unified cache written: {self._unified_cache_path()} "
            f"({len(entries_by_id)} entries)"
        )

    def _cleanup_legacy_profile_files(self) -> None:
        """Delete legacy ``nvd_cache_{standard,full}.json`` files after the
        unified cache has been successfully written."""
        # 1. Legacy profile split files
        for profile in ALLOWED_PROFILES:
            legacy = self.cache_dir / f"nvd_cache_{profile}.json"
            if legacy.exists():
                try:
                    legacy.unlink()
                    logger.info(f"NVD: removed legacy profile cache {legacy.name}")
                except OSError as e:
                    logger.warning(f"NVD: could not remove {legacy.name}: {e}")

        # 2. Pre-fixed-name files (nvd_standard_7441.json etc.)
        for profile in ALLOWED_PROFILES:
            legacy_pattern = re.compile(rf"^nvd_{re.escape(profile)}_\d+\.json$")
            for stale in self.cache_dir.glob(f"nvd_{profile}_*.json"):
                if legacy_pattern.match(stale.name):
                    try:
                        stale.unlink()
                        logger.info(f"NVD: removed stale cache file {stale.name}")
                    except OSError as e:
                        logger.warning(f"NVD: could not remove {stale.name}: {e}")

        # 3. Dead .checkpoint file (unused counter dict)
        dead_checkpoint = self.cache_dir / ".checkpoint"
        if dead_checkpoint.exists():
            try:
                content = dead_checkpoint.read_text()
                if '"HIGH"' in content or '"CRITICAL"' in content or content.strip() == "":
                    dead_checkpoint.unlink()
                    logger.info("NVD: removed dead cache/nvd/.checkpoint")
            except OSError as e:
                logger.warning(f"NVD: could not inspect/remove .checkpoint: {e}")

    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """Convert NVD CVE data to chunks. One chunk per CVE."""
        chunks = []
        for cve in raw_data:
            cve_id = cve.get("cve_id", "")
            description = cve.get("description", "")
            cvss_score = cve.get("cvss_score")
            severity = cve.get("severity", "")
            products = cve.get("affected_products", [])
            content = description
            if cvss_score is not None:
                content += f"\nCVSS: {cvss_score} ({severity})"
            if products:
                content += f"\nAffected: {', '.join(products[:10])}"

            chunk_id = ChunkStrategy.generate_chunk_id(self.SOURCE, cve_id)
            chunks.append({
                "chunk_id": chunk_id,
                "content": content,
                "title": cve_id,
                "source": self.SOURCE,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "affected_products": products[:20],
                "published_date": cve.get("published_date"),
                "source_path": cve.get("source_path", ""),
            })

        logger.info(f"Created {len(chunks)} NVD chunks")
        return chunks

    def _normalize_cve(self, vuln: dict) -> dict | None:
        """Normalize a NVD API v2.0 vulnerability entry."""
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Description (English)
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS v3
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        severity = ""
        for cvss_key in ["cvssMetricV31", "cvssMetricV30"]:
            cvss_list = metrics.get(cvss_key, [])
            if cvss_list:
                cvss_data = cvss_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "").lower()
                break

        # Affected products (CPE matches)
        products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        products.append(criteria)

        published = cve_data.get("published", "")
        published_date = published[:10] if published else None

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "affected_products": products,
            "published_date": published_date,
        }

    def _date_windows(
        self, start: datetime = None, end: datetime = None
    ) -> list[tuple[datetime, datetime]]:
        """
        Split a date range into 120-day windows (NVD API limit).

        Returns [(window_start, window_end), ...].
        If no dates provided, returns a single window with no date filtering.
        """
        if start is None or end is None:
            # No date range — single pass without date params
            return [(datetime(1999, 1, 1, tzinfo=timezone.utc),
                     datetime.now(timezone.utc))]

        windows = []
        current = start
        while current < end:
            window_end = min(current + timedelta(days=MAX_DATE_RANGE_DAYS), end)
            windows.append((current, window_end))
            current = window_end
        return windows
