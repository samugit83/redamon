"""An in-memory page store with the answers of ``tradecraft.store.Store``, and two helpers the
ingestion tests share (fixture sites with full start pages, a model for the pipeline).

The unit tests of the job runner, the pipeline and the reader run against ``MemoryStore``; the
same behaviours on a real Postgres are held by ``test_tradecraft_store_integration.py`` and the
other ``_integration`` files. Every method takes the owner like the real one, and a read for
another owner answers nothing. Not a test module (no ``test_`` prefix).
"""

from __future__ import annotations

import copy
import itertools
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from tradecraft.library.page_ids import PageIdRow
from tradecraft.store import (CARRIED_FROM_PREVIOUS, CARRY_WRITE, ENTRY_WRITE, REFRESH_BASIS, SECTION_WRITE,
                              SUMMARY_COLUMNS, SWAP_COLUMNS, TREE_WRITE, ResourceGone, _rows_for, summary_is_kept)

UNFINISHED = ("queued", "running")


def _now():
    return datetime.now(timezone.utc)


class MemoryStore:
    def __init__(self) -> None:
        self.resources: dict[str, dict] = {}
        self.jobs: dict[str, dict] = {}
        self.page_ids: dict[tuple[str, str], int] = {}
        self.entries: list[dict] = []
        self.sections: list[dict] = []
        self.tree: list[dict] = []
        self.curations: list[dict] = []
        self.calls: list[tuple[str, tuple]] = []
        self.writes = 0
        self._ids = itertools.count(1)
        self._page_numbers = itertools.count(1)

    # --- seeding ------------------------------------------------------------------

    def add_resource(self, user_id: str, resource_id: str, *, url: str = "https://wiki.tc-fixture.test/",
                     slug: str = "wiki", storage_mode: str = "live", **cols: Any) -> dict:
        row = {"id": resource_id, "user_id": user_id, "url": url, "slug": slug, "name": slug,
               "storage_mode": storage_mode, "generation": 0, "active_job_id": None, "summary": "",
               "summary_source": "generated", "summary_locked": False, "sitemap": {}, "resource_type": "agentic-crawl",
               "map_version": 1, "last_error": "", "crawl_stats": {}, "crawl_stopped_because": "",
               "settings_snapshot": {}, "settings_hash": "", "ingestion_report": {}, "legacy_map_hash": "",
               "last_verified_at": None, "last_refreshed_at": None, "has_login": False, "enabled": True}
        row.update(cols)
        self.resources[resource_id] = row
        return row

    def add_job(self, user_id: str, resource_id: str, job_id: str, *, claim: bool = True,
                lease_until: Any = "far", status: str = "queued") -> dict:
        job = {"id": job_id, "user_id": user_id, "resource_id": resource_id, "status": status,
               "cancel_requested": False, "lease_until": lease_until, "owner_instance": "", "stage": "",
               "progress": {}, "error_code": "", "target_generation": 0}
        self.jobs[job_id] = job
        if claim and resource_id in self.resources:
            self.resources[resource_id]["active_job_id"] = job_id
        return job

    def delete_resource(self, resource_id: str) -> None:
        """The cascade of the real schema."""
        self.resources.pop(resource_id, None)
        self.jobs = {k: j for k, j in self.jobs.items() if j["resource_id"] != resource_id}
        self.page_ids = {k: v for k, v in self.page_ids.items() if k[0] != resource_id}
        self.entries = [e for e in self.entries if e["resource_id"] != resource_id]
        self.sections = [s for s in self.sections if s["resource_id"] != resource_id]
        self.tree = [t for t in self.tree if t["resource_id"] != resource_id]
        self.curations = [c for c in self.curations if c["resource_id"] != resource_id]

    def _log(self, name: str, *args: Any) -> None:
        self.calls.append((name, args))

    def names(self) -> list[str]:
        return [n for n, _ in self.calls]

    def _res(self, user_id: str, resource_id: str) -> Optional[dict]:
        r = self.resources.get(resource_id)
        return r if r is not None and r["user_id"] == user_id else None

    def _job(self, user_id: str, job_id: str) -> Optional[dict]:
        j = self.jobs.get(job_id)
        return j if j is not None and j["user_id"] == user_id else None

    def _claimed(self, job: dict) -> bool:
        r = self.resources.get(job["resource_id"])
        return r is not None and r["user_id"] == job["user_id"] and r["active_job_id"] == job["id"]

    # --- jobs ---------------------------------------------------------------------

    async def accept_job(self, user_id, job_id, instance, lease_until):
        self._log("accept_job", user_id, job_id)
        j = self._job(user_id, job_id)
        if j is None or j["status"] != "queued" or not self._claimed(j):
            return False
        j.update(owner_instance=instance, lease_until=lease_until)
        return True

    async def claim_job_for_run(self, user_id, job_id, instance, lease_until):
        self._log("claim_job_for_run", user_id, job_id)
        j = self._job(user_id, job_id)
        if j is None or j["status"] != "queued" or j["owner_instance"] != instance or not self._claimed(j):
            return False
        j.update(status="running", lease_until=lease_until)
        return True

    async def renew_leases(self, instance, until, held):
        self._log("renew_leases", instance, tuple(held))
        out = set()
        for user_id, job_id in held:
            j = self._job(user_id, job_id)
            if j and j["owner_instance"] == instance and j["status"] in UNFINISHED:
                j["lease_until"] = until
                out.add(job_id)
        return out

    async def cancel_requested(self, user_id, job_id):
        j = self._job(user_id, job_id)
        return j is None or bool(j["cancel_requested"]) or j["status"] not in UNFINISHED

    async def request_cancel(self, user_id, job_id):
        self._log("request_cancel", user_id, job_id)
        j = self._job(user_id, job_id)
        if j and j["status"] in UNFINISHED:
            j["cancel_requested"] = True
            return True
        return False

    async def request_cancel_user(self, user_id):
        self._log("request_cancel_user", user_id)
        ids = []
        for j in self.jobs.values():
            if j["user_id"] == user_id and j["status"] in UNFINISHED:
                j["cancel_requested"] = True
                ids.append(j["id"])
        return ids

    async def set_job_stage(self, user_id, job_id, stage, progress=None):
        self._log("set_job_stage", user_id, job_id, stage, dict(progress or {}))
        j = self._job(user_id, job_id)
        if j and j["status"] == "running":
            j.update(stage=stage, progress=copy.deepcopy(dict(progress or {})))
            return True
        return False

    async def finish_job(self, user_id, job_id, status, error_code=""):
        self._log("finish_job", user_id, job_id, status, error_code)
        j = self._job(user_id, job_id)
        finished = False
        if j and j["status"] in UNFINISHED:
            j.update(status=status, error_code=error_code, lease_until=None)
            finished = True
        for r in self.resources.values():
            if r["user_id"] == user_id and r["active_job_id"] == job_id:
                r["active_job_id"] = None
        return finished

    async def fail_expired_leases(self, now, error_code="agent_restarted"):
        self._log("fail_expired_leases", now, error_code)
        out = []
        for j in self.jobs.values():
            lease = j["lease_until"]
            expired = lease is None or (lease != "far" and lease < now)
            if j["status"] in UNFINISHED and expired:
                j.update(status="failed", error_code=error_code, lease_until=None)
                r = self.resources.get(j["resource_id"])
                if r and r["active_job_id"] == j["id"]:
                    r.update(active_job_id=None, last_error=error_code,
                             last_verified_at=r.get("last_verified_at") or now)
                out.append({"id": j["id"], "user_id": j["user_id"], "resource_id": j["resource_id"],
                            "target_generation": j["target_generation"]})
        return out

    async def begin_generation(self, user_id, resource_id, job_id):
        self._log("begin_generation", user_id, resource_id, job_id)
        j, r = self._job(user_id, job_id), self._res(user_id, resource_id)
        if j is None or r is None or j["status"] != "running" or r["active_job_id"] != job_id:
            return None
        used = [r["generation"]] + [x["target_generation"] for x in self.jobs.values() if x["resource_id"] == resource_id]
        used += [e["generation"] for e in self.entries if e["resource_id"] == resource_id]
        j["target_generation"] = max(used) + 1
        return j["target_generation"]

    # --- the resource ---------------------------------------------------------------

    async def resource(self, user_id, resource_id):
        r = self._res(user_id, resource_id)
        return {k: v for k, v in r.items() if k != "sitemap"} if r else None

    async def legacy_sitemap(self, user_id, resource_id):
        r = self._res(user_id, resource_id)
        if r is None:
            return None
        return {k: r.get(k) for k in ("id", "slug", "url", "resource_type", "sitemap", "map_version",
                                      "storage_mode", "has_login", "generation")}

    async def set_last_error(self, user_id, resource_id, job_id, code, at):
        self._log("set_last_error", user_id, resource_id, job_id, code)
        r = self._res(user_id, resource_id)
        if r and r["active_job_id"] == job_id:
            r.update(last_error=code, last_verified_at=at)
            return True
        return False

    async def set_error_without_fetch(self, user_id, resource_id, job_id, code, at):
        self._log("set_error_without_fetch", user_id, resource_id, job_id, code)
        r = self._res(user_id, resource_id)
        if r and r["active_job_id"] == job_id:
            r.update(last_error=code, last_verified_at=r.get("last_verified_at") or at)
            return True
        return False

    async def set_error_if_never_verified(self, user_id, resource_id, job_id, code, at):
        self._log("set_error_if_never_verified", user_id, resource_id, job_id, code)
        r = self._res(user_id, resource_id)
        if r and r["active_job_id"] == job_id and r.get("last_verified_at") is None:
            r.update(last_error=code, last_verified_at=at)
            return True
        return False

    async def swap(self, user_id, resource_id, job_id, generation, expected_url, expected_storage_mode, updates,
                   *, status="succeeded", error_code=""):
        self._log("swap", user_id, resource_id, job_id, generation, dict(updates), status, error_code)
        unknown = set(updates) - set(SWAP_COLUMNS)
        if unknown:
            raise ValueError(f"a swap cannot write {sorted(unknown)}")
        r = self._res(user_id, resource_id)
        if r is None:
            return "gone"
        if r["active_job_id"] != job_id:
            return "lost"
        if r["url"] != expected_url or r["storage_mode"] != expected_storage_mode:
            return "changed"
        if summary_is_kept(r):
            updates = {k: v for k, v in updates.items() if k not in SUMMARY_COLUMNS}
        r.update(copy.deepcopy(dict(updates)))
        r.update(generation=generation, active_job_id=None)
        j = self._job(user_id, job_id)
        if j:
            j.update(status=status, error_code=error_code, stage="swap", lease_until=None)
        return "swapped"

    # --- writes ---------------------------------------------------------------------

    async def allocate_page_ids(self, user_id, resource_id, urls):
        if self._res(user_id, resource_id) is None:
            raise ResourceGone(resource_id)
        out = {}
        for url in urls:
            key = (resource_id, url)
            if key not in self.page_ids:
                self.page_ids[key] = next(self._page_numbers)
            out[url] = self.page_ids[key]
        return out

    def _check(self, user_id, resource_id):
        if self._res(user_id, resource_id) is None:
            raise ResourceGone(resource_id)
        self.writes += 1

    async def write_entries(self, user_id, resource_id, generation, entries):
        self._check(user_id, resource_id)
        out = {}
        own_pages = {v for (rid, _u), v in self.page_ids.items() if rid == resource_id}
        for row in _rows_for(ENTRY_WRITE, entries):
            if row["page_id"] not in own_pages:
                raise ValueError("write_entries: a page of another resource")
            entry = dict(row, id=next(self._ids), user_id=user_id, resource_id=resource_id, generation=generation)
            self.entries.append(entry)
            out[row["page_id"]] = entry["id"]
        return out

    async def write_sections(self, user_id, resource_id, generation, sections):
        self._check(user_id, resource_id)
        rows = _rows_for(SECTION_WRITE, sections)
        for row in rows:
            self.sections.append(dict(row, id=next(self._ids), user_id=user_id, resource_id=resource_id,
                                      generation=generation))
        return len(rows)

    async def write_tree(self, user_id, resource_id, generation, nodes):
        self._check(user_id, resource_id)
        rows = _rows_for(TREE_WRITE, nodes)
        for row in rows:
            self.tree.append(dict(row, id=next(self._ids), user_id=user_id, resource_id=resource_id,
                                  generation=generation))
        return len(rows)

    # --- incremental refresh (T6.2) -------------------------------------------------------

    async def refresh_basis(self, user_id, resource_id):
        self._log("refresh_basis", user_id, resource_id)
        return [{k: copy.deepcopy(e.get(k)) for k in REFRESH_BASIS} for e in self.entries
                if e["user_id"] == user_id and e["resource_id"] == resource_id and self._live(e)
                and e.get("stored_text") is not None and e.get("text_hash")]

    async def copy_forward(self, user_id, resource_id, from_generation, to_generation, cards):
        self._check(user_id, resource_id)
        rows = _rows_for(CARRY_WRITE, cards)
        self._log("copy_forward", user_id, resource_id, from_generation, to_generation, [r["page_id"] for r in rows])
        out = {}
        for row in rows:
            old = next((e for e in self.entries if e["user_id"] == user_id and e["resource_id"] == resource_id
                        and e["generation"] == from_generation and e["page_id"] == row["page_id"]
                        and e["url"] == row["url"]), None)
            if old is None or to_generation == from_generation:
                raise ValueError("copy_forward: a row names no page of the generation")
            entry = dict(row, id=next(self._ids), user_id=user_id, resource_id=resource_id, generation=to_generation)
            for k in CARRIED_FROM_PREVIOUS:
                entry[k] = old.get(k)
            for k in ("etag", "last_modified"):
                entry[k] = row.get(k) or old.get(k, "")
            self.entries.append(entry)
            out[row["page_id"]] = entry["id"]
            for sec in [x for x in self.sections if x["entry_id"] == old["id"]]:
                self.sections.append(dict(sec, id=next(self._ids), entry_id=entry["id"], generation=to_generation))
        return out

    # --- totals and purge -------------------------------------------------------------

    def _live(self, e: dict) -> bool:
        r = self.resources.get(e["resource_id"])
        return r is not None and r["user_id"] == e["user_id"] and e["generation"] == r["generation"]

    async def user_stored_bytes(self, user_id, exclude_resource_id=None):
        return sum(e["stored_bytes"] for e in self.entries
                   if e["user_id"] == user_id and self._live(e) and e["resource_id"] != exclude_resource_id)

    async def instance_stored_bytes(self):
        return sum(e["stored_bytes"] for e in self.entries if self._live(e))

    def _being_written(self, resource_id: str) -> set:
        return {j["target_generation"] for j in self.jobs.values()
                if j["resource_id"] == resource_id and j["status"] in UNFINISHED}

    async def purge_old_generations(self, user_id, resource_id, batch=5000):
        self._log("purge_old_generations", user_id, resource_id)
        r = self._res(user_id, resource_id)
        if r is None:
            return 0
        keep = {r["generation"]} | self._being_written(resource_id)
        return self._drop(resource_id, lambda g: g not in keep)

    async def discard_generation(self, user_id, resource_id, generation, batch=5000):
        self._log("discard_generation", user_id, resource_id, generation)
        r = self._res(user_id, resource_id)
        if r is None or generation <= 0 or generation == r["generation"]:
            return 0
        return self._drop(resource_id, lambda g: g == generation)

    def _drop(self, resource_id, gone) -> int:
        before = len(self.entries) + len(self.sections) + len(self.tree)
        self.sections = [s for s in self.sections if not (s["resource_id"] == resource_id and gone(s["generation"]))]
        self.tree = [t for t in self.tree if not (t["resource_id"] == resource_id and gone(t["generation"]))]
        self.entries = [e for e in self.entries if not (e["resource_id"] == resource_id and gone(e["generation"]))]
        return before - len(self.entries) - len(self.sections) - len(self.tree)

    # --- reads ------------------------------------------------------------------------

    async def entry_by_url(self, user_id, resource_id, url):
        self._log("entry_by_url", user_id, resource_id, url)
        for e in self.entries:
            if e["user_id"] == user_id and e["resource_id"] == resource_id and e["url"] == url and self._live(e):
                return dict(e)
        return None

    async def entry_by_page_id(self, user_id, page_id):
        for e in self.entries:
            if e["user_id"] == user_id and e["page_id"] == page_id and self._live(e):
                return dict(e)
        return None

    async def in_map(self, user_id, resource_id, url):
        return await self.entry_by_url(user_id, resource_id, url) is not None

    async def curation(self, user_id, resource_id, url):
        if self._res(user_id, resource_id) is None:
            return None
        for c in self.curations:
            if c["resource_id"] == resource_id and c["url"] == url:
                return dict(c)
        return None

    async def lookup_page_id(self, owner_id, page_number):
        for (rid, url), n in self.page_ids.items():
            r = self.resources.get(rid)
            if n == page_number and r and r["user_id"] == owner_id:
                return PageIdRow(resource_id=rid, url=url)
        return None

    async def min_page_id(self, owner_id, resource_id):
        if self._res(owner_id, resource_id) is None:
            return None
        nums = [n for (rid, _u), n in self.page_ids.items() if rid == resource_id]
        return min(nums) if nums else None

    # --- helpers for tests ---------------------------------------------------------

    def live_entries(self, resource_id: str) -> list[dict]:
        return [e for e in self.entries if e["resource_id"] == resource_id and self._live(e)]

    def snapshot_counts(self) -> dict:
        return {"entries": len(self.entries), "sections": len(self.sections), "tree": len(self.tree),
                "page_ids": len(self.page_ids), "writes": self.writes,
                "resources": copy.deepcopy(self.resources)}


def iter_names(calls: Iterable[tuple[str, tuple]]) -> list[str]:
    return [n for n, _ in calls]


# ---------------------------------------------------------------------------------------
# Fixture sites with full start pages
# ---------------------------------------------------------------------------------------

ARTICLE = ("<article><h1>About this library</h1>" + "<p>" + " ".join(
    ["Synthetic offensive security notes for tests: payloads, techniques and tool commands."] * 12)
    + "</p></article>")

# The start pages of the generated fixture sites hold under 500 characters of text, so 1.x
# (and 2.0 with its defaults) would call each one thin and crawl it as a website. A real
# wiki's start page has an article: these copies get one, so detection sees what it would.
PADDED_HOMES = (
    "wiki.tc-fixture.test/index.html", "docs.tc-fixture.test/index.html", "book.tc-fixture.test/index.html",
    "blog.tc-fixture.test/index.html", "github.com/tc-fixture/payloads/index.html",
    "github.com/tc-fixture/cve/index.html",
)


def padded_sites(tmp_path):
    """A copy of the fixture sites whose start pages carry an article; returns its root."""
    import shutil
    from pathlib import Path as _P
    src = _P(__file__).resolve().parent / "fixtures" / "tradecraft_sites"
    root = _P(tmp_path) / "sites"
    shutil.copytree(src, root)
    for rel in PADDED_HOMES:
        page = root / rel
        page.write_text(page.read_text().replace("</body>", ARTICLE + "</body>", 1))
    return root


class PipelineModel:
    """Answers the crawl's decisions (``follow`` the first ``follow`` links once, then stop) and
    every other prompt with a summary; records each prompt."""

    def __init__(self, follow=0, summary="A synthetic library of offensive techniques and payloads."):
        self.follow, self.summary = follow, summary
        self.prompts: list = []

    async def ainvoke(self, messages, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        self.prompts.append(messages)
        text = messages if isinstance(messages, str) else ""
        if "Reply ONLY with JSON" in text:
            if self.follow:
                n, self.follow = self.follow, 0
                return AIMessage(content='{"action": "follow", "indices": [' + ",".join(map(str, range(1, n + 1))) + '], "reason": "x"}')
            return AIMessage(content='{"action": "stop", "reason": "enough"}')
        return AIMessage(content=self.summary)

    @property
    def summary_prompts(self):
        return [m for m in self.prompts if not isinstance(m, str)]
