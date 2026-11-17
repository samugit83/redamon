"""One ingestion job on the fixture sites, the memory store and a scripted model, for the phase 6
tests (real titles, the archive, logins, incremental refresh, curation, content checks).

``JobHarness(...).run()`` runs ``pipeline.run`` once; ``refresh()`` starts the next job on the same
store (a second generation over the first), as a person's Refresh does. Not a test module.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from tradecraft import net
from tradecraft.contract import JobContext, JobStartRequest
from tradecraft.ingest import pipeline
from tradecraft.settings import EffectiveSettings
from tradecraft_doubles import FixtureFetcher
from tradecraft_memory_store import MemoryStore, PipelineModel, padded_sites

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER, RID = "u1", "r1"


class JobHarness:
    def __init__(self, tmp_path: Any, url: str, *, mode: str = "live", settings: Optional[dict] = None,
                 model: Any = None, root: Any = None, fetcher: Any = None, resource: Optional[dict] = None,
                 secrets: Optional[dict] = None, store: Optional[MemoryStore] = None, model_id: str = "openai/fake-small-model"):
        self.url, self.mode = url, mode
        self.settings = dict(settings or {})
        self.resource_spec = dict(resource or {})
        self.secrets = secrets or {"github_token": None, "credentials": None}
        self.model = model if model is not None else PipelineModel()
        self.model_id = model_id
        self.fetcher = fetcher or FixtureFetcher(root or padded_sites(tmp_path))
        self.store = store or MemoryStore()
        if RID not in self.store.resources:
            self.store.add_resource(OWNER, RID, url=url, storage_mode=mode, generation=0)
        self.settings_hash: Optional[str] = None
        self.stages: list = []
        self.jobs = 0
        self.outcome: Any = None

    def request(self, job_id: str) -> JobStartRequest:
        spec = json.loads(json.dumps(FIXTURE))
        spec.update(job_id=job_id, user_id=OWNER, actor_user_id=OWNER, resource_id=RID, settings=dict(self.settings))
        spec["resource"].update(url=self.url, storage_mode=self.mode, model=self.model_id, **self.resource_spec)
        spec["secrets"] = self.secrets
        if self.settings_hash:
            spec["settings_hash"] = self.settings_hash
        return JobStartRequest.model_validate(spec)

    async def _set_stage(self, stage: str, progress: Any = None) -> None:
        self.stages.append(stage)

    async def _not_cancelled(self) -> bool:
        return False

    def run(self) -> Any:
        self.jobs += 1
        job_id = f"job-{self.jobs}"
        self.store.add_job(OWNER, RID, job_id, status="running")
        gen = max([self.store.resources[RID]["generation"]] + [e["generation"] for e in self.store.entries]) + 1
        self.store.jobs[job_id]["target_generation"] = gen
        request = self.request(job_id)

        async def build_llm(owner: str, model: str) -> Any:
            assert owner == OWNER
            return self.model

        ctx = JobContext(request=request, settings=EffectiveSettings(request.settings), target_generation=gen,
                         is_cancelled=self._not_cancelled, set_stage=self._set_stage)
        with net.use_fetcher(self.fetcher):
            self.outcome = asyncio.run(pipeline.run(ctx, store=self.store, build_llm=build_llm))
        return self.outcome

    refresh = run

    @property
    def row(self) -> dict:
        return self.store.resources[RID]

    def live(self) -> list[dict]:
        return self.store.live_entries(RID)

    def live_by_url(self) -> dict[str, dict]:
        return {e["url"]: e for e in self.live()}

    def requested(self) -> list[str]:
        return [u for u, _h in self.fetcher.requests]
