"""
On-demand local LLM (Ollama) lifecycle manager for the AI Attack Surface layer.

`redamon-local-llm` is the judge/attacker model used by the AI Attack Surface
scan tools (garak judge detectors, PyRIT attacker, giskard/promptfoo graders).
It is NOT an always-on docker-compose service: it is spawned on demand when an
AI-attack job needs it and torn down when the last job finishes, exactly like
the on-demand tool containers in container_manager.py (start_gvm_scan, etc.).

Design (see AI_ATTACK_SURFACE_IMPLEMENTATION.md §15.2):
  - Ref-counted lease: ensure_up() acquires, release() frees. The container is
    removed only when the lease count returns to zero (shared across the N
    per-tool jobs of one scan).
  - Weights persist, container does not: models live in the named volume
    `redamon_llm_models` (-> /root/.ollama). Start cost is load-into-RAM, not a
    re-download. First-ever launch pulls the judge model into the volume.
  - Networking: spawned on the shared bridge network with its port published on
    the host's loopback only. The orchestrator reaches it by container DNS
    (http://redamon-local-llm:11434); host-network scan containers reach the
    published port via loopback (http://localhost:11434).
  - Failure-soft: any failure (image pull, container start, readiness, model
    pull) yields an unavailable status object and never raises to the caller,
    so a scan degrades to no-judge probes instead of blocking (§9).

Uses only the stdlib (urllib) + the docker SDK, both already in the
recon-orchestrator image -- no new dependencies.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

import docker
from docker.errors import APIError, ImageNotFound, NotFound

logger = logging.getLogger(__name__)


# --- Configuration (env-overridable; defaults recorded in the run envelope) ---

# Ollama image. Pinned via env for reproducibility (§9); a floating default
# keeps first-run setup zero-touch.
LLM_IMAGE = os.environ.get("LOCAL_LLM_IMAGE", "ollama/ollama:latest")
# Judge/attacker model. §12.4 open question (llama3.1-8b vs qwen2.5-7b) is
# settled by env until the offline benchmark locks it.
LLM_MODEL = os.environ.get("LOCAL_LLM_MODEL", "qwen2.5:7b")
LLM_CONTAINER_NAME = os.environ.get("LOCAL_LLM_CONTAINER_NAME", "redamon-local-llm")
LLM_MODELS_VOLUME = os.environ.get("LOCAL_LLM_VOLUME", "redamon_llm_models")
# Phase 7: the Ollama judge ran with NO mem_limit, so a model load could balloon
# past what the governor assumed was free and OOM the host. Cap it (Docker mem_limit
# string, e.g. "8g"). Empty/"0"/"none" disables the cap (GPU or a very large judge
# model). Must comfortably hold the LOCAL_LLM_MODEL in CPU mode; raise for bigger.
def _default_llm_mem() -> str:
    """Ollama's ceiling, sized from the host rather than a flat 8g.

    8g was right for a 16-32 GB workstation and wrong everywhere else: on an 8 GB
    host it promised the entire machine, and on a 128 GB one it needlessly capped
    a judge model that had room to spare. Take a share of the SCAN POOL, since
    the judge is on-demand work like a scan, not an always-on service. Floors at
    4g so a small model still loads; falls back to 8g when /proc is unreadable
    (same fail-open contract as the rest of the governor).
    """
    try:
        import resource_governor as _rg
        mem = _rg.read_mem()
        if not mem or mem[0] <= 0:
            return "8g"
        # scan pool ~= 32% of host (redamon.sh: (1 - OS_RESERVE_PCT) x (1 - SERVICES_PCT));
        # the judge may claim half of it.
        gb = max(4, (mem[0] * 16 // 100) // (1024 ** 3))
        return f"{gb}g"
    except Exception:
        return "8g"


LLM_MEM_LIMIT = (os.environ.get("LOCAL_LLM_MEM") or _default_llm_mem()).strip()
LLM_PORT = int(os.environ.get("LOCAL_LLM_PORT", "11434"))
# Ollama's API has no authentication: whoever reaches it can rewrite, pull or
# delete the judge model, and the weights volume outlives the container. So the
# port is published on the host's loopback only, never on every interface:
# Docker's own iptables rules bypass ufw, and the deploy overlay cannot re-bind
# a port published through the SDK. Deliberately not an env knob.
LLM_PUBLISH_HOST = "127.0.0.1"
# Ollama is spawned on the shared bridge network and publishes its port to the
# host's loopback. Two consumers reach it two different ways:
#   - The orchestrator (this process) is ON the bridge network, so it reaches
#     Ollama by container DNS name: http://redamon-local-llm:11434
#   - Future AI-attack scan containers run on the HOST network, so they reach
#     the published port via loopback: http://localhost:11434
LLM_NETWORK = os.environ.get("LOCAL_LLM_NETWORK", "redamon-network")
# How the orchestrator itself talks to Ollama (container DNS on the shared net).
LLM_INTERNAL_HOST = os.environ.get("LOCAL_LLM_INTERNAL_HOST", LLM_CONTAINER_NAME)
LLM_INTERNAL_URL = f"http://{LLM_INTERNAL_HOST}:{LLM_PORT}"
# How host-network scan jobs talk to Ollama (published port via loopback).
LLM_SCAN_HOST = os.environ.get("LOCAL_LLM_SCAN_HOST", "localhost")
LLM_SCAN_URL = f"http://{LLM_SCAN_HOST}:{LLM_PORT}"

# Optional GPU passthrough (CPU by default; works everywhere). Set to "1"/"true"
# to request all GPUs from the Docker daemon.
LLM_USE_GPU = os.environ.get("LOCAL_LLM_GPU", "").lower() in ("1", "true", "yes")

READY_TIMEOUT_S = int(os.environ.get("LOCAL_LLM_READY_TIMEOUT", "120"))
READY_POLL_INTERVAL_S = float(os.environ.get("LOCAL_LLM_READY_POLL_INTERVAL", "2"))
# Model pull can be a multi-minute download on first ever launch.
PULL_TIMEOUT_S = int(os.environ.get("LOCAL_LLM_PULL_TIMEOUT", "1800"))


def _model_matches(present_names: list[str], model: str) -> bool:
    """True if `model` is among `present_names`, matching on the model-name
    segment (the part before the tag). An exact id matches; so does any other
    tag of the same model name. We compare the name segment exactly rather than
    by prefix so e.g. `llama3` does not spuriously match `llama3.1:8b`.
    """
    base = model.split(":")[0]
    return any(m == model or m.split(":")[0] == base for m in present_names)


@dataclass
class LocalLlmStatus:
    """Snapshot of the local-LLM service state, returned to callers/API."""
    available: bool = False
    running: bool = False
    container_id: str | None = None
    base_url: str = LLM_SCAN_URL
    model: str = LLM_MODEL
    model_present: bool = False
    leases: int = 0
    models: list[str] = field(default_factory=list)
    warning: str | None = None

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "running": self.running,
            "containerId": self.container_id,
            "baseUrl": self.base_url,
            "model": self.model,
            "modelPresent": self.model_present,
            "leases": self.leases,
            "models": self.models,
            "warning": self.warning,
        }


class LocalLlmManager:
    """Ref-counted, failure-soft lifecycle for the on-demand Ollama judge."""

    def __init__(self, client: docker.DockerClient | None = None):
        # Reuse the orchestrator's docker client when provided.
        self.client = client or docker.from_env()
        # Guards the lease counter only (short critical sections).
        self._lock = threading.RLock()
        # Serializes container bring-up so concurrent ensure_up() calls (the N
        # tools of one scan share one judge) never race on containers.run() and
        # never pull the same model twice. Separate from _lock so status() /
        # release() never block behind a multi-minute model pull.
        self._bringup_lock = threading.Lock()
        self._leases = 0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def ensure_up(self, model: str | None = None) -> LocalLlmStatus:
        """Acquire a lease and ensure Ollama is running with the model pulled.

        Always returns a status; never raises. On any failure the status has
        available=False and a warning, so the caller can degrade to no-judge.
        """
        model = model or LLM_MODEL
        with self._lock:
            self._leases += 1
            lease_count = self._leases

        try:
            # Serialize bring-up: only one thread creates the container and
            # pulls the model; the rest find it already running and proceed.
            with self._bringup_lock:
                self._ensure_container()
                ready = self._wait_ready(READY_TIMEOUT_S)
                if not ready:
                    return self._unavailable(
                        f"Ollama did not become ready within {READY_TIMEOUT_S}s",
                        leases=lease_count,
                    )
                model_present = self._ensure_model(model)
                models = self._list_models()
            return LocalLlmStatus(
                available=model_present,
                running=True,
                container_id=self._container_id(),
                model=model,
                model_present=model_present,
                leases=lease_count,
                models=models,
                warning=None if model_present else f"Model {model} unavailable; degrade to no-judge",
            )
        except Exception as e:  # failure-soft: never propagate
            logger.warning(f"local-llm ensure_up failed: {e}")
            return self._unavailable(str(e), leases=lease_count)

    def release(self) -> LocalLlmStatus:
        """Release one lease; tear the container down when the count hits zero."""
        with self._lock:
            if self._leases > 0:
                self._leases -= 1
            lease_count = self._leases

        if lease_count > 0:
            logger.info(f"local-llm lease released; {lease_count} still active, keeping container")
            return self.status()

        # Last lease gone -> stop + remove the container (the volume persists).
        try:
            container = self.client.containers.get(LLM_CONTAINER_NAME)
            container.stop(timeout=10)
            container.remove()
            logger.info("local-llm: last lease released, container stopped + removed (weights volume kept)")
        except NotFound:
            pass
        except Exception as e:
            logger.warning(f"local-llm teardown failed: {e}")

        return LocalLlmStatus(available=False, running=False, leases=0)

    def status(self) -> LocalLlmStatus:
        """Best-effort current state without changing the lease count."""
        with self._lock:
            lease_count = self._leases
        running = self._is_running()
        models = self._list_models() if running else []
        model_present = _model_matches(models, LLM_MODEL)
        return LocalLlmStatus(
            available=running and model_present,
            running=running,
            container_id=self._container_id() if running else None,
            model=LLM_MODEL,
            model_present=model_present,
            leases=lease_count,
            models=models,
        )

    def shutdown(self) -> None:
        """Force teardown regardless of leases (orchestrator cleanup)."""
        with self._lock:
            self._leases = 0
        try:
            container = self.client.containers.get(LLM_CONTAINER_NAME)
            container.stop(timeout=10)
            container.remove()
            logger.info("local-llm: force shutdown on orchestrator cleanup")
        except NotFound:
            pass
        except Exception as e:
            logger.warning(f"local-llm shutdown failed: {e}")

    # ------------------------------------------------------------------ #
    # Container lifecycle
    # ------------------------------------------------------------------ #

    def _ensure_container(self) -> None:
        """Start the Ollama container if it is not already running."""
        # Already up?
        try:
            container = self.client.containers.get(LLM_CONTAINER_NAME)
            if container.status == "running":
                return
            # Exists but not running (exited/created) -> remove and recreate clean.
            container.remove(force=True)
            logger.info("local-llm: removed stale container before restart")
        except NotFound:
            pass

        self._ensure_image()

        run_kwargs = dict(
            image=LLM_IMAGE,
            name=LLM_CONTAINER_NAME,
            detach=True,
            # On the shared bridge network so the orchestrator reaches it by DNS;
            # publish the port on loopback so host-network scan containers reach
            # localhost and nothing off the host reaches it.
            network=LLM_NETWORK,
            ports={f"{LLM_PORT}/tcp": (LLM_PUBLISH_HOST, LLM_PORT)},
            environment={"OLLAMA_HOST": f"0.0.0.0:{LLM_PORT}"},
            volumes={LLM_MODELS_VOLUME: {"bind": "/root/.ollama", "mode": "rw"}},
            restart_policy={"Name": "no"},
        )
        # Phase 7: cap the judge's RAM unless explicitly disabled. GPU mode loads
        # into VRAM, so the RAM cap does not apply there.
        if LLM_MEM_LIMIT and LLM_MEM_LIMIT.lower() not in ("0", "none", "off") and not LLM_USE_GPU:
            run_kwargs["mem_limit"] = LLM_MEM_LIMIT
        if LLM_USE_GPU:
            # Request all GPUs (equivalent to `--gpus all`).
            run_kwargs["device_requests"] = [
                docker.types.DeviceRequest(count=-1, capabilities=[["gpu"]])
            ]

        container = self.client.containers.run(**run_kwargs)
        logger.info(f"local-llm: started Ollama container {container.id[:12]} on {LLM_INTERNAL_URL}")

    def _ensure_image(self) -> None:
        """Pull the Ollama image if it is not present locally."""
        try:
            self.client.images.get(LLM_IMAGE)
        except (ImageNotFound, NotFound):
            logger.info(f"local-llm: pulling image {LLM_IMAGE} (first run)")
            self.client.images.pull(LLM_IMAGE)

    def _is_running(self) -> bool:
        try:
            return self.client.containers.get(LLM_CONTAINER_NAME).status == "running"
        except (NotFound, APIError):
            return False

    def _container_id(self) -> str | None:
        try:
            return self.client.containers.get(LLM_CONTAINER_NAME).id
        except (NotFound, APIError):
            return None

    # ------------------------------------------------------------------ #
    # Ollama HTTP API (stdlib urllib only)
    # ------------------------------------------------------------------ #

    def _wait_ready(self, timeout_s: int) -> bool:
        """Poll GET /api/tags until Ollama responds or the timeout elapses."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"{LLM_INTERNAL_URL}/api/tags", timeout=5) as resp:
                    if resp.status == 200:
                        return True
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(READY_POLL_INTERVAL_S)
        return False

    def _list_models(self) -> list[str]:
        """Return the model names Ollama currently has pulled."""
        try:
            with urllib.request.urlopen(f"{LLM_INTERNAL_URL}/api/tags", timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
        except Exception:
            return []

    def _ensure_model(self, model: str) -> bool:
        """Ensure `model` is pulled. Returns True if present/pulled, else False."""
        if _model_matches(self._list_models(), model):
            return True

        logger.info(f"local-llm: pulling model {model} (streamed; may take minutes on first run)")
        try:
            payload = json.dumps({"name": model}).encode("utf-8")
            req = urllib.request.Request(
                f"{LLM_INTERNAL_URL}/api/pull",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # /api/pull streams NDJSON progress lines until done; drain it.
            with urllib.request.urlopen(req, timeout=PULL_TIMEOUT_S) as resp:
                for raw in resp:
                    line = raw.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if evt.get("error"):
                        logger.warning(f"local-llm: pull error for {model}: {evt['error']}")
                        return False
        except Exception as e:
            logger.warning(f"local-llm: model pull failed for {model}: {e}")
            return False

        return _model_matches(self._list_models(), model)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _unavailable(self, warning: str, leases: int) -> LocalLlmStatus:
        return LocalLlmStatus(
            available=False,
            running=self._is_running(),
            container_id=self._container_id(),
            leases=leases,
            warning=warning,
        )
