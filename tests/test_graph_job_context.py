import importlib.util
import os
import re
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parent.parent


def _install_dependency_stubs():
    neo4j_stub = types.ModuleType("neo4j")
    neo4j_stub.GraphDatabase = MagicMock()
    sys.modules.setdefault("neo4j", neo4j_stub)

    dotenv_stub = types.ModuleType("dotenv")
    dotenv_stub.load_dotenv = lambda *args, **kwargs: None
    sys.modules.setdefault("dotenv", dotenv_stub)

    graph_db_stub = types.ModuleType("graph_db")
    graph_db_stub.__path__ = [str(REPO_ROOT / "graph_db")]
    sys.modules.setdefault("graph_db", graph_db_stub)

    mixins_stub = types.ModuleType("graph_db.mixins")
    mixins_stub.__path__ = [str(REPO_ROOT / "graph_db" / "mixins")]
    sys.modules.setdefault("graph_db.mixins", mixins_stub)

    schema_stub = types.ModuleType("graph_db.schema")
    schema_stub.init_schema = MagicMock()
    sys.modules.setdefault("graph_db.schema", schema_stub)


def _load_base_mixin_module():
    _install_dependency_stubs()
    module_name = "graph_db.mixins.base_mixin"
    path = REPO_ROOT / "graph_db" / "mixins" / "base_mixin.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def make_base_without_init():
    BaseMixin = _load_base_mixin_module().BaseMixin

    return BaseMixin.__new__(BaseMixin)


def test_graph_job_context_uses_env_values():
    with patch.dict(
        os.environ,
        {
            "RECON_JOB_ID": "full-20260529T141530Z-abcdef12",
            "RECON_JOB_STARTED_AT": "2026-05-29T14:15:30Z",
        },
        clear=False,
    ):
        base = make_base_without_init()
        base._init_recon_job_context()

    assert base.recon_job_id == "full-20260529T141530Z-abcdef12"
    assert base.recon_job_started_at == "2026-05-29T14:15:30Z"
    assert base._recon_job_params() == {
        "recon_job_id": "full-20260529T141530Z-abcdef12",
        "recon_job_started_at": "2026-05-29T14:15:30Z",
    }


def test_graph_job_context_generates_fallback_values():
    with patch.dict(os.environ, {}, clear=True):
        base = make_base_without_init()
        base._init_recon_job_context()

    assert base.recon_job_started_at.endswith("Z")
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
        base.recon_job_started_at,
    )
    assert base.recon_job_id.startswith("adhoc-")
    assert re.fullmatch(
        r"adhoc-\d{8}T\d{6}Z-[0-9a-f]{8}",
        base.recon_job_id,
    )
    assert base._recon_job_params() == {
        "recon_job_id": base.recon_job_id,
        "recon_job_started_at": base.recon_job_started_at,
    }


def test_node_seen_set_clause_preserves_first_seen_and_updates_last_seen():
    base = make_base_without_init()
    clause = base._node_seen_set_clause("d")

    assert clause == (
        "d.first_seen = coalesce(d.first_seen, $recon_job_started_at), "
        "d.first_seen_job_id = coalesce(d.first_seen_job_id, $recon_job_id), "
        "d.last_seen = $recon_job_started_at, "
        "d.last_seen_job_id = $recon_job_id"
    )
