from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main.py"


def test_main_reads_recon_delete_graph_env():
    src = MAIN.read_text(encoding="utf-8")
    assert "RECON_DELETE_GRAPH" in src
    assert "DELETE_GRAPH_BEFORE_RECON" in src


def test_clear_project_data_is_guarded_by_delete_flag():
    src = MAIN.read_text(encoding="utf-8")
    assert "if UPDATE_GRAPH_DB and DELETE_GRAPH_BEFORE_RECON:" in src
    assert "Preserving existing graph data" in src
