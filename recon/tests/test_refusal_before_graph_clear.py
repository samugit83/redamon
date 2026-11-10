"""A refused scan root is refused BEFORE the one-time graph clear (R-5).

`_run_pipeline` clears the project's recon assets once per run, then hands the
group(s) to `run_domain_group`, which refuses a root the RoE excludes or whose
ownership TXT record does not verify. A refusal after the clear left the
project with no Subdomain, IP, Port, BaseURL or Endpoint, and a run that
exited 1 and rebuilt nothing. The same checks now run before the clear: a run
where every root is refused clears nothing; a batch with one eligible root
clears once and runs, and the refused groups still refuse in the loop.

Ownership answers are cached for the run, so the group run does not ask again.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))


def _group(root):
    return {'scanRoot': root, 'orgDomain': root, 'mode': 'exact', 'includeRoot': True,
            'exactHosts': []}


@pytest.fixture
def recon_main(monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'a.example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': True, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': 'tok', 'OWNERSHIP_TXT_PREFIX': '_redamon-verify',
        'SCOPE_GROUPS': [_group('a.example.com')],
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    monkeypatch.setattr(rm, "_check_roe_time_window", lambda s: (True, ""))
    monkeypatch.setattr(rm, "_start_urlscan_budget", lambda groups: None)
    yield rm


class Txt:
    """verify_domain_ownership stand-in: `verified` names pass, `down` names
    get a resolver failure, every other name has no matching record."""

    def __init__(self, verified=(), down=()):
        self.verified, self.down, self.asked = set(verified), set(down), []

    def __call__(self, domain, token, prefix):
        self.asked.append(domain)
        res = {"verified": domain in self.verified, "record_name": f"{prefix}.{domain}",
               "expected_value": f"redamon-verify={token}", "found_values": [],
               "error": None, "resolver_failed": domain in self.down}
        if domain in self.down:
            res["error"] = "DNS resolver down - cannot verify ownership (retry later)"
        elif domain not in self.verified:
            res["error"] = "TXT record found but value doesn't match"
        return res


@pytest.fixture
def run(recon_main, monkeypatch):
    """_run_pipeline with the clear and the group runners recorded, not run."""
    calls = []
    monkeypatch.setattr(recon_main, "_clear_recon_graph", lambda: calls.append("clear"))
    monkeypatch.setattr(recon_main, "_prune_recon_findings", lambda: calls.append("prune"))

    def group_run(group, start_time=None):
        # The checks run_domain_group makes before it touches the target.
        if recon_main._roe_refuses_root(group['scanRoot']):
            calls.append(("refused", group['scanRoot']))
            return 1
        if not recon_main._group_ownership(group)['verified']:
            calls.append(("refused", group['scanRoot']))
            return 1
        calls.append(("ran", group['scanRoot']))
        return 0

    monkeypatch.setattr(recon_main, "run_domain_group", group_run)
    return calls


def _use(recon_main, monkeypatch, txt):
    monkeypatch.setattr(recon_main, "verify_domain_ownership", txt)


class TestASingleDomainRefusedBeforeTheClear:
    def test_a_failed_ownership_check_clears_nothing(self, recon_main, run, monkeypatch, capsys):
        txt = Txt()
        _use(recon_main, monkeypatch, txt)
        assert recon_main._run_pipeline() == 1
        assert "clear" not in run
        assert not any(c[0] == "ran" for c in run if isinstance(c, tuple))
        out = capsys.readouterr().out
        assert "Domain ownership verification failed for a.example.com" in out
        assert '_redamon-verify.a.example.com' in out and "redamon-verify=tok" in out
        assert "Nothing was cleared" in out

    def test_a_resolver_failure_clears_nothing(self, recon_main, run, monkeypatch, capsys):
        _use(recon_main, monkeypatch, Txt(down={"a.example.com"}))
        assert recon_main._run_pipeline() == 1
        assert "clear" not in run
        assert "DNS resolver down" in capsys.readouterr().out

    def test_an_roe_excluded_root_clears_nothing_and_asks_no_txt(self, recon_main, run,
                                                                 monkeypatch, capsys):
        txt = Txt(verified={"a.example.com"})
        _use(recon_main, monkeypatch, txt)
        monkeypatch.setitem(recon_main._settings, "ROE_ENABLED", True)
        monkeypatch.setitem(recon_main._settings, "ROE_EXCLUDED_HOSTS", ["a.example.com"])
        assert recon_main._run_pipeline() == 1
        assert "clear" not in run
        assert txt.asked == []
        assert "[RoE] BLOCKED: Root domain 'a.example.com'" in capsys.readouterr().out

    def test_a_verified_root_clears_once_then_runs_without_asking_again(self, recon_main, run,
                                                                       monkeypatch):
        txt = Txt(verified={"a.example.com"})
        _use(recon_main, monkeypatch, txt)
        assert recon_main._run_pipeline() == 0
        assert run == ["clear", ("ran", "a.example.com"), "prune"]
        # The group's own check read the answer cached before the clear.
        assert txt.asked == ["a.example.com"]

    def test_ownership_off_runs_as_before(self, recon_main, run, monkeypatch):
        txt = Txt()
        _use(recon_main, monkeypatch, txt)
        monkeypatch.setattr(recon_main, "VERIFY_DOMAIN_OWNERSHIP", False)
        monkeypatch.setattr(recon_main, "run_domain_group", lambda g, start_time=None:
                            run.append(("ran", g['scanRoot'])) or 0)
        assert recon_main._run_pipeline() == 0
        assert run == ["clear", ("ran", "a.example.com"), "prune"]
        assert txt.asked == []

    def test_the_resolver_is_rechecked_before_the_first_lookup(self, recon_main, run,
                                                               monkeypatch):
        from recon.main_recon_modules import domain_recon as dr
        order = []
        monkeypatch.setattr(dr.resolver_breaker, "recheck",
                            lambda: order.append("recheck") or True)
        txt = Txt()
        monkeypatch.setattr(recon_main, "verify_domain_ownership",
                            lambda *a: order.append("ownership") or txt(*a))
        recon_main._run_pipeline()
        assert order[:2] == ["recheck", "ownership"]

    def test_no_target_refuses_before_the_clear(self, recon_main, run, monkeypatch):
        monkeypatch.setitem(recon_main._settings, "SCOPE_GROUPS", [])
        monkeypatch.setitem(recon_main._settings, "TARGET_DOMAIN", "")
        assert recon_main._run_pipeline() == 1
        assert run == []


class TestABatch:
    @pytest.fixture
    def batch(self, recon_main, monkeypatch, run):
        groups = [_group("a.example.com"), _group("b.example.org")]
        monkeypatch.setattr(recon_main, "DOMAIN_BATCH_MODE", True)
        monkeypatch.setitem(recon_main._settings, "DOMAIN_BATCH_MODE", True)
        monkeypatch.setitem(recon_main._settings, "SCOPE_GROUPS", groups)
        monkeypatch.setattr(recon_main, "clear_batch_outputs", lambda *a, **kw: 0)
        monkeypatch.setattr(recon_main, "initialize_batch_canonical", lambda *a, **kw: None)
        monkeypatch.setattr(recon_main, "merge_batch_outputs", lambda *a, **kw: None)
        monkeypatch.setattr(recon_main, "_seed_batch_root_domains", lambda roots: None)
        return groups

    def test_every_root_refused_clears_nothing(self, recon_main, run, batch, monkeypatch, capsys):
        _use(recon_main, monkeypatch, Txt())
        assert recon_main._run_pipeline() == 1
        assert run == []
        out = capsys.readouterr().out
        assert "a.example.com" in out and "b.example.org" in out

    def test_one_eligible_root_clears_once_and_the_refused_group_still_refuses(
            self, recon_main, run, batch, monkeypatch):
        txt = Txt(verified={"b.example.org"})
        _use(recon_main, monkeypatch, txt)
        assert recon_main._run_pipeline() == 0
        assert run.count("clear") == 1 and run[0] == "clear"
        assert ("refused", "a.example.com") in run and ("ran", "b.example.org") in run
        # A refused group is a failed group: no prune for the batch.
        assert "prune" not in run
        assert recon_main._BATCH_ATTACH_ROOTS == ["b.example.org"]
        # Each name asked once in the whole run: before the clear, then cached.
        assert sorted(txt.asked) == ["a.example.com", "b.example.org"]

    def test_the_pre_check_agrees_with_the_batch_attach_roots(self, recon_main, batch,
                                                             monkeypatch):
        _use(recon_main, monkeypatch, Txt(verified={"b.example.org"}))
        monkeypatch.setitem(recon_main._settings, "ROE_ENABLED", True)
        monkeypatch.setitem(recon_main._settings, "ROE_EXCLUDED_HOSTS", ["b.example.org"])
        assert recon_main._eligible_batch_roots(batch) == []
        assert recon_main._refuse_before_clear(batch) is True

    def test_an_ownership_check_that_raises_is_a_refusal(self, recon_main, run, batch,
                                                         monkeypatch):
        def boom(*a):
            raise RuntimeError("resolver library crashed")
        monkeypatch.setattr(recon_main, "verify_domain_ownership", boom)
        assert recon_main._run_pipeline() == 1
        assert run == []
