"""The takeover re-key script lands where the writer writes (S-23, S-24).

tooling/scripts/takeover_finding_rekey.py recomputes a finding's provider from
the properties its node stores. Here the real scan (run_subdomain_takeover)
produces each finding and the real graph writer (TakeoverMixin) stores it on a
fake session; the node is then given back the provider (and certificate
provider) the earlier release wrote, and the script must move it to the id the
writer now writes. Scanners and DNS probes are mocked.
"""
from __future__ import annotations

import sys
from pathlib import Path

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from graph_db.mixins.recon.takeover_mixin import TakeoverMixin  # noqa: E402
from recon.helpers import takeover_helpers as th  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as runner  # noqa: E402
from tooling.scripts import takeover_finding_rekey as rk  # noqa: E402

HOST = "portal.example.test"
ACM_ISSUER = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True, "SUBJACK_ENABLED": True,
    "NUCLEI_TAKEOVERS_ENABLED": True, "BADDNS_ENABLED": False,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": True, "TAKEOVER_CERT_VALIDATION_ENABLED": True,
    "TAKEOVER_CONFIDENCE_THRESHOLD": 60,
    "TAKEOVER_SEVERITY": ["info", "low", "medium", "high", "critical"],
}


class _Result:
    def single(self):
        return {"matched": 1}


class _Session:
    def __init__(self):
        self.props = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        if "props" in params:
            self.props.append(params["props"])
        return _Result()


class _Writer(TakeoverMixin):
    def __init__(self):
        self.session_obj = _Session()
        self.driver = self

    def session(self):
        return self.session_obj


def _stored(monkeypatch, *, subjack=(), nuclei=(), cname=None, cert=None):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: list(subjack))
    monkeypatch.setattr(runner, "_run_nuclei_takeover", lambda urls, work_dir, settings: list(nuclei))
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target",
                        lambda c, timeout=3.0: {"resolves": False, "ips": (), "nxdomain": True})
    probe = {"status_code": 404, "host": HOST}
    if cert:
        probe["tls"] = {"certificate": cert}
    records = {HOST: {"records": {"CNAME": f"{cname}."}}} if cname else {}
    recon = {"domain": "example.test", "dns": {"subdomains": records},
             "http_probe": {"by_url": {f"https://{HOST}": probe}}}
    runner.run_subdomain_takeover(recon, settings=dict(SETTINGS))
    writer = _Writer()
    writer.update_graph_from_subdomain_takeover(recon, "u1", "p1")
    [props] = writer.session_obj.props
    return props


def _as_written_before(props, provider, cert_provider):
    """The node the earlier release wrote: the same evidence, the old provider."""
    return {"id": th.finding_id(props["hostname"], provider, props["takeover_method"]),
            "hostname": props["hostname"], "provider": provider,
            "method": props["takeover_method"], "cname_target": props.get("cname_target"),
            "cert_provider": cert_provider, "cert_issuer": props.get("cert_issuer"),
            "cert_subject_cn": props.get("cert_subject_cn"), "tool_raw": props.get("tool_raw")}


class _Rows:
    def __init__(self, row):
        self.row = row

    def run(self, query, **params):
        return [self.row]


def _rekey(row):
    plan = rk.plan_project(_Rows(row), {"id": "p1", "user_id": "u1"})
    assert plan["unmapped"] == []
    [r] = plan["rekeys"]
    return r


def _acm_cert():
    return {"subject_cn": "www.example.test", "san": ["www.example.test"], "issuer": ACM_ISSUER,
            "expired": False, "self_signed": False, "mismatched": False}


def _dangling(cname):
    return {"template-id": "detect-dangling-cname", "template": "dns/detect-dangling-cname.yaml",
            "info": {"name": "CNAME Detect Dangling", "severity": "info",
                     "tags": ["dns", "takeover", "discovery"]},
            "type": "dns", "host": HOST, "matched-at": HOST, "extracted-results": [cname]}


def test_an_acm_only_finding_moves_to_the_id_the_writer_writes(monkeypatch):
    props = _stored(monkeypatch, subjack=[{"subdomain": HOST, "vulnerable": True, "service": ""}],
                    cname="app-123.us-east-1.elb.amazonaws.com", cert=_acm_cert())
    assert props["takeover_provider"] == "aws"
    r = _rekey(_as_written_before(props, "aws-s3", "aws-s3"))
    assert (r["new_provider"], r["new_id"]) == ("aws", props["id"])


def test_a_dangling_cname_finding_moves_to_the_id_the_writer_writes(monkeypatch):
    props = _stored(monkeypatch, nuclei=[_dangling("orphan-app.herokuapp.com")])
    assert props["takeover_provider"] == "heroku"
    r = _rekey(_as_written_before(props, "dangling-cname", None))
    assert (r["new_provider"], r["new_id"]) == ("heroku", props["id"])


def test_a_dangling_cname_named_by_an_acm_certificate_moves_to_aws(monkeypatch):
    props = _stored(monkeypatch, nuclei=[_dangling("orphan.deadcdn.example")], cert=_acm_cert())
    assert props["takeover_provider"] == "aws"
    r = _rekey(_as_written_before(props, "dangling-cname", "aws-s3"))
    assert (r["new_provider"], r["new_id"]) == ("aws", props["id"])


def test_an_s3_finding_the_tool_named_keeps_its_id(monkeypatch):
    props = _stored(monkeypatch,
                    subjack=[{"subdomain": HOST, "vulnerable": True, "service": "aws/s3"}],
                    cname="app-123.us-east-1.elb.amazonaws.com", cert=_acm_cert())
    assert props["takeover_provider"] == "aws-s3"
    row = _as_written_before(props, "aws-s3", "aws-s3")
    assert row["id"] == props["id"]
    plan = rk.plan_project(_Rows(row), {"id": "p1", "user_id": "u1"})
    assert plan == {"rekeys": [], "unmapped": []}
