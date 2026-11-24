"""No tool container poses as a per-user sandbox (follow-up FU, review round 3).

The orchestrator's sandbox manager lists every container on the daemon that carries the
`redamon.sandbox` label: adoption, cleanup and the pool port allocation read its
`redamon.sandbox.*` labels. A container the broker made for a scan could carry any label,
so one labelled as a sandbox with a port label the orchestrator cannot read made every
pool start fail, and one with a real port number held that port from every person. A
create that sets any label of that namespace is now refused; every other label passes.

The label name is the contract's (recon_orchestrator/sandbox_contract.py LABEL_SANDBOX);
test_sandbox_networks.py pins it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402

IMAGE = "projectdiscovery/naabu:latest"


def create(labels):
    return broker.validate_create({"Image": IMAGE, "Labels": labels})


@pytest.mark.parametrize("name", ["redamon.sandbox", "redamon.sandbox.port", "redamon.sandbox.user",
                                  "redamon.sandbox.owner", "redamon.sandbox.role"])
def test_a_sandbox_label_is_refused(name):
    ok, reason = create({name: "1"})
    assert not ok and reason == f"sandbox label denied: {name!r}"


def test_the_label_spelled_in_another_case_of_its_key_is_still_read():
    # _canonical_keys renames a lone case variant of a key the daemon reads.
    ok, reason = broker.validate_create({"Image": IMAGE, "labels": {"redamon.sandbox.port": "²"}})
    assert not ok and "sandbox label denied" in reason


@pytest.mark.parametrize("labels", [None, {}, {"redamon.run_id": "r1", "redamon.sandboxed": "1",
                                               "com.example.sandbox": "1", "redamon.broker-owned": "1"}])
def test_other_labels_pass(labels):
    ok, reason = broker.validate_create({"Image": IMAGE, **({} if labels is None else {"Labels": labels})})
    assert ok, reason


def test_labels_that_are_not_a_map_are_refused():
    ok, reason = create(["redamon.sandbox=1"])
    assert not ok and reason == "Labels is not a JSON object"


def test_the_label_name_is_the_contracts():
    assert broker.SANDBOX_LABEL == "redamon.sandbox"
