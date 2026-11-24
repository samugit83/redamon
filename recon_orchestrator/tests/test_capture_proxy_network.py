"""
The capture proxy joins its own stack's pentest-net, and recon its js_recon volumes (FU-7).

docker-compose.yml gives `pentest-net` no explicit name, so compose names it
"<project>_pentest-net" after the stack's compose project. The orchestrator used the
literal "redamon_pentest-net": in a clone whose project is not `redamon` the proxy
failed to start, or, beside a `redamon` stack on the same daemon, joined the other
stack's network. The name now follows the project read from the orchestrator's own
compose labels (api.py sets it at startup); without one it stays "redamon_pentest-net".
Docker is intercepted: no container starts.
"""
from __future__ import annotations

import asyncio
from unittest import mock

import pytest

import container_manager as cm


def _proxy_network(project):
    mgr = cm.ContainerManager.__new__(cm.ContainerManager)
    runs = []
    mgr.client = mock.Mock()
    mgr.client.containers.run = lambda image, **kw: runs.append(kw) or mock.Mock()
    mgr._remove_container_if_exists = lambda name: None
    mgr._capture_image = lambda: "redamon-capture-proxy:latest"
    mgr._capture_port = lambda: 8888

    async def _status():
        return {"running": True}

    mgr.capture_proxy_status = _status
    if project is not ...:
        mgr.compose_project = project
    asyncio.run(mgr.start_capture_proxy({}))
    proxy = next(kw for kw in runs if kw["name"] == cm.ContainerManager.CAPTURE_PROXY_NAME)
    return proxy["network"]


@pytest.mark.parametrize("project,network", [
    ("myclone", "myclone_pentest-net"),
    ("redamon", "redamon_pentest-net"),
    (None, "redamon_pentest-net"),
    (..., "redamon_pentest-net"),
])
def test_the_proxy_joins_its_own_stacks_pentest_net(project, network):
    assert _proxy_network(project) == network


def test_the_js_recon_volumes_are_the_stacks_own():
    # The same compose naming: a recon or partial-recon spawn of a clone mounted an
    # empty "redamon_js_recon_*" volume (Docker makes a missing named volume).
    mgr = cm.ContainerManager.__new__(cm.ContainerManager)
    mgr.compose_project = "myclone"
    assert mgr._compose_object("js_recon_uploads") == "myclone_js_recon_uploads"
    with open(cm.__file__, encoding="utf-8") as f:
        source = f.read()
    assert '"redamon_js_recon_' not in source
    assert source.count('self._compose_object("js_recon_uploads")') == 2
    assert source.count('self._compose_object("js_recon_custom")') == 2


def test_the_orchestrator_sets_its_compose_project_before_anything_starts_the_proxy():
    import inspect
    import api
    source = inspect.getsource(api.lifespan)
    assert source.index("container_manager.compose_project = own_project") < \
        source.index("_capture_config_reconcile()")
