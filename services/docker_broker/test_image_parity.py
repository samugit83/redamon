"""Broker/recon image-allowlist parity.

The two allowlists are hand-maintained in separate services and nothing compared
them, so a tool added recon-side (DEFAULT_SETTINGS) would pass the recon suite
while the broker rejected the spawn at run time. This asserts every shipped
tool image the recon side allows is also on the broker's allowlist.

Run: cd services/docker_broker && python3 -m pytest test_image_parity.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))          # broker
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(     # repo root
    os.path.abspath(__file__)))))

import broker  # noqa: E402
from recon.project_settings import ALLOWED_TOOL_IMAGES  # noqa: E402


def test_every_recon_tool_image_is_broker_allowlisted():
    # redamon-* images are locally built and spawned outside the broker path;
    # the broker only gates registry pulls/creates, so exclude them.
    shipped = {img for img in ALLOWED_TOOL_IMAGES if not img.startswith("redamon-")}
    missing = sorted(img for img in shipped if img not in broker.ALLOWED_IMAGES)
    assert not missing, f"images allowed recon-side but rejected by the broker: {missing}"


def test_tlsx_specifically_is_on_both():
    assert "projectdiscovery/tlsx:latest" in ALLOWED_TOOL_IMAGES
    assert "projectdiscovery/tlsx:latest" in broker.ALLOWED_IMAGES


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
