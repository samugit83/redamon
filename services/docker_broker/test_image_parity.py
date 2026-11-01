"""Broker/recon image-allowlist parity, both directions.

Recon and partial recon spawn every scan tool as a sibling container through
the broker's filtered socket (container_manager.py points their DOCKER_HOST at
it), and the broker refuses to pull or create any image missing from its
allowlist. The two lists live in separate services, so this derives the recon
side from what recon actually runs, the `*_DOCKER_IMAGE` defaults and the
images recon/entrypoint.sh pre-pulls, and asserts the broker's shipped list
allows every one of them. Locally built `redamon-*` images are included: they
go through the broker like any other, and exempting them is how the WCVS image
was refused at run time with this test green (drift-map #2, #29).

The reverse direction keeps the broker list from growing past what is used:
every shipped entry is a recon tool image or a BROKER_IMAGES_BEYOND_RECON entry
that names its broker-socket caller. And the entrypoint pre-pull list must be
the `*_DOCKER_IMAGE` set exactly, so a tool added to one is caught missing from
the other at test time rather than mid-scan (drift-map #2).

Run: ./redamon.sh test unit (section docker_broker)
"""

import os
import re
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)
sys.path.insert(0, _REPO)

import broker  # noqa: E402

if not os.path.isfile(os.path.join(_REPO, "recon", "project_settings.py")):
    pytest.skip("recon/ is not in this checkout; nothing to compare the broker with",
                allow_module_level=True)

from recon.project_settings import ALLOWED_TOOL_IMAGES, DEFAULT_SETTINGS  # noqa: E402

_ENTRYPOINT = os.path.join(_REPO, "recon", "entrypoint.sh")

# Images recon names but never spawns through the broker socket, each with the
# reason. Empty today: recon reaches Docker only through the broker. An entry
# here is a claim about container_manager.py, so name the spawn path.
RECON_IMAGES_OUTSIDE_BROKER: dict[str, str] = {}

# Shipped broker entries that are not a recon `*_DOCKER_IMAGE` tool, as
# image -> (repo file that runs it through the broker socket, reason). The file
# must name the image, so a caller that stops using it turns this red. None
# means no broker caller exists today: the entry is dead weight on a security
# allowlist and should be dropped from broker.py, after which this test fails
# until the line here goes too.
BROKER_IMAGES_BEYOND_RECON: dict[str, tuple[str | None, str]] = {
    "alpine": (
        "recon/helpers/docker_helpers.py",
        "recon's temp-file cleanup and nuclei-template volume probe "
        "(docker_helpers.ensure_templates_volume, vuln_scan.py, domain_recon.py) "
        "run `docker run alpine` through DOCKER_HOST=broker",
    ),
    "alpine:latest": (
        "recon/helpers/docker_helpers.py",
        "the spelling the daemon normalizes the bare `alpine` above to",
    ),
    "redamon-supply-chain-analyzer:latest": (
        "scanners/supply_chain_common/guarddog_runner.py",
        "the DIRTY GuardDog/retire analyzer; analyzer_dispatch.run_analyzer_job "
        "shells out to `docker run` from the recon container "
        "(supply_chain_recon.py) and the supply-chain scan container, both on "
        "DOCKER_HOST=broker",
    ),
    "redamon-trufflehog:latest": (
        "recon/helpers/js_recon/trufflehog_bridge.py",
        "JS Recon's TruffleHog sidecar: the bridge shells out to `docker run` "
        "from the recon container on DOCKER_HOST=broker; not a `*_DOCKER_IMAGE` "
        "setting and not pre-pulled (a normal install builds it)",
    ),
}


def _broker_allows(image: str) -> bool:
    """Match against the SHIPPED list, not ALLOWED_IMAGES: the env extras
    (DOCKER_BROKER_ALLOWED_IMAGES) are an operator's, and must not make a
    shipped tool pass here."""
    shipped = {broker._canonical_image(i) for i in broker._DEFAULT_ALLOWED_IMAGES}
    return broker._canonical_image(image) in shipped


def _docker_image_defaults() -> dict[str, str]:
    return {
        k: v for k, v in DEFAULT_SETTINGS.items()
        if k.endswith("_DOCKER_IMAGE") and isinstance(v, str) and v
    }


def _entrypoint_images() -> list[str]:
    """The quoted entries of the IMAGES=( ... ) bash array, comments skipped."""
    with open(_ENTRYPOINT, encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"^IMAGES=\((.*?)^\)", text, re.S | re.M)
    assert block, f"no IMAGES=( ... ) array in {_ENTRYPOINT}"
    images = []
    for line in block.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            images.extend(re.findall(r'"([^"]+)"', line))
    return images


def test_sources_are_parsed():
    # A broken parser must fail here, not make the parity tests pass vacuously.
    assert len(_docker_image_defaults()) >= 10
    assert len(_entrypoint_images()) >= 10


def test_every_docker_image_default_is_broker_allowlisted():
    missing = sorted(
        f"{key}={img}" for key, img in _docker_image_defaults().items()
        if img not in RECON_IMAGES_OUTSIDE_BROKER and not _broker_allows(img)
    )
    assert not missing, (
        "recon spawns these through the broker but services/docker_broker/broker.py "
        f"_DEFAULT_ALLOWED_IMAGES refuses them: {missing}"
    )


def test_every_entrypoint_prepull_image_is_broker_allowlisted():
    missing = sorted(
        img for img in _entrypoint_images()
        if img not in RECON_IMAGES_OUTSIDE_BROKER and not _broker_allows(img)
    )
    assert not missing, (
        "recon/entrypoint.sh pulls these through the broker but "
        f"_DEFAULT_ALLOWED_IMAGES refuses them: {missing}"
    )


def test_outside_broker_entries_are_live_and_explained():
    recon_images = set(_docker_image_defaults().values()) | set(_entrypoint_images())
    stale = sorted(set(RECON_IMAGES_OUTSIDE_BROKER) - recon_images)
    assert not stale, f"RECON_IMAGES_OUTSIDE_BROKER names images recon no longer uses: {stale}"
    unexplained = sorted(i for i, why in RECON_IMAGES_OUTSIDE_BROKER.items() if not why.strip())
    assert not unexplained, f"RECON_IMAGES_OUTSIDE_BROKER entries need a reason: {unexplained}"


def _shipped_canonical() -> set[str]:
    return {broker._canonical_image(i) for i in broker._DEFAULT_ALLOWED_IMAGES}


def _recon_tool_images_canonical() -> set[str]:
    return {broker._canonical_image(i)
            for i in set(_docker_image_defaults().values()) | set(_entrypoint_images())}


def test_every_broker_image_is_a_recon_tool_or_named():
    named = {broker._canonical_image(i) for i in BROKER_IMAGES_BEYOND_RECON}
    unexplained = sorted(_shipped_canonical() - _recon_tool_images_canonical() - named)
    assert not unexplained, (
        "services/docker_broker/broker.py _DEFAULT_ALLOWED_IMAGES lets these through, "
        "but recon runs none of them and BROKER_IMAGES_BEYOND_RECON does not say who "
        f"does: {unexplained}. Drop the entry or name its broker-socket caller."
    )


def test_beyond_recon_entries_are_live_and_explained():
    shipped = _shipped_canonical()
    recon = _recon_tool_images_canonical()
    problems = []
    for image, (caller, why) in sorted(BROKER_IMAGES_BEYOND_RECON.items()):
        canon = broker._canonical_image(image)
        if canon not in shipped:
            problems.append(f"{image}: no longer on _DEFAULT_ALLOWED_IMAGES; delete the entry")
        if canon in recon:
            problems.append(f"{image}: recon runs it as a tool image; the entry is redundant")
        if not why.strip():
            problems.append(f"{image}: needs a reason")
        if caller is None:
            continue
        path = os.path.join(_REPO, caller)
        if not os.path.isfile(path):
            problems.append(f"{image}: named caller {caller} does not exist")
            continue
        with open(path, encoding="utf-8") as f:
            if image.split(":", 1)[0] not in f.read():
                problems.append(f"{image}: named caller {caller} no longer mentions it")
    assert not problems, "BROKER_IMAGES_BEYOND_RECON is stale:\n" + "\n".join(problems)


def test_entrypoint_prepull_list_equals_docker_image_defaults():
    """recon/entrypoint.sh IMAGES is a hand copy of the `*_DOCKER_IMAGE`
    defaults. A tool only in the defaults is first pulled mid-scan; an image only
    in IMAGES is pulled for nothing on every recon start."""
    entry = _entrypoint_images()
    dupes = sorted({i for i in entry if entry.count(i) > 1})
    defaults = set(_docker_image_defaults().values())
    only_defaults = sorted(defaults - set(entry))
    only_entrypoint = sorted(set(entry) - defaults)
    assert not (dupes or only_defaults or only_entrypoint), (
        "recon/entrypoint.sh IMAGES must equal the set of *_DOCKER_IMAGE defaults in "
        f"recon/project_settings.py. Missing from IMAGES: {only_defaults}; not a "
        f"default: {only_entrypoint}; listed twice: {dupes}"
    )


def test_wcvs_and_tlsx_specifically_are_on_both():
    for img in ("projectdiscovery/tlsx:latest", "redamon-wcvs:latest"):
        assert img in ALLOWED_TOOL_IMAGES
        assert _broker_allows(img)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
