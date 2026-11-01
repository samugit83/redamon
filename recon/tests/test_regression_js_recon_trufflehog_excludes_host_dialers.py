"""R5: the sidecar never runs a detector that dials a host from the scanned text.

With verification on, TruffleHog's PrivateKey detector sends key material to
a third-party lookup, and the URI, JDBC, JWT and database detectors connect to
the host the finding names: from hostile JavaScript that is an SSRF probe. The
exclusion list (rule V2, reviewed per detector against TruffleHog 3.96.0) is
passed in both modes, so the findings do not depend on whether keys are
verified. TruffleHog refuses an unknown or malformed name with exit 1 and no
results, so every entry must be a plain detector name.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import trufflehog_bridge as th  # noqa: E402

HOST_DIALERS = {"PrivateKey", "URI", "JDBC", "JWT", "Postgres", "MongoDB", "SQLServer", "Redis",
                "RabbitMQ", "LDAP", "FTP", "GCP", "Docker", "JiraToken"}


def _excluded(verify: bool) -> set:
    argv = th.build_argv("/tmp/redamon/js_recon_th_x_y", verify=verify, concurrency=4,
                         validation_timeout=5, name="redamon-jsth-x", memory="1")
    (flag,) = [a for a in argv if a.startswith("--exclude-detectors=")]
    return set(flag.split("=", 1)[1].split(","))


def test_the_list_is_in_the_argv_in_both_modes():
    for verify in (False, True):
        assert _excluded(verify) == set(th.TRUFFLEHOG_EXCLUDED_DETECTORS)
        assert HOST_DIALERS <= _excluded(verify)


def test_every_name_is_a_plain_detector_name():
    # A hyphen is read as an ID range and anything unknown aborts the scan.
    for name in th.TRUFFLEHOG_EXCLUDED_DETECTORS:
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name), name


def test_no_excluded_detector_is_mapped_to_a_js_recon_type():
    assert not set(th._DETECTOR_NAMES) & set(th.TRUFFLEHOG_EXCLUDED_DETECTORS)
