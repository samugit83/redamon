"""The shipped Alpine Nuclei image must use its system Chromium, not Rod's glibc download."""
from unittest.mock import patch

import pytest

from recon.helpers.nuclei_helpers import build_nuclei_command


@pytest.mark.parametrize('force_dast_pass', [False, True], ids=['detection', 'dast'])
@pytest.mark.parametrize('headless', [False, True], ids=['http-only', 'headless'])
def test_browser_selection_tracks_headless_for_both_passes(headless, force_dast_pass):
    with patch.dict('os.environ', {}, clear=True), patch(
        'helpers.proxy_routing.get_capture_routing', return_value=(None, None),
    ):
        cmd = build_nuclei_command(
            '/tmp/targets.txt', '/tmp/findings.jsonl', 'projectdiscovery/nuclei:latest',
            tags=['cve'], exclude_tags=['dos', 'fuzz'],
            exclude_templates=['http/example-denied.yaml'],
            headless=headless, force_dast_pass=force_dast_pass,
            auth_headers=['X-Test-Identity: synthetic-fixture'],
        )
    args = cmd[cmd.index('projectdiscovery/nuclei:latest') + 1:]
    assert args.count('-headless') == int(headless)
    assert args.count('-system-chrome') == int(headless)
    assert args.count('-dast') == int(force_dast_pass)
    assert args[args.index('-exclude-tags') + 1] == 'dos,fuzz'
    assert args[args.index('-exclude-templates') + 1] == 'http/example-denied.yaml'
    assert args[args.index('-H') + 1] == 'X-Test-Identity: synthetic-fixture'
