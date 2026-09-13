"""The authenticated session must never reach a host outside the profile scope.

`merge_auth_headers` scope-checks the hosts a command is pointed at, but nuclei
and httpx both apply their `-H` set to requests they generate themselves:

  * nuclei polls a PUBLIC interactsh collector (interact.sh / oast.fun) for OAST
    callbacks. A live run was observed sending `cookie` + `csrf_token` there with
    `in_scope=f`; it escaped disclosure only because the box had no DNS for it.
  * both re-send `-H` headers on a redirect to ANY host, so one off-scope
    `Location` hands over the session.

These assert the built command, not the run, so they pin the flags themselves.
"""

from unittest import mock

from recon.helpers.auth_profile import merge_auth_headers_ex
from recon.helpers.nuclei_helpers import build_nuclei_command

AUTH = ["Cookie: sid=abc123"]

SETTINGS = {'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': [], 'IP_MODE': False}
PROFILE = {'authType': 'cookie', 'authValue': 'sid=abc123',
           'authHeaderName': '', 'extraHeaders': {}}


def _nuclei(**kw):
    args = dict(targets_file="/targets/t.txt", output_file="/output/o.jsonl",
                docker_image="projectdiscovery/nuclei:latest")
    args.update(kw)
    return build_nuclei_command(**args)


class TestNucleiOastLeak:
    def test_auth_forces_no_interactsh_even_when_enabled(self):
        cmd = _nuclei(interactsh=True, auth_headers=AUTH)
        assert "-no-interactsh" in cmd

    def test_no_auth_keeps_oast_coverage(self):
        cmd = _nuclei(interactsh=True, auth_headers=None)
        assert "-no-interactsh" not in cmd

    def test_explicit_disable_is_not_duplicated_under_auth(self):
        # Both branches append the same flag; nuclei must not receive it twice.
        cmd = _nuclei(interactsh=False, auth_headers=AUTH)
        assert cmd.count("-no-interactsh") == 1


class TestNucleiRedirectLeak:
    def test_auth_confines_redirects_to_same_host(self):
        cmd = _nuclei(follow_redirects=True, max_redirects=10, auth_headers=AUTH)
        assert "-follow-host-redirects" in cmd
        assert "-follow-redirects" not in cmd

    def test_no_auth_keeps_cross_host_redirects(self):
        cmd = _nuclei(follow_redirects=True, max_redirects=10, auth_headers=None)
        assert "-follow-redirects" in cmd
        assert "-follow-host-redirects" not in cmd

    def test_max_redirects_still_applied_under_auth(self):
        cmd = _nuclei(follow_redirects=True, max_redirects=7, auth_headers=AUTH)
        assert "-max-redirects" in cmd
        assert cmd[cmd.index("-max-redirects") + 1] == "7"

    def test_redirects_off_adds_no_redirect_flag(self):
        cmd = _nuclei(follow_redirects=False, auth_headers=AUTH)
        assert "-follow-redirects" not in cmd
        assert "-follow-host-redirects" not in cmd


class TestNucleiStillSendsAuth:
    def test_each_auth_header_gets_its_own_H(self):
        cmd = _nuclei(auth_headers=["Cookie: sid=abc123", "X-CSRF-Token: t"])
        assert cmd.count("-H") == 2
        assert "Cookie: sid=abc123" in cmd
        assert "X-CSRF-Token: t" in cmd


class TestHttpxRedirectLeak:
    """httpx picks -fhr over -fr only when a session was actually attached."""

    def _cmd(self, profile, hosts):
        import recon.main_recon_modules.http_probe as hp

        settings = dict(SETTINGS)
        settings['HTTPX_FOLLOW_REDIRECTS'] = True
        settings['HTTPX_MAX_REDIRECTS'] = 10
        with mock.patch.object(hp, 'get_host_path', side_effect=lambda p: p), \
             mock.patch('recon.helpers.auth_profile.profile_from_settings',
                        return_value=profile):
            return hp.build_httpx_command("/t/targets.txt", "/o/out.json",
                                          settings, probe_hosts=hosts)

    def test_attached_session_confines_redirects_to_same_host(self):
        cmd = self._cmd(PROFILE, ['example.test'])
        assert "-fhr" in cmd
        assert "-fr" not in cmd

    def test_no_profile_keeps_cross_host_redirects(self):
        cmd = self._cmd(None, ['example.test'])
        assert "-fr" in cmd
        assert "-fhr" not in cmd

    def test_out_of_scope_host_means_no_auth_and_so_plain_fr(self):
        # Fail-closed drops the session; the redirect flag must follow suit
        # rather than silently tightening an unauthenticated scan.
        cmd = self._cmd(PROFILE, ['not-ours.test'])
        assert "-fr" in cmd
        assert "-fhr" not in cmd


class TestMergeAuthHeadersEx:
    def test_reports_true_when_attached(self):
        with mock.patch('recon.helpers.auth_profile.profile_from_settings',
                        return_value=PROFILE):
            merged, attached = merge_auth_headers_ex([], SETTINGS, ['example.test'])
        assert attached is True
        assert merged == ["Cookie: sid=abc123"]

    def test_reports_false_when_host_out_of_scope(self):
        with mock.patch('recon.helpers.auth_profile.profile_from_settings',
                        return_value=PROFILE):
            merged, attached = merge_auth_headers_ex(["X-Foo: 1"], SETTINGS,
                                                     ['not-ours.test'])
        assert attached is False
        assert merged == ["X-Foo: 1"]

    def test_reports_false_with_no_profile(self):
        with mock.patch('recon.helpers.auth_profile.profile_from_settings',
                        return_value=None):
            merged, attached = merge_auth_headers_ex(["X-Foo: 1"], SETTINGS,
                                                     ['example.test'])
        assert attached is False
        assert merged == ["X-Foo: 1"]

    def test_true_even_when_override_keeps_the_length_equal(self):
        # The profile's Cookie replaces the operator's, so the list is still one
        # entry long. A length comparison would call this "not attached".
        with mock.patch('recon.helpers.auth_profile.profile_from_settings',
                        return_value=PROFILE):
            merged, attached = merge_auth_headers_ex(["Cookie: stale=1"], SETTINGS,
                                                     ['example.test'])
        assert len(merged) == 1
        assert attached is True
        assert merged == ["Cookie: sid=abc123"]
