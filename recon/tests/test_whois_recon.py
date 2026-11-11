"""recon/main_recon_modules/whois_recon.py: an empty answer is an answer.

python-whois is stubbed at `whois_recon.whois.whois`; `time.sleep` is patched,
so no test waits.
"""
from __future__ import annotations

import socket
from unittest import mock

import pytest
from whois.exceptions import (
    WhoisDomainNotFoundError, WhoisError, WhoisQuotaExceededError,
)

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import whois_recon
from recon.main_recon_modules.whois_recon import (
    WhoisUnavailable, get_whois_data, whois_lookup,
)


def _entry(**fields):
    base = {"domain_name": None, "registrar": None, "creation_date": None, "org": None}
    base.update(fields)
    entry = mock.MagicMock()
    for k, v in base.items():
        setattr(entry, k, v)
    entry.__bool__ = lambda self: True
    entry.keys = lambda: base.keys()
    entry.__iter__ = lambda self: iter(base)
    entry.__getitem__ = lambda self, k: base[k]
    return entry


@pytest.fixture
def fake_whois():
    with mock.patch.object(whois_recon.whois, "whois") as fake, \
            mock.patch.object(whois_recon.time, "sleep") as sleep:
        yield fake, sleep


def test_an_empty_parse_is_returned_at_once_with_no_sleep(fake_whois):
    # An address is asked through the registry client, never python-whois's
    # whois() (its hidden PTR lookup): see test_ip_hostnames_mode_gates.py.
    domain_whois, sleep = fake_whois
    empty = _entry(org="Example Hosting")
    with mock.patch.object(whois_recon, "_ip_whois", return_value=empty) as fake:
        result, target = get_whois_data("198.51.100.7")
    assert fake.call_count == 1
    domain_whois.assert_not_called()
    sleep.assert_not_called()
    assert result is empty and target == "198.51.100.7"


def test_the_seventh_call_is_gone(fake_whois):
    fake, _ = fake_whois
    fake.return_value = _entry()
    get_whois_data("example.com", max_retries=6)
    assert fake.call_count == 1


def test_a_real_record_is_returned(fake_whois):
    fake, sleep = fake_whois
    fake.return_value = _entry(domain_name="example.com", registrar="R")
    result, _ = get_whois_data("example.com")
    assert result.registrar == "R" and fake.call_count == 1
    sleep.assert_not_called()


def test_socket_errors_are_raised_not_parsed_as_empty(fake_whois):
    fake, _ = fake_whois
    fake.return_value = _entry(domain_name="example.com")
    get_whois_data("example.com")
    assert fake.call_args.kwargs == {"ignore_socket_errors": False, "quiet": True}


def test_unknown_domain_is_no_data(fake_whois):
    fake, sleep = fake_whois
    fake.side_effect = WhoisDomainNotFoundError("No match for")
    result, _ = get_whois_data("unregistered.example")
    assert result == {} and fake.call_count == 1
    sleep.assert_not_called()


def test_no_output_is_no_data_for_an_ip(fake_whois):
    _, sleep = fake_whois
    with mock.patch.object(whois_recon, "_ip_whois",
                           side_effect=WhoisError("Whois command returned no output")) as fake:
        result, _ = get_whois_data("198.51.100.7")
    assert result == {} and fake.call_count == 1
    sleep.assert_not_called()


def test_no_output_for_a_domain_gets_one_short_retry(fake_whois):
    fake, sleep = fake_whois
    fake.side_effect = WhoisError("Whois command returned no output")
    with pytest.raises(Exception, match="no output"):
        get_whois_data("example.com", max_retries=6)
    assert fake.call_count == 2
    sleep.assert_called_once_with(1)


def test_socket_failures_retry_with_backoff_until_the_breaker_opens(fake_whois):
    fake, sleep = fake_whois
    fake.side_effect = socket.timeout("timed out")
    with pytest.raises(Exception, match="TimeoutError"):
        get_whois_data("example.com", max_retries=6)
    # Three consecutive failures open the whois breaker: no fourth call and
    # no sleep after it opened.
    assert fake.call_count == 3
    assert [c.args[0] for c in sleep.call_args_list] == [1, 2]
    with pytest.raises(WhoisUnavailable):
        get_whois_data("example.org")
    assert fake.call_count == 3


def test_a_socket_error_then_an_answer_recovers(fake_whois):
    fake, _ = fake_whois
    fake.side_effect = [ConnectionResetError(), _entry(domain_name="example.com")]
    result, _ = get_whois_data("example.com")
    assert result.domain_name == "example.com" and fake.call_count == 2


def test_quota_exhaustion_is_fatal(fake_whois):
    fake, sleep = fake_whois
    fake.side_effect = WhoisQuotaExceededError("quota exceeded")
    with pytest.raises(Exception, match="quota exceeded"):
        get_whois_data("example.com")
    assert fake.call_count == 1
    sleep.assert_not_called()
    assert cb.peek_breaker("whois").is_fatal


def test_the_error_message_carries_no_server_text(fake_whois):
    fake, _ = fake_whois
    fake.side_effect = OSError("connect to whois.example-registry.test:43 SECRETISH")
    with pytest.raises(Exception) as err:
        get_whois_data("example.com", max_retries=1)
    assert "SECRETISH" not in str(err.value) and "OSError" in str(err.value)


def test_whois_lookup_can_skip_the_banner(fake_whois, capsys):
    fake, _ = fake_whois
    fake.return_value = _entry(domain_name="example.com")
    whois_lookup("example.com", save_output=False, settings={"WHOIS_MAX_RETRIES": 2},
                 print_settings=False)
    assert "Effective settings" not in capsys.readouterr().out
    whois_lookup("example.com", save_output=False, settings={"WHOIS_MAX_RETRIES": 2})
    assert "Effective settings" in capsys.readouterr().out


def test_off_switch_keeps_retrying(fake_whois, monkeypatch):
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    fake, _ = fake_whois
    fake.side_effect = socket.timeout("timed out")
    with pytest.raises(Exception):
        get_whois_data("example.com", max_retries=6)
    assert fake.call_count == 6
