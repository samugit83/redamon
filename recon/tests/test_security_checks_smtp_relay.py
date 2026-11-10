"""L-20: the SMTP open-relay check reads whole replies, one per command.

check_smtp_open_relay did one recv(1024) per command and tested
`'250' in reply`. A greeting split across two TCP segments (`220-` then `220 `)
shifted every later reply by one: HELO's 250 was read as the MAIL answer and
MAIL's 250 as the RCPT answer, so a server refusing the relay was reported as
an open relay (High).

`_SmtpConversation` is a fake socket that behaves like a server: each recv()
returns one TCP segment, a command's reply becomes readable only once the
command is sent, and nothing to read is a timeout. A real local TCP server
checks the same over the loopback. Addresses are RFC 5737.
"""
from __future__ import annotations

import socket
import socketserver
import threading
import time
from unittest import mock

import pytest

from recon.helpers import security_checks as sc

IP = "192.0.2.25"

SPLIT_GREETING = [b"220-mx.example.test ESMTP\r\n", b"220 mx.example.test ready\r\n"]
HELO_OK = [b"250 mx.example.test hello\r\n"]
MAIL_OK = [b"250 2.1.0 sender ok\r\n"]
RELAY_DENIED = [b"554 5.7.1 relay access denied\r\n"]
RELAY_ACCEPTED = [b"250 2.1.5 recipient ok\r\n"]


class _SmtpConversation:
    def __init__(self, greeting, replies):
        self.pending = list(greeting)
        self.replies = {verb: list(segments) for verb, segments in replies.items()}
        self.sent = []
        self.closed = False

    def recv(self, _n):
        if not self.pending:
            raise socket.timeout("timed out")
        segment = self.pending.pop(0)
        if isinstance(segment, BaseException):
            raise segment
        return segment

    def sendall(self, data):
        self.sent.append(data)
        verb = data.split(b":", 1)[0].split(b" ", 1)[0].strip().upper()
        self.pending.extend(self.replies.get(verb.decode(), []))

    def send(self, data):
        self.sendall(data)
        return len(data)

    def settimeout(self, _t):
        pass

    def close(self):
        self.closed = True


def _check(greeting, **replies):
    conversation = _SmtpConversation(greeting, replies)
    with mock.patch.object(sc.socket, "create_connection", return_value=conversation) as connect:
        try:
            return sc.check_smtp_open_relay(IP, 25, timeout=2), conversation
        finally:
            assert connect.call_args.args[0] == (IP, 25)


def _verbs(conversation):
    return [c.split(b":", 1)[0].split(b" ", 1)[0].strip().decode() for c in conversation.sent]


class TestRepliesAreReadWhole:
    def test_a_two_segment_greeting_with_the_relay_refused_is_clean(self):
        result, conversation = _check(SPLIT_GREETING, HELO=HELO_OK, MAIL=MAIL_OK,
                                      RCPT=RELAY_DENIED)
        assert result is None
        assert _verbs(conversation) == ["HELO", "MAIL", "RCPT", "QUIT"]
        assert conversation.closed

    def test_a_two_segment_greeting_with_the_relay_accepted_is_a_finding(self):
        result, conversation = _check(SPLIT_GREETING, HELO=HELO_OK, MAIL=MAIL_OK,
                                      RCPT=RELAY_ACCEPTED)
        assert result["type"] == "smtp_open_relay"
        assert (result["ip"], result["port"], result["severity"]) == (IP, 25, "high")
        assert _verbs(conversation) == ["HELO", "MAIL", "RCPT", "QUIT"]
        assert conversation.sent[1] == b"MAIL FROM:<test@external-domain.com>\r\n"
        assert conversation.sent[2] == b"RCPT TO:<test@another-external-domain.com>\r\n"

    def test_a_multi_line_helo_answer_in_one_segment_is_one_reply(self):
        helo = [b"250-mx.example.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n"]
        result, _ = _check([b"220 mx ESMTP\r\n"], HELO=helo, MAIL=MAIL_OK, RCPT=RELAY_DENIED)
        assert result is None

    def test_a_multi_line_reply_split_over_segments_is_one_reply(self):
        helo = [b"250-mx.example.test\r\n", b"250-PIPELINING\r\n", b"250 8BITMIME\r\n"]
        result, _ = _check(SPLIT_GREETING, HELO=helo, MAIL=MAIL_OK, RCPT=RELAY_DENIED)
        assert result is None

    def test_a_line_split_mid_code_is_joined(self):
        result, _ = _check([b"22", b"0 mx ESMTP\r\n"], HELO=[b"25", b"0 hi\r\n"],
                           MAIL=[b"250 ok", b"\r\n"], RCPT=[b"5", b"54 denied\r\n"])
        assert result is None

    def test_bare_line_feeds_and_a_code_with_no_text_are_read(self):
        result, _ = _check([b"220-mx\n220\n"], HELO=[b"250\n"], MAIL=[b"250\n"],
                           RCPT=[b"251 will forward\n"])
        assert result["type"] == "smtp_open_relay"

    def test_the_rcpt_code_is_compared_not_searched(self):
        """'250' inside a refusal's text is not an acceptance."""
        result, _ = _check([b"220 mx ESMTP\r\n"], HELO=HELO_OK, MAIL=MAIL_OK,
                           RCPT=[b"550 5.7.1 <x@example.org>: max 250 recipients, relay denied\r\n"])
        assert result is None


class TestOutcomesKeepTheirMeaning:
    def test_a_refusing_greeting_is_clean_and_sends_nothing(self):
        result, conversation = _check([b"554 5.7.1 no service for you\r\n"])
        assert result is None
        assert conversation.sent == []

    def test_a_busy_greeting_is_no_verdict(self):
        with pytest.raises(sc.CheckUnknown):
            _check([b"421 4.3.2 service not available\r\n"])

    def test_a_service_that_is_not_smtp_is_clean(self):
        result, conversation = _check([b"SSH-2.0-OpenSSH_9.6\r\n"])
        assert result is None
        assert conversation.sent == []

    def test_a_greylisted_recipient_is_no_verdict(self):
        with pytest.raises(sc.CheckUnknown):
            _check(SPLIT_GREETING, HELO=HELO_OK, MAIL=MAIL_OK,
                   RCPT=[b"451 4.7.1 greylisted, try again later\r\n"])

    def test_an_unreadable_answer_mid_dialogue_is_no_verdict_not_clean(self):
        with pytest.raises(sc.CheckUnknown):
            _check(SPLIT_GREETING, HELO=HELO_OK, MAIL=[b"hello there\r\n"])

    def test_a_reply_the_connection_cuts_short_is_no_verdict(self):
        with pytest.raises(sc.CheckUnknown):
            _check(SPLIT_GREETING, HELO=HELO_OK, MAIL=MAIL_OK, RCPT=[b"250-accepted\r\n", b""])

    def test_a_reply_that_never_ends_is_no_verdict(self):
        """A continuation line with no final line is a timeout, not an answer."""
        with pytest.raises(sc.CheckUnknown):
            _check([b"220-mx ESMTP\r\n"], HELO=HELO_OK)

    def test_a_reply_past_the_size_cap_is_no_verdict(self):
        endless = [b"220-" + b"x" * 1000 + b"\r\n"] * 200
        with pytest.raises(sc.CheckUnknown):
            _check(endless)

    def test_a_reply_dripped_past_the_timeout_is_no_verdict(self):
        """The timeout bounds the whole reply, not each recv()."""
        clock = iter(range(0, 1000, 1))
        drip = [b"220-mx\r\n"] * 50
        with mock.patch.object(sc.time, "monotonic", side_effect=lambda: next(clock)):
            with pytest.raises(sc.CheckUnknown):
                _check(drip + [b"220 ready\r\n"], HELO=HELO_OK)

    def test_a_refused_helo_is_clean(self):
        result, conversation = _check([b"220 mx ESMTP\r\n"], HELO=[b"550 go away\r\n"])
        assert result is None
        assert _verbs(conversation) == ["HELO", "QUIT"]


# ---------------------------------------------------------------------------
# Over a real loopback socket
# ---------------------------------------------------------------------------

class _RealSmtp(socketserver.StreamRequestHandler):
    """Writes a two-line greeting in two writes, then answers each command."""

    rcpt_reply = b"554 5.7.1 relay access denied\r\n"

    def handle(self):
        self.wfile.write(b"220-mx.example.test ESMTP\r\n")
        self.wfile.flush()
        time.sleep(0.05)
        self.wfile.write(b"220 mx.example.test ready\r\n")
        self.wfile.flush()
        answers = {b"HELO": b"250-mx.example.test\r\n250 PIPELINING\r\n",
                   b"MAIL": b"250 2.1.0 ok\r\n", b"RCPT": self.server.rcpt_reply}
        for line in self.rfile:
            verb = line.split(b":", 1)[0].split(b" ", 1)[0].strip().upper()
            if verb == b"QUIT":
                break
            self.wfile.write(answers.get(verb, b"502 not implemented\r\n"))
            self.wfile.flush()


@pytest.fixture
def smtp_server():
    def start(rcpt_reply):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _RealSmtp)
        server.daemon_threads = True
        server.rcpt_reply = rcpt_reply
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_address[1]

    servers = []
    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_a_real_server_refusing_the_relay_is_clean(smtp_server):
    port = smtp_server(b"554 5.7.1 relay access denied\r\n")
    assert sc.check_smtp_open_relay("127.0.0.1", port, timeout=3) is None


def test_a_real_server_accepting_the_relay_is_a_finding(smtp_server):
    port = smtp_server(b"250 2.1.5 ok\r\n")
    assert sc.check_smtp_open_relay("127.0.0.1", port, timeout=3)["type"] == "smtp_open_relay"
