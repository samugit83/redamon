"""Static guards for the per-user Kali sandbox's single reverse port (FU-20..23).

Each person's sandbox exposes AT MOST ONE inbound port reachable from targets: the
pool port (published host P -> sandbox P), or the sandbox's 4444 reached through the
person's own RedAmon-managed ngrok/chisel tunnel. The payload settings block (built by
utils.py) hands the model LHOST/LPORT and the bind for whichever mode is active.

Prompt, skill and community-skill text must therefore NOT:
  - hardcode an attacker-side LPORT to a literal number (the port comes from the block),
  - start an `http.server` as a delivery method on a sandbox service port OR with the
    port defaulted (8000 is the sandbox's own network_recon server),
  - start it chained after `&&` / inside `( ... &)` (kali_shell hangs to its timeout and
    `$!` is a subshell), without every stream redirected, or logging inside the served dir,
  - offer a module that needs a SECOND inbound port (web_delivery, hta_server,
    office_word_hta) without the one-port caveat RIGHT THERE,
  - teach the ngrok handler bind as "your LPORT" (it is 127.0.0.1:4444),
  - advertise exposing the sandbox with `ngrok tcp` / a `chisel server`.

These scan the files on disk, so they run hermetically in the agent image and need no
imports beyond the stdlib. They fail on 40c11197 and pass after the FU-20..23 edits.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
_PROMPTS_DIR = _AGENTIC_DIR / "prompts"
_SKILLS_DIR = _AGENTIC_DIR / "skills"
_COMMUNITY_DIR = _AGENTIC_DIR / "community-skills"
_TOOL_REGISTRY = _PROMPTS_DIR / "tool_registry.py"

# The sandbox's own service ports (agentic/sandbox_contract.py PORTS) plus ngrok's 4040.
# An http.server bound to any of these is a port clash with the sandbox's own service and
# is never target-reachable; 8000 is also the default when no port is given.
_SANDBOX_SERVICE_PORTS = {8000, 8002, 8003, 8004, 8005, 8013, 8014, 8015, 8016, 4040}

# Metasploit modules / payloads that need a SECOND inbound port (an SRVPORT the target
# must reach, on top of the reverse handler port) and so cannot work in the sandbox.
_SECOND_PORT_MODULES = (
    "web_delivery",
    "hta_server",
    "office_word_hta",
)

# A real server invocation: `python3 -m http.server ...` (NOT `import http.server`).
_HTTP_SERVER = re.compile(r"python3?\s+-m\s+http\.server")
# Stop the argument run at the first shell / markup terminator.
_ARG_TERMINATOR = re.compile(r"[\n`\"'|;&>)]")
_PLACEHOLDER = re.compile(r"<[^>]+>")
_INT_TOKEN = re.compile(r"^\d+$")


def _text_files():
    """Every prompt .py and every skill / community-skill .md, as (path, text)."""
    for base in (_PROMPTS_DIR, _SKILLS_DIR, _COMMUNITY_DIR):
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in (".py", ".md"):
                yield path, path.read_text(encoding="utf-8")


def _rel(path: Path) -> str:
    return str(path.relative_to(_AGENTIC_DIR))


def _lineno(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _http_server_violation(text: str):
    """Yield (lineno, reason) for each http.server delivery bound to a sandbox port or
    defaulted. Placeholders like `<listen_port>` count as an explicit (safe) port."""
    for m in _HTTP_SERVER.finditer(text):
        rest = text[m.end():]
        term = _ARG_TERMINATOR.search(rest)
        arg_run = rest[: term.start()] if term else rest
        term_ch = rest[term.start()] if term else ""
        # Drop a -d/--directory flag and the directory token that follows it.
        toks = arg_run.split()
        cleaned = []
        skip = False
        for t in toks:
            if skip:
                skip = False
                continue
            if t in ("-d", "--directory"):
                skip = True
                continue
            cleaned.append(t)
        port_tok = cleaned[0] if cleaned else None
        if port_tok is None:
            # No port at all -> defaults to 8000. Flag only a REAL command (ends in a
            # shell terminator), not a prose/backtick mention.
            if term_ch in ("&", ">", ";", "\n", ""):
                yield _lineno(text, m.start()), "http.server with no port (defaults to 8000)"
            continue
        if _INT_TOKEN.match(port_tok):
            if int(port_tok) in _SANDBOX_SERVICE_PORTS:
                yield _lineno(text, m.start()), f"http.server on sandbox port {port_tok}"
        elif _PLACEHOLDER.match(port_tok):
            continue  # e.g. <listen_port> -- an explicit, settings-derived port
        # anything else (a non-sandbox literal, a shell var) is left alone


_TAIL_END = re.compile(r"[\n`\"]")
_BG_AMP = re.compile(r"(?<![&>])&(?![&>])")
_STDOUT_TARGET = re.compile(r"(?<![0-9<&])>\s*(\S+)")
_SERVED_DIR = re.compile(r"(?:--directory|-d)\s+(\S+)")


def _server_start_violations(text: str):
    """Yield (lineno, reason) for each `python3 -m http.server` started in a way that hangs
    kali_shell or leaks the request log: chained after `&&` or wrapped in `( ... &)` (the
    whole list is backgrounded in a subshell, the output pipe stays open until the 300 s
    timeout and `$!` is the subshell, not python), backgrounded without every stream
    redirected, or logging INSIDE the folder it serves."""
    for m in _HTTP_SERVER.finditer(text):
        before = text[max(0, m.start() - 8): m.start()].rstrip()
        ln = _lineno(text, m.start())
        if before.endswith("&&") or before.endswith("("):
            yield ln, "http.server chained after `&&` / inside `( … &)`"
            continue
        end = _TAIL_END.search(text, m.end())
        tail = text[m.end(): end.start() if end else len(text)]
        # A `<listen_port>` placeholder's `>` is not a redirect; `</dev/null` starts with `/`.
        tail = re.sub(r"<[A-Za-z][^<>\n]*>", "PORT", tail)
        if not _BG_AMP.search(tail.replace("2>&1", "")):
            continue  # not a backgrounded command (prose or a foreground mention)
        if "</dev/null" not in tail or "2>&1" not in tail or not _STDOUT_TARGET.search(tail):
            yield ln, "backgrounded http.server without stdin/stdout/stderr all redirected"
        d = _SERVED_DIR.search(tail)
        out = _STDOUT_TARGET.search(tail)
        if d and out and out.group(1).startswith(d.group(1).rstrip("/") + "/"):
            yield ln, f"request log {out.group(1)} is inside the served folder {d.group(1)}"


class ReversePortHygieneTest(unittest.TestCase):
    def test_http_server_is_started_alone_with_the_log_outside(self):
        """R2-1/R2-2: python backgrounded ALONE (setup joined by `;`), every stream
        redirected, and the log outside the served folder."""
        offenders = []
        for path, text in _text_files():
            for ln, reason in _server_start_violations(text):
                offenders.append(f"{_rel(path)}:{ln} ({reason})")
        self.assertEqual(offenders, [], f"http.server start form: {offenders}")

    def test_no_hardcoded_attacker_lport(self):
        """FU-22: the reverse port is the payload-settings LPORT, never a literal."""
        # LPORT = <digits> or LPORT <digits> on one line, but not a `<LPORT>` placeholder,
        # a word, or a list number on the next line ("LHOST/LPORT\n 3.").
        pat = re.compile(r"\bLPORT[ \t]*=?[ \t]*\d", re.IGNORECASE)
        offenders = []
        for path, text in _text_files():
            for m in pat.finditer(text):
                offenders.append(f"{_rel(path)}:{_lineno(text, m.start())} -> {text[m.start():m.start()+24]!r}")
        self.assertEqual(
            offenders, [],
            "Hardcoded attacker LPORT; take LPORT from the "
            f'"Pre-Configured Payload Settings" block instead: {offenders}',
        )

    def test_no_http_server_delivery_on_a_sandbox_port(self):
        """FU-22: no delivery method starts `python3 -m http.server` on a sandbox port
        or with the port defaulted (default 8000, the sandbox's own service)."""
        offenders = []
        for path, text in _text_files():
            for ln, reason in _http_server_violation(text):
                offenders.append(f"{_rel(path)}:{ln} ({reason})")
        self.assertEqual(
            offenders, [],
            "http.server used as a delivery server on a sandbox port / default 8000: it "
            "clashes with the sandbox's own service and is unreachable from a target. "
            "Upload over the session, or serve on the single reverse port with an explicit "
            f"non-sandbox port: {offenders}",
        )

    def test_second_inbound_port_modules_carry_the_one_port_caveat(self):
        """FU-21: every mention of web_delivery / hta_server / office_word_hta has the
        one-port caveat ("inbound port") within 600 chars of it, not merely somewhere in
        the file."""
        offenders = []
        for path, text in _text_files():
            low = text.lower()
            for mod in _SECOND_PORT_MODULES:
                start = 0
                while True:
                    i = text.find(mod, start)
                    if i < 0:
                        break
                    start = i + len(mod)
                    window = low[max(0, i - 600): i + 600]
                    if "inbound port" not in window:
                        offenders.append(f"{_rel(path)}:{_lineno(text, i)} ({mod})")
        self.assertEqual(
            offenders, [],
            "A second-inbound-port module is named without the one-port caveat nearby "
            '("needs a second inbound port; the sandbox exposes only one"): '
            f"{offenders}",
        )

    def test_ngrok_troubleshooting_binds_4444(self):
        """FU-20: the ngrok/chisel handler binds 127.0.0.1:4444, not 'your LPORT'."""
        for name in ("cve_exploit_prompts.py", "phishing_social_engineering_prompts.py"):
            text = (_PROMPTS_DIR / name).read_text(encoding="utf-8")
            self.assertNotIn(
                "necessarily 4444", text,
                f"{name}: stale text claims the bind port is the LPORT, not 4444",
            )
            self.assertIn(
                "ReverseListenerBindPort 4444", text,
                f"{name}: ngrok/chisel troubleshooting must bind the handler on 4444",
            )

    def test_pool_mode_does_not_say_never_bind_lport(self):
        """FU-9/round-2: 'do not bind on LPORT' must be scoped to a tunnel; in pool mode
        the handler and LPORT are both the pool port."""
        for name in ("cve_exploit_prompts.py", "phishing_social_engineering_prompts.py"):
            text = (_PROMPTS_DIR / name).read_text(encoding="utf-8")
            # the correct, tunnel-scoped phrasing we introduced
            self.assertIn("WITH A TUNNEL", text,
                          f"{name}: the LPORT-bind caveat must be scoped to a tunnel")

    def test_tool_registry_does_not_advertise_exposing_the_sandbox(self):
        """FU-23: the registry must not teach `ngrok tcp` / `chisel server` by hand."""
        text = _TOOL_REGISTRY.read_text(encoding="utf-8")
        self.assertNotIn(
            "`ngrok tcp PORT`", text,
            "tool_registry advertises `ngrok tcp PORT`; the exposing tunnel is RedAmon-managed",
        )
        self.assertNotIn(
            "chisel server -p", text,
            "tool_registry advertises starting a chisel server; the exposing tunnel is RedAmon-managed",
        )


if __name__ == "__main__":
    unittest.main()
