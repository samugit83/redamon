"""The model is never told that a RedAmon tunnel reaches a web-delivery port.

A person's tunnel (ngrok or chisel, mcp/servers/tunnel_manager.py) forwards one port: the
handler's, to 4444 inside their Kali sandbox. Text that pairs chisel with 8080, or offers
"chisel instead" for web or HTA delivery, sends the agent after a server port no target can
reach. A chisel command line (`chisel server -p 8080 …`, a pivot the agent runs itself on a
target) is not about RedAmon's tunnel and is allowed.
"""
from __future__ import annotations

import os
import re
import unittest

AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TUNNEL_MANAGER = os.path.join(os.path.dirname(AGENTIC), "mcp", "servers", "tunnel_manager.py")


def _texts():
    paths = [os.path.join(AGENTIC, "utils.py")]
    prompts = os.path.join(AGENTIC, "prompts")
    paths += sorted(os.path.join(prompts, n) for n in os.listdir(prompts) if n.endswith(".py"))
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                yield f"{os.path.relpath(path, AGENTIC)}:{n}", line


_COMMAND = re.compile(r"chisel (server|client)\b")
_PAIR = re.compile(r"chisel.*\b8080\b|\b8080\b.*chisel", re.I)
# Chisel offered as the way out ("use chisel tunnel instead", "Method A or chisel."), not named
# beside ngrok as one of the two tunnels.
_CHISEL_INSTEAD = re.compile(r"\buse (the )?chisel\b(?! (server|client))|\bor chisel\s*[.|]", re.I)


class TunnelTextTests(unittest.TestCase):
    def test_no_text_pairs_chisel_with_8080(self):
        hits = [f"{where}: {line.strip()[:120]}" for where, line in _texts()
                if _PAIR.search(line) and not _COMMAND.search(line)]
        self.assertEqual(hits, [])

    def test_no_text_offers_chisel_for_a_delivery_server(self):
        hits = [f"{where}: {line.strip()[:120]}" for where, line in _texts()
                if re.search(r"web delivery|hta|srvport", line, re.I) and _CHISEL_INSTEAD.search(line)]
        self.assertEqual(hits, [])

    def test_the_tunnel_manager_forwards_only_the_handler_port(self):
        # What the texts above rely on: chisel's one remote, and ngrok's one TCP port.
        if not os.path.isfile(TUNNEL_MANAGER):
            self.skipTest("mcp/servers is not in this checkout")
        with open(TUNNEL_MANAGER, encoding="utf-8") as f:
            source = f.read()
        self.assertEqual(re.findall(r'"R:[^"]*"', source), ['"R:4444:localhost:4444"'])
        self.assertIn('["ngrok", "tcp", "4444"', source)

    def test_the_checks_see_the_prompts(self):
        seen = {where.split(":")[0] for where, _ in _texts()}
        self.assertIn("utils.py", seen)
        self.assertIn(os.path.join("prompts", "phishing_social_engineering_prompts.py"), seen)
        self.assertTrue(_PAIR.search("Verify chisel tunnels port 8080."))
        self.assertTrue(_CHISEL_INSTEAD.search("Use Method A or chisel."))
        self.assertTrue(_CHISEL_INSTEAD.search("Switch to Method A or use chisel tunnel instead."))
        self.assertIsNone(_CHISEL_INSTEAD.search("If using a tunnel (ngrok or chisel): DO NOT use HTA delivery."))
        self.assertIsNone(_PAIR.search("chisel forwards only 4444"))


if __name__ == "__main__":
    unittest.main()
