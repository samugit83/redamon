"""
Per-tool output-offload policy.

For every registered tool, declares one of:
    "never"  - output is reliably small/structured; always inline
    "always" - output is reliably huge; always offload to a file
    "auto"   - offload only if len(output) > OFFLOAD_THRESHOLD

Tools not listed default to "auto". Per-call override via the `output_mode`
arg ("inline" | "file" | "auto") wins over this map.
"""

OFFLOAD_THRESHOLD = 20_000

OFFLOAD_POLICY = {
    # never: structured + small
    "query_graph": "never",
    "web_search": "never",
    "cve_intel": "never",
    "shodan": "never",
    "google_dork": "never",
    "tradecraft_lookup": "never",
    "tradecraft_search": "never",
    "tradecraft_ask": "never",
    "msf_restart": "never",

    # always: reliably huge
    "execute_nuclei": "always",
    "execute_playwright": "always",

    # everything else falls through to "auto"
}


def get_offload_mode(tool_name: str) -> str:
    return OFFLOAD_POLICY.get(tool_name, "auto")
