"""
RedAmon Agent Parameters

Configuration constants for the agent orchestrator.
"""

# =============================================================================
# LLM CONFIGURATION
# =============================================================================

OPENAI_MODEL = "gpt-4.1"

INFORMATIONAL_SYSTEM_PROMPT = ""
EXPL_SYSTEM_PROMPT = ""
POST_EXPL_SYSTEM_PROMPT = ""


ACTIVATE_POST_EXPL_PHASE = True
POST_EXPL_PHASE_TYPE = "statefull" # stateless or statefull, it will be considered if ACTIVATE_POST_EXPL_PHASE = True

# =============================================================================
# PAYLOAD DIRECTION CONFIGURATION
# =============================================================================
#
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │                     PAYLOAD SELECTION DECISION LOGIC                        │
# ├─────────────────────────────────────────────────────────────────────────────┤
# │                                                                             │
# │  The system automatically selects REVERSE or BIND payload based on         │
# │  which settings you configure:                                              │
# │                                                                             │
# │  ┌─────────────────────────────────────────────────────────────────────┐   │
# │  │ IF LPORT is set (not None, > 0):                                    │   │
# │  │    → Use REVERSE payload (target connects TO you)                   │   │
# │  │    → Required: LHOST (your IP) + LPORT (your listening port)        │   │
# │  │    → Metasploit: set LHOST <ip>; set LPORT <port>                   │   │
# │  │                                                                     │   │
# │  │    Connection: TARGET ──────────────────────► ATTACKER              │   │
# │  │                        connects to LHOST:LPORT                      │   │
# │  └─────────────────────────────────────────────────────────────────────┘   │
# │                                                                             │
# │  ┌─────────────────────────────────────────────────────────────────────┐   │
# │  │ IF LPORT is None (or 0):                                            │   │
# │  │    → Use BIND payload (you connect TO target)                       │   │
# │  │    → Required: BIND_PORT_ON_TARGET (port target opens)              │   │
# │  │    → Metasploit: set LPORT <bind_port>  (NO LHOST needed!)          │   │
# │  │                                                                     │   │
# │  │    Connection: ATTACKER ──────────────────────► TARGET              │   │
# │  │                          connects to RHOST:BIND_PORT                │   │
# │  └─────────────────────────────────────────────────────────────────────┘   │
# │                                                                             │
# └─────────────────────────────────────────────────────────────────────────────┘
#
# EXAMPLES:
#
#   Example 1: REVERSE payload (you can receive connections)
#   ─────────────────────────────────────────────────────────
#   LHOST = "172.28.0.2"      # Your IP (required)
#   LPORT = 4444              # Your listening port (required)
#   BIND_PORT_ON_TARGET = ... # Ignored when LPORT is set
#
#   Result: meterpreter/reverse_tcp with LHOST=172.28.0.2, LPORT=4444
#
#
#   Example 2: BIND payload (you cannot receive, e.g. behind NAT)
#   ─────────────────────────────────────────────────────────────
#   LHOST = "172.28.0.2"      # Still set but NOT used for bind
#   LPORT = None              # None = use BIND payload
#   BIND_PORT_ON_TARGET = 4444  # Port the TARGET opens
#
#   Result: meterpreter/bind_tcp with LPORT=4444 (target opens this port)
#           After exploit, you connect to RHOST:4444
#



# -----------------------------------------------------------------------------
# REVERSE PAYLOAD SETTINGS (when LPORT is set)
# -----------------------------------------------------------------------------

# LHOST: Your attacker IP address (only used for REVERSE payloads)
#
#   REVERSE payload (LPORT is set):
#     - LHOST is REQUIRED - target connects BACK to this IP
#     - Must be reachable from the target network
#     - Examples: "172.28.0.2" (Docker), "192.168.1.50" (LAN), "10.10.14.5" (HTB VPN)
#
#   BIND payload (LPORT is None):
#     - LHOST is NOT USED - you can leave it as None
#     - You connect TO the target, not the other way around
#
LHOST = None

# LPORT: Your listening port for reverse connections.
#   - Set to a port number (e.g., 4444) → REVERSE payload
#   - Set to None → BIND payload (uses BIND_PORT_ON_TARGET instead)
LPORT = None  # Set to None to use BIND payload

# -----------------------------------------------------------------------------
# BIND PAYLOAD SETTINGS (when LPORT is None)
# -----------------------------------------------------------------------------

# BIND_PORT_ON_TARGET: Port the target opens when using bind payloads.
# After exploitation, YOU connect to RHOST:BIND_PORT_ON_TARGET.
# Only used when LPORT is None.
# Target's firewall must allow INBOUND connections on this port.
BIND_PORT_ON_TARGET = 4444

# -----------------------------------------------------------------------------
# REVERSE PAYLOAD TYPE (only applies when LPORT is set)
# -----------------------------------------------------------------------------

# PAYLOAD_USE_HTTPS: Determines the reverse payload connection type.
#   True  → reverse_https (encrypted, evades firewalls, uses port 443)
#   False → reverse_tcp (fastest, plain TCP on LPORT)
# NOTE: This is for the PAYLOAD (how target calls back to you).
#       This is DIFFERENT from the exploit's SSL setting (how you connect to target).
PAYLOAD_USE_HTTPS = False






# =============================================================================
# MCP SERVER URLs
# =============================================================================

MCP_CURL_URL = "http://host.docker.internal:8001/sse"
MCP_NAABU_URL = "http://host.docker.internal:8000/sse"
MCP_METASPLOIT_URL = "http://host.docker.internal:8003/sse"

# =============================================================================
# REACT AGENT SETTINGS
# =============================================================================

# Maximum iterations before forcing completion
MAX_ITERATIONS = 100

EXECUTION_TRACE_MEMORY_STEPS = 100

# Phase transition approval requirements
REQUIRE_APPROVAL_FOR_EXPLOITATION = True
REQUIRE_APPROVAL_FOR_POST_EXPLOITATION = True

# Maximum characters of tool output to send to LLM for analysis
# Large outputs (port scans, vuln reports) are truncated to avoid token limits
TOOL_OUTPUT_MAX_CHARS = 8000

# =============================================================================
# NEO4J SETTINGS
# =============================================================================

# Cypher query retry settings
CYPHER_MAX_RETRIES = 3

# =============================================================================
# DEBUG SETTINGS
# =============================================================================

CREATE_GRAPH_IMAGRE_ON_INIT = True

# =============================================================================
# LOGGING SETTINGS
# =============================================================================

# Log file settings
LOG_MAX_MB = 10  # Maximum size per log file in MB
LOG_BACKUP_COUNT = 5  # Number of backup files to keep (total ~60MB max with 10MB files)

# =============================================================================
# TOOL PHASE RESTRICTIONS
# =============================================================================

# Defines which tools are allowed in each phase
TOOL_PHASE_MAP = {
    "query_graph": ["informational", "exploitation", "post_exploitation"],
    "execute_curl": ["informational", "exploitation", "post_exploitation"],
    "execute_naabu": ["informational", "exploitation", "post_exploitation"],
    # Metasploit - single tool for all operations (stateful, persistent msfconsole)
    "metasploit_console": ["exploitation", "post_exploitation"],
}


def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
    return phase in allowed_phases


def get_allowed_tools_for_phase(phase: str) -> list:
    """Get list of tool names allowed in the given phase."""
    return [
        tool_name
        for tool_name, allowed_phases in TOOL_PHASE_MAP.items()
        if phase in allowed_phases
    ]
