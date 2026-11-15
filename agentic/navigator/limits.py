"""AI Navigator limits (plan Appendix A). Code constants, no environment variable.

The webapp holds its own copy of the ones it enforces (webapp/src/lib/navigator/constants.ts).
"""

RUN_TIMEOUT_S = 180
TOOL_CALLS_PER_SPECIALIST = 6
TOOL_CALLS_PER_RUN = 20
TOOL_TIMEOUT_S = 30
RUN_CYPHER_TIMEOUT_S = 60
WIKI_READ_MAX_CHARS = 6000
ANSWER_MAX_CHARS = 20000
AGENT_MAX_NAVIGATOR_RUNS = 16
WORKSPACE_FILES_PER_RUN = 3

WIKI_DIR = "/app/wiki"
WIKI_RECHECK_S = 60
WIKI_SEARCH_MAX_K = 8
WIKI_QUERY_MAX_CHARS = 200
WIKI_SNIPPET_CHARS = 240
WIKI_SUMMARY_CHARS = 160

ROUTES = ("docs", "graph", "records", "workspace", "direct")
DATA_ROUTES = ("graph", "records", "workspace")

#: Event field caps (Appendix B); the webapp checks them again.
MAX_DELTA_CHARS = 4000
MAX_SUMMARY_CHARS = 200
MAX_DETAIL_CHARS = 8000
MAX_ERROR_MESSAGE_CHARS = 300
MAX_CITATIONS = 20
