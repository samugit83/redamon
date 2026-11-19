/**
 * AI Navigator limits, route ids and error codes (plan Appendix A). Code constants on purpose: no
 * environment variable tunes them, and the agent holds its own copy of the ones it enforces
 * (agentic/navigator/limits.py).
 */

export const MAX_MESSAGE_CHARS = 4000
export const MAX_TITLE_CHARS = 80
export const MAX_THREADS_PER_PERSON_PROJECT = 200
/** A project retention of 0 counts as this, so a conversation in use is never deleted. */
export const NAVIGATOR_MIN_RETENTION_DAYS = 1
/** The project form shows 90 for an unset retention; the Navigator follows it. */
export const NAVIGATOR_DEFAULT_RETENTION_DAYS = 90
/** The sweep's backstop for a thread with no message (the API never creates one). */
export const EMPTY_THREAD_MAX_AGE_S = 3600
export const MAX_MESSAGES_PER_THREAD = 200
export const HISTORY_TURNS = 12
export const HISTORY_CHARS = 24000
export const THREAD_LIST_MAX = 200
export const THREAD_PAGE_SIZE = 50

/** Per person: the `navigator` bucket (per 5 minutes) and `navigator_day`. */
export const RATE_MESSAGES_PER_5_MIN = 20
export const RATE_MESSAGES_PER_DAY = 300

export const MAX_RUNS_PER_PERSON = 2
export const MAX_RUNS_PER_PERSON_PROJECT = 1
export const RUN_TIMEOUT_S = 180
/** A registry entry, reservations included, outlives a crashed stream by at most this. */
export const RUN_EXPIRY_S = RUN_TIMEOUT_S + 60
export const CREDENTIAL_BYTES = 32

export const TOOL_CALLS_PER_RUN = 20
export const TOOL_TIMEOUT_S = 30
export const RUN_CYPHER_TIMEOUT_S = 60
export const TOOL_RESULT_MAX_BYTES = 32768
export const ROWS_MAX = 200
export const ANSWER_MAX_CHARS = 20000
export const NDJSON_LINE_MAX_BYTES = 65536
export const WORKSPACE_READ_MAX_BYTES = 65536
export const WORKSPACE_TREE_MAX_DEPTH = 4
export const WORKSPACE_MAX_ENTRIES = 300

export const NAVIGATOR_ROUTES = ['docs', 'graph', 'records', 'workspace', 'direct'] as const
export type NavigatorRoute = (typeof NAVIGATOR_ROUTES)[number]
/** The routes that read project data through the tool callbacks; `docs` and `direct` read none. */
export const DATA_ROUTES = ['graph', 'records', 'workspace'] as const
export type DataRoute = (typeof DATA_ROUTES)[number]

/** The header that carries the run's credential on a tool callback. */
export const NAVIGATOR_CREDENTIAL_HEADER = 'x-redamon-navigator'

/**
 * Every error code a Navigator route or tool answers, with its fixed sentence. Never an
 * exception's text, an upstream body or a query fragment (routeErrors.ts).
 */
export const NAVIGATOR_ERRORS = {
  not_found: 'Not found',
  navigator_disabled: 'AI Navigator is turned off on this server.',
  navigator_not_available: "AI Navigator isn't available with this kind of access.",
  owner_disallowed: "The owner of this project hasn't enabled AI Navigator for collaborators.",
  navigator_unavailable: "AI Navigator isn't configured on this server. Ask your administrator to run ./redamon.sh update.",
  rate_limited: "You're sending messages too fast.",
  busy: 'An answer is already being written for you on this project, maybe in another tab.',
  thread_full: 'This conversation is full. Start a new one.',
  too_many_threads: 'You have too many conversations on this project. Delete some in History.',
  project_busy: 'This project is being restored or transferred. Try again in a minute.',
  invalid_message: 'The message must be between 1 and 4000 characters.',
  agent_unreachable: "AI Navigator's service isn't reachable right now.",
  agent_outdated: 'The agent is older than the web app. Rebuild it with ./redamon.sh update.',
  agent_protocol: 'The answer could not be read.',
  answer_too_long: 'The answer was cut because it grew too long.',
  tool_budget: 'This answer used every tool call it is allowed.',
  tool_unknown: 'No such tool.',
  tool_refused: 'You may not read this on this project.',
  tool_failed: 'The tool could not read this data.',
  tool_timeout: 'The tool took too long.',
  invalid_args: 'The tool arguments were not valid.',
  run_gone: 'This answer is no longer running.',
} as const
export type NavigatorErrorCode = keyof typeof NAVIGATOR_ERRORS
