/**
 * The text of an agent ERROR frame (live, or a persisted `error` row on
 * restore): its sentence plus what the agent sent about the cause, e.g.
 * "The agent run failed (agent_run_failed · RateLimitError · provider HTTP 429)".
 *
 * The agent sends an exception's class and a status, never its text, so each
 * part is safe to show; anything that does not look like one is dropped.
 */

const CODE = /^[a-z][a-z0-9_]{0,63}$/
const CLASS_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/

export interface AgentErrorPayload {
  message?: unknown
  code?: unknown
  error_class?: unknown
  provider_status?: unknown
  http_status?: unknown
  /** Which kind of provider 429 it was (llm_builder.provider_error_kind). */
  provider_error_kind?: unknown
  /** How long the agent waited for the rate limit to clear before giving up. */
  rate_limit_waited_s?: unknown
}

/** What a person can do about each kind of 429: they differ, and the status alone does not say. */
const KIND_HINTS: Record<string, string> = {
  rate_limited: "The model provider's rate limit did not clear. Send the message again in a minute, or use a plan or model with a higher limit.",
  quota_exhausted: 'The model provider account has no credit or quota left. Add credit, or pick another model.',
  request_too_large: "The request is larger than the provider's per-minute limit for this account. Use a plan or model with a higher limit.",
}

const httpStatus = (v: unknown): number | null =>
  typeof v === 'number' && Number.isInteger(v) && v >= 100 && v <= 599 ? v : null

export function agentErrorText(payload: AgentErrorPayload | null | undefined, fallback = 'Agent error'): string {
  const p = payload ?? {}
  const message = typeof p.message === 'string' && p.message.trim() ? p.message.trim() : fallback
  const parts: string[] = []
  if (typeof p.code === 'string' && CODE.test(p.code)) parts.push(p.code)
  if (typeof p.error_class === 'string' && CLASS_NAME.test(p.error_class)) parts.push(p.error_class)
  const provider = httpStatus(p.provider_status)
  if (provider) parts.push(`provider HTTP ${provider}`)
  const http = httpStatus(p.http_status)
  if (http) parts.push(`HTTP ${http}`)
  const waited = p.rate_limit_waited_s
  if (typeof waited === 'number' && Number.isInteger(waited) && waited > 0 && waited <= 86_400) {
    parts.push(`waited ${waited} s`)
  }
  const text = parts.length ? `${message} (${parts.join(' · ')})` : message
  const hint = typeof p.provider_error_kind === 'string' && Object.hasOwn(KIND_HINTS, p.provider_error_kind)
    ? KIND_HINTS[p.provider_error_kind]
    : null
  return hint ? `${text}. ${hint}` : text
}

/**
 * A resume the agent refused because another user's run holds a different set of
 * MCP Tool Plugins: the answer was not applied, the run is still paused, and the
 * agent sends the request again right after this frame. A refused new run is not
 * recoverable and has no request to show again.
 */
export function reopensPendingRequest(payload: (AgentErrorPayload & { recoverable?: unknown }) | null | undefined): boolean {
  return payload?.code === 'mcp_toolset_busy' && payload.recoverable === true
}

/** The one-time "chat is not being saved" notice: shown, but it does not end the run. */
export function isPersistFailedNotice(payload: AgentErrorPayload | null | undefined): boolean {
  return payload?.code === 'persist_failed'
}
