/**
 * Mint the short-lived ticket an agent WebSocket (chat, CypherFix triage and
 * CodeFix, Kali terminal) presents to the agent. The ticket names the one socket
 * it opens, and the agent refuses it on any other (HD-25). A failed mint answers
 * its cause (401 expired session, 403 no terminal grant, 404 no project access,
 * 409 version activation in progress), which the caller shows instead of a bare
 * "authentication failed".
 */
import { ApiError, readApiError, toApiError } from './apiError'

/** The sockets a ticket can open; the agent's WS_AUDIENCES (agentic/ws_ticket.py) lists the same four. */
export const WS_SOCKETS = ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'] as const
export type WsSocket = (typeof WS_SOCKETS)[number]

export function isWsSocket(value: unknown): value is WsSocket {
  return typeof value === 'string' && (WS_SOCKETS as readonly string[]).includes(value)
}

/**
 * The one rule for a ticket's session id (`sid`), at the mint (/api/agent/ws-ticket) and in the
 * agent's per-run writer check (/api/internal/agent/writer-check): 1-200 characters, no control
 * character or line separator. The agent refuses every run on a socket whose session id the check
 * refuses, so the ticket never signs one; and the id reaches the agent's log lines, where a CR/LF
 * would forge one. The browser's ids (useSession, the terminal, CypherFix) stay under 50 characters.
 */
export const WS_SESSION_ID_MAX = 200
// eslint-disable-next-line no-control-regex
const SESSION_ID_UNSAFE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/

export function isWsSessionId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= WS_SESSION_ID_MAX && !SESSION_ID_UNSAFE.test(value)
}

export type WsTicketResult =
  /** `ticket` is null when the deployment runs without ticket signing: the agent then accepts the socket. */
  | { ok: true; ticket: string | null }
  | { ok: false; error: ApiError }

const FALLBACK = 'Could not get a ticket for the agent connection'

export async function mintWsTicket(projectId: string, sessionId: string, socket: WsSocket): Promise<WsTicketResult> {
  try {
    const res = await fetch('/api/agent/ws-ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ projectId, sessionId, socket }),
    })
    if (!res.ok) return { ok: false, error: await readApiError(res, FALLBACK) }
    const body = await res.json().catch(() => null) as { ticket?: unknown } | null
    return { ok: true, ticket: typeof body?.ticket === 'string' && body.ticket ? body.ticket : null }
  } catch (err) {
    return { ok: false, error: toApiError(err, FALLBACK) }
  }
}
