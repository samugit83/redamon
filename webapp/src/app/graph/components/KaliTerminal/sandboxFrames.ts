/**
 * The agent's `sandbox_status` frames on the Kali terminal socket (group 1, B.13).
 *
 * The agent proxy sends them as JSON text frames before the PTY starts or instead
 * of it; the PTY itself only ever sends binary frames (mcp/servers/terminal_server.py
 * forwards os.read() bytes), so a text frame parsed here never comes from a shell.
 */
import { describeWsClose } from '@/hooks/agentWsClose'
import { SANDBOX_STATUS, SANDBOX_STATUS_REASONS, SANDBOX_STATUS_STATES, type SandboxStatusPayload } from '@/lib/sandbox/contract'

// TERMINAL_CLOSE_UNAVAILABLE / TERMINAL_CLOSE_REFUSED of agentic/sandbox_contract.py,
// which the TS contract does not carry; KaliTerminal.sandbox.test.tsx pins them to it.
/** "Try again later": the sandbox could not start (ram, hard, error). */
export const TERMINAL_CLOSE_UNAVAILABLE = 1013
/** "Policy violation": this person may not use the sandbox on this project. */
export const TERMINAL_CLOSE_REFUSED = 1008

export const TERMINAL_STARTING_BANNER = 'Starting sandbox…'

const FRAME_MAX = 4096
const STATES: ReadonlySet<string> = new Set(SANDBOX_STATUS_STATES)
const REASONS: ReadonlySet<string> = new Set(SANDBOX_STATUS_REASONS)

/** The status in a text frame, or null for any other text (written to the terminal as before). */
export function parseSandboxFrame(text: string): SandboxStatusPayload | null {
  if (text.length > FRAME_MAX || !text.startsWith('{')) return null
  let value: unknown
  try { value = JSON.parse(text) } catch { return null }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const f = value as Record<string, unknown>
  if (f.type !== SANDBOX_STATUS || typeof f.state !== 'string' || !STATES.has(f.state)) return null
  const out: SandboxStatusPayload = { state: f.state as SandboxStatusPayload['state'] }
  if (typeof f.reason === 'string' && REASONS.has(f.reason)) out.reason = f.reason as SandboxStatusPayload['reason']
  if (f.limit && typeof f.limit === 'object') out.limit = f.limit as SandboxStatusPayload['limit']
  return out
}

/**
 * The terminal line for a close that follows an `unavailable` frame of reason
 * `frameReason`, or null to keep the usual disconnect line. A code alone proves
 * nothing: a refused ticket is 1008 too, and 1013 is any server's "try again later".
 */
export function sandboxCloseLine(code: number, reason: string, frameReason: string | null): string | null {
  if (!frameReason) return null
  if (code === TERMINAL_CLOSE_REFUSED && frameReason === 'refused') {
    return `Kali sandbox not available on this project (${describeWsClose(code, reason)})`
  }
  if (code === TERMINAL_CLOSE_UNAVAILABLE) return `The Kali sandbox could not start (${describeWsClose(code, reason)})`
  return null
}
