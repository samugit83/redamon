/**
 * A person's reverse-shell port, as the orchestrator reports it for one sandbox (FU-24, D-B):
 * `reverse_port`, where 4444 means none (the pool never hands 4444 out), and `reverse_port_state`,
 * which says why there is none. An orchestrator older than D-B sends no state: its 4444 still means
 * none, any other port is assigned, and a value outside the contract is read as unknown, never as an
 * error. Client safe: the Sessions panel, the Kali terminal and the Operations view read it, and the
 * status route uses it to decide what it passes on.
 */

import { REVERSE_PORT_ASSIGNED, REVERSE_PORT_POOL_FULL, reversePortState, type ReversePortState } from './contract'

/** DEFAULT_REVERSE_PORT of the Python contract: the port a sandbox listens on when it has no pool port. */
export const NO_REVERSE_PORT = 4444

/**
 * What is known of a sandbox's reverse port. `port` is set exactly when `state` is `assigned`;
 * `state` null with no port is "none, reason not reported" (an older orchestrator's 4444).
 */
export interface ReversePort {
  port: number | null
  state: ReversePortState | null
}

export const REVERSE_PORT_ASSIGNED_TEXT = 'Your reverse-shell port (LPORT): {port}'
export const REVERSE_PORT_POOL_FULL_TEXT =
  'No reverse-shell port: the port pool is full. Use your tunnel or a bind payload'
export const REVERSE_PORT_NONE_TEXT = 'No reverse-shell port: use your tunnel or a bind payload'

const isPort = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 1 && (v as number) <= 65535

/** The port as the contract allows it, or null for anything else. */
export function reversePortValue(v: unknown): number | null {
  return isPort(v) ? v : null
}

/**
 * The reverse port of one status, list or ensure entry, or null when the entry says nothing usable.
 * A state that contradicts the port (assigned with no port, or with 4444) is unknown, not a port.
 */
export function readReversePort(entry: object | null | undefined): ReversePort | null {
  if (!entry) return null
  const raw = entry as Record<string, unknown>
  const port = reversePortValue(raw.reverse_port)
  const state = reversePortState(raw.reverse_port_state)
  if (state === REVERSE_PORT_ASSIGNED) return port !== null && port !== NO_REVERSE_PORT ? { port, state } : null
  if (state) return { port: null, state }
  if (port === null) return null
  return port === NO_REVERSE_PORT ? { port: null, state: null } : { port, state: REVERSE_PORT_ASSIGNED }
}

/** The line a person reads about their own port, or null when nothing is known. */
export function reversePortLine(info: ReversePort | null): string | null {
  if (!info) return null
  if (info.state === REVERSE_PORT_ASSIGNED && info.port !== null) return REVERSE_PORT_ASSIGNED_TEXT.replace('{port}', String(info.port))
  if (info.state === REVERSE_PORT_POOL_FULL) return REVERSE_PORT_POOL_FULL_TEXT
  return REVERSE_PORT_NONE_TEXT
}

/** The Operations view's short cell: the port, "none (pool full)", "none", or null when unknown. */
export function reversePortCell(info: ReversePort | null): string | null {
  if (!info) return null
  if (info.state === REVERSE_PORT_ASSIGNED && info.port !== null) return String(info.port)
  if (info.state === REVERSE_PORT_POOL_FULL) return 'none (pool full)'
  return 'none'
}
