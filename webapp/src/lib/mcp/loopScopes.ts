/**
 * The driver-token rule of Agent in the Loop.
 *
 * A driver reads target-controlled text at every step. If its token could also
 * start scans or run sandbox commands, injected text could make the driver call
 * those tools directly over MCP, around every gate RedAmon applies to its own
 * agent. So a token that holds `agent:loop` may hold read scopes only besides it.
 *
 * Computed from MCP_SCOPE_COPY, never a hand list: a new write scope is covered
 * the day it is added, and a scope missing from the table counts as a problem
 * (fail closed).
 */
import { MCP_SCOPE_COPY } from './scopeCopy'

export const LOOP_SCOPE = 'agent:loop'

/** The scopes that make `scopes` too broad for a driver token (empty when fine). */
export function loopTokenProblem(scopes: readonly string[]): string[] {
  const copy = MCP_SCOPE_COPY as Record<string, { access?: string } | undefined>
  return scopes.filter((s) => s !== LOOP_SCOPE && copy[s]?.access !== 'read')
}
