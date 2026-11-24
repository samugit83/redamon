/**
 * Whose agent runs PAUSE ALL stops (HD-07), as the emergency-stop route answers it: an
 * admin's press stops every user's, anyone else's only their own. The texts here are the
 * toolbar's tooltip before a press and the graph page's message after it.
 */
export type EmergencyStopScope = 'all' | 'own'

export function isEmergencyStopScope(value: unknown): value is EmergencyStopScope {
  return value === 'all' || value === 'own'
}

const PAUSE_TAIL = 'Use if scanning or exploiting unwanted targets. CypherFix triage and CodeFix runs are not stopped.'

export function emergencyPauseTitle(scope: EmergencyStopScope | undefined): string {
  const agents = scope === 'own'
    ? "Stop your own agent runs (other users' runs keep going)"
    : scope === 'all'
      ? "Stop every user's agent runs"
      // Until the route answers: a promise either way could be false.
      : "Stop agent runs (every user's for an administrator, otherwise only your own)"
  const sandboxes = scope === 'own' ? 'your own Kali sandbox' : scope === 'all' ? 'every Kali sandbox' : 'Kali sandboxes'
  return `EMERGENCY PAUSE - ${agents} and ${sandboxes} (shells, sessions and tunnels end), and freeze this project's running scans. ${PAUSE_TAIL}`
}

export function agentStopFailureLabel(scope: EmergencyStopScope | undefined): string {
  return scope === 'own' ? 'Your AI agents' : 'AI agents'
}

/** What the press did to agent runs, from the route's `{scope, stopped}`; null when unknown. */
export function agentStopSummary(answer: unknown): string | null {
  if (!answer || typeof answer !== 'object') return null
  const { scope, stopped } = answer as { scope?: unknown; stopped?: unknown }
  if (!isEmergencyStopScope(scope)) return null
  const count = typeof stopped === 'number' ? stopped : 0
  if (scope === 'all') return `AI agents: stopped ${count} ${count === 1 ? 'run' : 'runs'} of every user.`
  return count === 0
    ? "AI agents: you had no run to stop. Other users' runs keep going."
    : `AI agents: stopped ${count} of your own runs. Other users' runs keep going.`
}

/**
 * What the press did to the Kali sandboxes, from the route's `sandboxes` (`{stopped}` or `{error}`),
 * which it sends whether or not the agent answered. A failed stop leaves shells, handlers and tunnels
 * running, so it is never folded into the agent's success message. Null when the answer has none.
 */
export function sandboxStopSummary(
  answer: unknown, scope: EmergencyStopScope | undefined,
): { ok: true; text: string } | { ok: false; text: string } | null {
  if (!answer || typeof answer !== 'object') return null
  const outcome = (answer as { sandboxes?: unknown }).sandboxes
  if (!outcome || typeof outcome !== 'object') return null
  const { stopped, error } = outcome as { stopped?: unknown; error?: unknown }
  if (typeof error === 'string') {
    const code = /^[a-z0-9_]{1,64}$/.test(error) ? error : 'unknown'
    return {
      ok: false,
      text: `Kali sandboxes: not stopped (${code}); their shells, handlers and tunnels may still be running.`,
    }
  }
  if (typeof stopped !== 'number') return null
  const what = stopped === 1 ? 'sandbox' : 'sandboxes'
  if (scope === 'own') {
    return { ok: true, text: stopped === 0 ? 'Kali sandboxes: you had none running.' : `Kali sandboxes: stopped ${stopped} of your own.` }
  }
  return { ok: true, text: stopped === 0 ? 'Kali sandboxes: none was running.' : `Kali sandboxes: stopped ${stopped} ${what}.` }
}
