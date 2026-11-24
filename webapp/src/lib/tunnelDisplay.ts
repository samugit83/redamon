/**
 * What a tunnel indicator shows for one tunnel of the agent's /tunnel-status answer, which gives
 * each tunnel as `{active, status, host?, port?}`: `active` says the tunnel's process runs, `status`
 * whether it forwards ("on", "connecting", "off" or "error: <reason>"), and host and port come only
 * with "on". With no running sandbox the answer is `{active: false, status: "off"}`. The turn-off
 * control and personTunnelRuns read `active`; only indicators read this. Client safe.
 */
export type TunnelDisplay =
  | { state: 'on' }
  | { state: 'connecting' }
  | { state: 'error'; reason: string }
  | { state: 'off' }

/** A reason is the tunnel client's own log line: shown as text, and kept short. */
const REASON_MAX = 200

export function tunnelDisplay(entry: unknown): TunnelDisplay {
  if (!entry || typeof entry !== 'object') return { state: 'off' }
  const { status, active } = entry as { status?: unknown; active?: unknown }
  if (typeof status === 'string') {
    if (status === 'on') return { state: 'on' }
    if (status === 'connecting') return { state: 'connecting' }
    if (status.startsWith('error')) {
      const reason = status.replace(/^error:?\s*/, '').trim().slice(0, REASON_MAX)
      return { state: 'error', reason: reason || 'unknown error' }
    }
    return { state: 'off' }
  }
  // A sandbox image older than the `status` field (the window after an update, before every
  // sandbox restarts on the new image) sends `active` alone: read it as before. Remove this once
  // every sandbox reports `status`.
  return active === true ? { state: 'on' } : { state: 'off' }
}

