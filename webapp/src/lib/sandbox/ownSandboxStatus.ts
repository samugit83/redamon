/**
 * The signed-in person's own Kali sandbox, as GET /api/agent/sandbox/status answers it: the server
 * decides whose sandbox and which view (the act_as one under act-as), never the browser. Read by the
 * Sessions panel (its stop warning and the reverse-port line) and by the Kali terminal. Client side.
 */
import { SESSION_ROUTE_STATUS } from './contract'
import { readReversePort, type ReversePort } from './reversePort'

export interface OwnSandboxStatus {
  /** When the sandbox stops, once it warns (epoch seconds); null otherwise. */
  stopAt: number | null
  /** The sandbox's reverse-shell port; null when no sandbox runs or nothing is known. */
  reversePort: ReversePort | null
}

type Instance = { state?: unknown; warn?: unknown; stop_at?: unknown }

/** The status, or null when it cannot be read (refused, failed, unreachable): a hint, never an error. */
export async function readOwnSandboxStatus(): Promise<OwnSandboxStatus | null> {
  try {
    const res = await fetch(SESSION_ROUTE_STATUS, { cache: 'no-store' })
    if (!res.ok) return null
    const body = await res.json() as { instances?: unknown }
    const instances = (Array.isArray(body?.instances) ? body.instances : [])
      .filter((i): i is Instance => !!i && typeof i === 'object')
    const warning = instances.find(i => i.warn === true && typeof i.stop_at === 'number')
    // A replacement can briefly list a draining instance next to the new one: the running one's port is the live one.
    const current = instances.find(i => i.state === 'running') ?? instances[0]
    return { stopAt: warning ? (warning.stop_at as number) : null, reversePort: readReversePort(current) }
  } catch {
    return null
  }
}
