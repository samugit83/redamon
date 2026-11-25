/**
 * What a saved tunnel or capture change does outside the database, the same for the
 * user settings PUT (identity switch off) and PUT /api/admin/instance-settings (on):
 * the capture proxy container follows its master switch and the knobs baked in at spawn,
 * and the tunnel config reaches the person's own Kali sandbox. Best effort: a save must not fail
 * because the orchestrator, the agent or a sandbox is briefly unreachable, but it says so in a
 * warning rather than reading as applied.
 *
 * A person's tunnel is their own user row, pushed through the agent to their own Kali sandbox
 * only (`pushSandboxTunnel`; group 1, OD-G1-i, OQ-G1-2 default A). A sandbox starts with no tunnel and its start turns the person's `tunnelsEnabled` off (I19,
 * the gateway's `fresh` rule), so a stored "on" is pushed only when the person turned tunnels on
 * after the sandbox's start: by this save (which starts the sandbox first, so that start cannot
 * reset the flag after the push), or earlier, which a tunnel running in that sandbox proves. A
 * stored "on" whose sandbox runs no tunnel outlived a start whose reset never happened (the
 * webapp's call timed out while the orchestrator finished the start): it is turned off and the
 * person is told, never pushed. Tunnel configs and credentials are sent, never logged.
 *
 * Fail-closed rules: the instance tunnel's credentials (mirrored into one person's row with the
 * identity switch on) never reach a person's sandbox; one person's tunnel saves run one at a time;
 * under act-as the indicator shows no tunnel (the act_as sandbox never runs one).
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { agentFetch } from '@/lib/agentFetch'
import { getAuthzIdentity } from '@/lib/session'
import type { AuditActor } from '@/lib/auditActor'
import { sharedToolHeldBy } from '@/lib/authz/sharedTools'
import { logValue, safeErrorCode, upstreamFailure } from '@/lib/routeErrors'
import { ensureSandbox, sandboxStatus } from '@/lib/sandbox/gateway'
import { pushSandboxTunnel } from '@/lib/sandbox/agentCalls'
import { OrchestratorUnreachable, SandboxError } from '@/lib/sandbox/orchestratorClient'
import { instanceSettingsInForce } from '@/lib/sharedInstanceSettings'
import { followUpWarning, type SaveWarning } from '@/app/api/users/[id]/settings/saveWarnings'

/**
 * Egress toggles + body-storage policy are applied LIVE by the proxy's config-file
 * hot-reload (DB -> /spool/.capture-config.json -> proxy, within seconds), so a
 * save that touches ONLY those must NOT restart the proxy. A container recreate is
 * required solely for knobs baked in at spawn time: the listen port (proxy command)
 * and redact-secrets (the ingest container's env). Everything else is either
 * hot-reloaded or enforced outside the container (scope routing, retention cron).
 */
export const CAPTURE_RECREATE_FIELDS = ['captureProxyPort', 'captureProxyRedactSecrets'] as const

export interface CaptureValues {
  captureProxyEnabled: boolean
  captureProxyPort: number
  captureProxyMaxBodyKb: number
  captureProxyStoreBodies: boolean
  captureProxyRedactSecrets: boolean
  captureProxyScope: string
  captureProxyStoreReqBodies: boolean
  captureProxyStoreRespBodies: boolean
  captureProxyMaxStoreMb: number
  captureProxyBodyRules: unknown
  captureEgressBlockEmptyHost: boolean
  captureEgressBlockHardGuardrail: boolean
  captureEgressFailClosed: boolean
  captureEgressBlockUnresolvable: boolean
  captureEgressBlockPrivate: boolean
  captureEgressBlockLoopback: boolean
  captureEgressBlockLinkLocal: boolean
  captureEgressBlockCgnat: boolean
  captureEgressBlockReserved: boolean
  captureEgressBlockMulticast: boolean
  captureEgressBlockUnspecified: boolean
}

/**
 * Reconcile the capture proxy container with the saved state (plan §8.4): flipping the
 * master toggle, or changing a spawn-time knob while enabled, drives the orchestrator's
 * capture-proxy/{start,stop}. Null when nothing was due or the call succeeded.
 */
export async function reconcileCaptureProxy(
  settings: CaptureValues,
  { enabledChanged, recreateFieldChanged }: { enabledChanged: boolean; recreateFieldChanged: boolean },
): Promise<SaveWarning | null> {
  if (!enabledChanged && !(settings.captureProxyEnabled && recreateFieldChanged)) return null
  const orchUrl = process.env.RECON_ORCHESTRATOR_URL || 'http://recon-orchestrator:8010'
  return settings.captureProxyEnabled
    ? followUpWarning('orchestrator', 'The capture proxy was not started', () =>
      orchestratorFetch(`${orchUrl}/capture-proxy/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          port: settings.captureProxyPort,
          maxBodyKb: settings.captureProxyMaxBodyKb,
          storeBodies: settings.captureProxyStoreBodies,
          redactSecrets: settings.captureProxyRedactSecrets,
          scope: settings.captureProxyScope,
          // Granular body-storage policy -> CAPTURE_* env at proxy spawn.
          storeReqBodies: settings.captureProxyStoreReqBodies,
          storeRespBodies: settings.captureProxyStoreRespBodies,
          maxStoreMb: settings.captureProxyMaxStoreMb,
          bodyRules: JSON.stringify(settings.captureProxyBodyRules ?? {}),
          // Egress-guard toggles -> CAPTURE_EGRESS_* env at proxy spawn.
          egressBlockEmptyHost: settings.captureEgressBlockEmptyHost,
          egressBlockHardGuardrail: settings.captureEgressBlockHardGuardrail,
          egressFailClosed: settings.captureEgressFailClosed,
          egressBlockUnresolvable: settings.captureEgressBlockUnresolvable,
          egressBlockPrivate: settings.captureEgressBlockPrivate,
          egressBlockLoopback: settings.captureEgressBlockLoopback,
          egressBlockLinkLocal: settings.captureEgressBlockLinkLocal,
          egressBlockCgnat: settings.captureEgressBlockCgnat,
          egressBlockReserved: settings.captureEgressBlockReserved,
          egressBlockMulticast: settings.captureEgressBlockMulticast,
          egressBlockUnspecified: settings.captureEgressBlockUnspecified,
        }),
      }))
    : followUpWarning('orchestrator', 'The capture proxy was not stopped', () =>
      orchestratorFetch(`${orchUrl}/capture-proxy/stop`, { method: 'POST' }))
}

export interface TunnelSettings {
  tunnelsEnabled: boolean
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
}

type TunnelConfig = Pick<TunnelSettings, 'ngrokAuthtoken' | 'chiselServerUrl' | 'chiselAuth'>

/** The stop config: a tunnel manager given it runs no tunnel. */
export const EMPTY_TUNNEL: Readonly<TunnelConfig> = Object.freeze({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })

const NOT_APPLIED = 'The tunnel configuration was not applied'
const INSTANCE_CREDENTIALS =
  'Your saved tunnel credentials are the instance tunnel\'s, copied into your settings: tunnels are per person now. Type your own ngrok token or chisel server and auth, then turn tunnels on.'
const SANDBOX_RESTARTED =
  'Your tunnel is off: your Kali sandbox started again since you turned it on, and a new sandbox has no tunnel. Turn tunnels on again to start it.'

/**
 * One person's tunnel saves run one at a time in this process (the webapp runs one), so a later
 * "off" is never overtaken by an earlier "on" still waiting for a cold start.
 */
const personTunnelLocks = new Map<string, Promise<unknown>>()

export async function withPersonTunnelLock<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  const before = personTunnelLocks.get(userId) ?? Promise.resolve()
  const mine = before.catch(() => undefined).then(fn)
  const tail = mine.catch(() => undefined)
  personTunnelLocks.set(userId, tail)
  try {
    return await mine
  } finally {
    if (personTunnelLocks.get(userId) === tail) personTunnelLocks.delete(userId)
  }
}

/** The person a push is for: the settings row's own account. */
export interface TunnelPerson {
  userId: string
  /** This save turned tunnels on (stored off, now on): the person turned them on now. */
  turnedOn: boolean
  /** Who the `sandbox.started` row names when the push starts the person's sandbox. */
  actor: AuditActor | null
}

export interface TunnelPushResult {
  warning: SaveWarning | null
  /** The person's `tunnelsEnabled` after the push: the route answers this value. */
  tunnelsEnabled: boolean
}

const credentialsOf = (s: TunnelSettings): TunnelConfig =>
  ({ ngrokAuthtoken: s.ngrokAuthtoken, chiselServerUrl: s.chiselServerUrl, chiselAuth: s.chiselAuth })

/**
 * Push a saved tunnel config to `person`'s own sandbox. STRIDE I19: tunnels activate ONLY when
 * explicitly enabled; otherwise an empty (stop) config goes, so a credential edit alone never
 * brings a tunnel up.
 */
export async function pushTunnelConfig(settings: TunnelSettings, person: TunnelPerson): Promise<TunnelPushResult> {
  const enabled = settings.tunnelsEnabled
  if (!enabled) return { warning: await turnPersonTunnelOff(person.userId), tunnelsEnabled: false }
  if (!person.turnedOn && !(await personTunnelRuns(person.userId))) {
    // Stored "on", yet the person's sandbox runs no tunnel: it started (or stopped) after the
    // person turned tunnels on, and that start's reset never happened. Off, never pushed.
    await prisma.userSettings.updateMany({ where: { userId: person.userId, tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    const off = await turnPersonTunnelOff(person.userId)
    return { warning: off ?? restartedWarning(), tunnelsEnabled: false }
  }
  return pushPersonTunnel(settings, person)
}

async function pushPersonTunnel(settings: TunnelSettings, person: TunnelPerson): Promise<TunnelPushResult> {
  const { userId } = person
  if (await holdsInstanceCredentials(settings)) {
    // With the identity switch on, the instance tunnel group is mirrored into one person's row:
    // those credentials are the instance's, not that person's own.
    await prisma.userSettings.updateMany({ where: { userId, tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    return {
      warning: { service: 'kali_sandbox', message: INSTANCE_CREDENTIALS, code: 'tunnel_instance_credentials' },
      tunnelsEnabled: false,
    }
  }
  // Started (or found) here, before the push: a start caused by the agent's own acquire would
  // turn the flag off after this save turned it on, with the tunnel then up in that sandbox.
  let started: Awaited<ReturnType<typeof ensureSandbox>>
  try {
    started = await ensureSandbox(userId, { wait: true, actor: person.actor })
  } catch (err) {
    const code = ensureFailureCode(err)
    console.warn(`[tunnel] the person's sandbox did not start for the tunnel code=${code}`)
    return { warning: { service: 'orchestrator', message: NOT_APPLIED, code }, tunnelsEnabled: true }
  }
  // The start this call caused turned the flag off; the person turned it on after that start. The
  // person's saves run one at a time (withPersonTunnelLock), so no later "off" of theirs is undone.
  if (started.fresh) await prisma.userSettings.updateMany({ where: { userId }, data: { tunnelsEnabled: true } })

  const pushed = await pushSandboxTunnel(userId, credentialsOf(settings))
  if (!pushed.ok) {
    return { warning: { service: 'agent', message: NOT_APPLIED, code: pushed.code ?? 'agent_error', ...(pushed.status ? { upstreamStatus: pushed.status } : {}) }, tunnelsEnabled: true }
  }
  // Another start between the ensure and the push turned the flag off: that sandbox may now run
  // the tunnel the settings call off, so it goes off again.
  const now = await prisma.userSettings.findUnique({ where: { userId }, select: { tunnelsEnabled: true } })
  if (!now?.tunnelsEnabled) {
    const off = await turnPersonTunnelOff(userId)
    return { warning: off ?? restartedWarning(), tunnelsEnabled: false }
  }
  return { warning: null, tunnelsEnabled: true }
}

export interface TunnelPermissionOutcome {
  /** The stored "on" was turned off now. */
  turnedOff: boolean
  /** Set when the empty config could not reach the person's sandbox. */
  warning: SaveWarning | null
}

/**
 * A person who no longer holds platform:tunnels keeps no tunnel (G-03; HD-06: the permission guards
 * an internet-facing listener). Nothing else ends a tunnel that is already up: the agent's chisel
 * lookup (/api/global/tunnel-config) and the hold watcher go on while the stored flag is on, and a
 * lost permission is only read when the person next saves. So the flag is stored off and the empty
 * config pushed to the person's own sandbox. Asked by a demotion, a removed legacy grant and the
 * sandbox backstop (an expired override, a set or profile change, a switch rolled back). A person
 * who still holds it, or whose tunnel is off, is left alone.
 */
export async function enforceTunnelPermission(userId: string): Promise<TunnelPermissionOutcome> {
  const row = await prisma.userSettings.findUnique({ where: { userId }, select: { tunnelsEnabled: true } })
  if (!row?.tunnelsEnabled) return { turnedOff: false, warning: null }
  if (await sharedToolHeldBy(userId, 'tunnels')) return { turnedOff: false, warning: null }
  return withPersonTunnelLock(userId, async () => {
    const changed = await prisma.userSettings.updateMany({ where: { userId, tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    if (changed.count === 0) return { turnedOff: false, warning: null }
    console.info(`[tunnel] turned off for ${logValue(userId, 80)}: platform:tunnels is no longer held`)
    return { turnedOff: true, warning: await turnPersonTunnelOff(userId) }
  })
}

/**
 * The empty config to the person, through the agent, whenever an instance of their own view
 * lives (a draining one included: the agent sends a stop config to every instance of the person's
 * own view). With none there is nothing to turn off (a sandbox starts with no tunnel), and no
 * sandbox is started for it. A status that cannot be read sends it anyway.
 */
async function turnPersonTunnelOff(userId: string): Promise<SaveWarning | null> {
  try {
    const status = await sandboxStatus(userId)
    if (!status.instances.some((i) => i.view === 'own')) return null
  } catch {
    // Unknown: send the stop config.
  }
  const pushed = await pushSandboxTunnel(userId, EMPTY_TUNNEL)
  if (pushed.ok) return null
  return { service: 'agent', message: 'The tunnel was not turned off', code: pushed.code ?? 'agent_error', ...(pushed.status ? { upstreamStatus: pushed.status } : {}) }
}

/**
 * The agent's /tunnel-status path for the tunnel indicator: the signed-in person's own tunnel, so
 * nobody sees another person's tunnel host. Null (no tunnel shown) without a session, and under
 * act-as: the acting admin's Kali work runs in the member's `act_as` sandbox, which never runs a
 * tunnel, and the member's own tunnel is not the admin's to see. Whose tunnel is shown, not who
 * may ask: the route keeps its own login check.
 */
export async function tunnelStatusPath(): Promise<string | null> {
  const identity = await getAuthzIdentity()
  if (!identity || identity.actingAs) return null
  return `/tunnel-status?user_id=${encodeURIComponent(identity.session.userId)}`
}

/** Whether a tunnel runs in the person's sandbox now (the agent asks it); an agent that cannot say is a no. */
async function personTunnelRuns(userId: string): Promise<boolean> {
  try {
    const res = await agentFetch(`/tunnel-status?user_id=${encodeURIComponent(userId)}`, { cache: 'no-store' }, { timeoutMs: 5_000 })
    if (!res.ok) return false
    const body = await res.json() as Partial<Record<'ngrok' | 'chisel', { active?: unknown }>> | null
    return body?.ngrok?.active === true || body?.chisel?.active === true
  } catch {
    return false
  }
}

/**
 * Whether the settings hold the instance tunnel's credentials (identity switch on): its ngrok token,
 * or its chisel server with its auth. Compared, never logged.
 */
async function holdsInstanceCredentials(settings: TunnelSettings): Promise<boolean> {
  const instance = await instanceSettingsInForce()
  if (!instance) return false
  if (settings.ngrokAuthtoken && settings.ngrokAuthtoken === instance.ngrokAuthtoken) return true
  return !!settings.chiselServerUrl && settings.chiselServerUrl === instance.chiselServerUrl
    && settings.chiselAuth === instance.chiselAuth
}

function restartedWarning(): SaveWarning {
  return { service: 'kali_sandbox', message: SANDBOX_RESTARTED, code: 'tunnel_off_sandbox_restarted' }
}

function ensureFailureCode(err: unknown): string {
  if (err instanceof SandboxError) return err.code
  if (err instanceof OrchestratorUnreachable) return upstreamFailure('orchestrator', err.cause_, '').body.code
  return safeErrorCode(err)
}

/** Tests only: forget the locks. */
export function resetTunnelEffectsForTests(): void {
  personTunnelLocks.clear()
}
