/**
 * What a saved tunnel or capture change does outside the database, the same for the
 * user settings PUT (identity switch off) and PUT /api/admin/instance-settings (on):
 * the capture proxy container follows its master switch and the knobs baked in at spawn,
 * and the tunnel config reaches a tunnel manager. Best effort: a save must not fail because
 * the orchestrator, the agent or a sandbox is briefly unreachable, but it says so in a
 * warning rather than reading as applied.
 *
 * Tunnels follow the Kali sandbox mode (group 1, OD-G1-i, OQ-G1-2 default A). Shared: the one
 * shared kali-sandbox takes the config directly, as before. Per-user: a person's tunnel is
 * their own user row, pushed through the agent to their own sandbox only (`pushSandboxTunnel`).
 * A sandbox starts with no tunnel and its start turns the person's `tunnelsEnabled` off (I19,
 * the gateway's `fresh` rule), so a stored "on" is pushed only when the person turned tunnels on
 * after the sandbox's start: by this save (which starts the sandbox first, so that start cannot
 * reset the flag after the push), or earlier, which a tunnel running in that sandbox proves. A
 * stored "on" whose sandbox runs no tunnel outlived a start whose reset never happened (the
 * webapp's call timed out while the orchestrator finished the start): it is turned off and the
 * person is told, never pushed. Tunnel configs and credentials are sent, never logged.
 *
 * Fail-closed rules: before the orchestrator names a mode, nothing that carries a credential is
 * pushed and nothing tied to a person is answered; a start that answers another mode than the one
 * read pushes nothing; the instance tunnel's credentials (mirrored into one person's row with the
 * identity switch on) never reach a person's sandbox; one person's tunnel saves run one at a time.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { agentFetch } from '@/lib/agentFetch'
import { getEffectiveUser } from '@/lib/session'
import type { AuditActor } from '@/lib/auditActor'
import { safeErrorCode, upstreamFailure } from '@/lib/routeErrors'
import { ensureSandbox, sandboxMode, sandboxStatus } from '@/lib/sandbox/gateway'
import { pushSandboxTunnel } from '@/lib/sandbox/agentCalls'
import { DEFAULT_MODE, type SandboxMode } from '@/lib/sandbox/contract'
import { OrchestratorUnreachable, SandboxError } from '@/lib/sandbox/orchestratorClient'
import { instanceSettingsInForce, instanceTunnelDown } from '@/lib/sharedInstanceSettings'
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
 * The sandbox mode tunnels follow. `named`: the orchestrator said it, now or earlier in this
 * process (the mode changes only with an orchestrator restart). With no answer yet the contract's
 * DEFAULT_MODE stands in, `named: false`, and nothing that carries a credential is pushed on it.
 */
export interface TunnelMode {
  mode: SandboxMode
  named: boolean
}

let lastNamedMode: SandboxMode | null = null

/**
 * Never throws. A per_user answer turns the shared container's instance tunnel off (the flip),
 * once it has worked; a shared answer re-arms it, for the next switch to per_user.
 */
export async function tunnelMode(): Promise<TunnelMode> {
  try {
    const mode = await sandboxMode()
    lastNamedMode = mode
    if (mode === 'per_user') startSharedTunnelFlip()
    else flip.done = false
    return { mode, named: true }
  } catch {
    return lastNamedMode ? { mode: lastNamedMode, named: true } : { mode: DEFAULT_MODE, named: false }
  }
}

// A shared container that is gone fails at once; a hung one must not hold the flip forever.
const SHARED_FLIP_TIMEOUT_MS = 10_000
// A failed flip is tried again at the next per_user read after this, not at every read.
const FLIP_RETRY_MS = 60_000

const flip: { done: boolean; running: Promise<void> | null; retryAt: number } = { done: false, running: null, retryAt: 0 }

function startSharedTunnelFlip(): void {
  if (flip.done || flip.running || Date.now() < flip.retryAt) return
  flip.running = turnSharedTunnelOff()
    .then((done) => {
      flip.done = done
      if (!done) flip.retryAt = Date.now() + FLIP_RETRY_MS
    })
    .finally(() => { flip.running = null })
}

/**
 * The flip (WI-S17-3): the shared container keeps running after per-user mode starts, and its
 * instance tunnel with it, so a webapp process that reads per_user stops it, then marks the unused
 * instance tunnel row off. A container that does not exist runs no tunnel. No person's
 * `tunnelsEnabled` changes: a restarted webapp process runs this again while per-user tunnels are
 * up. True when the shared container runs no tunnel now; one log line either way.
 */
async function turnSharedTunnelOff(): Promise<boolean> {
  let failure: string | null = null
  let state = 'turned off'
  try {
    const res = await sharedTunnelRequest(EMPTY_TUNNEL, AbortSignal.timeout(SHARED_FLIP_TIMEOUT_MS))
    if (!res.ok) failure = `kali_sandbox_${res.status}`
  } catch (err) {
    const { code, cause } = upstreamFailure('kali_sandbox', err, '').body
    if (cause === 'ENOTFOUND') state = 'absent (ENOTFOUND)'
    else failure = cause ? `${code} cause=${cause}` : code
  }
  if (failure) {
    console.warn(`[tunnel] per-user sandboxes: the shared sandbox's tunnel was not turned off code=${failure}; tried again later`)
    return false
  }
  try {
    await instanceTunnelDown()
  } catch (err) {
    console.warn(`[tunnel] per-user sandboxes: the shared sandbox's tunnel is ${state}; the instance tunnel setting was not marked off code=${safeErrorCode(err)}`)
    return true
  }
  console.info(`[tunnel] per-user sandboxes: the shared sandbox's tunnel is ${state}`)
  return true
}

/**
 * Per-user mode: the stop config to the shared container, the one thing the unused instance tunnel
 * may still do (an administrator's "off" when the flip could not reach it).
 */
export function pushSharedTunnelOff(): Promise<SaveWarning | null> {
  return pushSharedTunnel(EMPTY_TUNNEL)
}

// How long a decision that needs a named mode waits for the orchestrator, and how often it asks.
let modeWait = { retryMs: 5_000, maxMs: 120_000 }
const modeWaits = new Set<Promise<void>>()

/**
 * Runs `then` with the mode once the orchestrator names it, asking every few seconds for up to two
 * minutes (the orchestrator can start after the shared container, whose boot call needs it). Never
 * throws; one log line when no mode was named in time.
 */
export function afterTunnelModeNamed(what: string, then: (mode: SandboxMode) => Promise<void>): void {
  const task = (async () => {
    const until = Date.now() + modeWait.maxMs
    while (Date.now() < until) {
      const known = await tunnelMode()
      if (known.named) {
        try {
          await then(known.mode)
        } catch (err) {
          console.warn(`[tunnel] ${what} not done code=${safeErrorCode(err)}`)
        }
        return
      }
      await new Promise((r) => setTimeout(r, modeWait.retryMs))
    }
    console.warn(`[tunnel] ${what} not done: the orchestrator named no sandbox mode in time`)
  })()
  modeWaits.add(task)
  void task.finally(() => modeWaits.delete(task))
}

/**
 * Per-user mode: one person's tunnel saves run one at a time in this process (the webapp runs one),
 * so a later "off" is never overtaken by an earlier "on" still waiting for a cold start.
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

/**
 * The shared kali-sandbox's tunnel manager, with the TUNNEL_AUTH_TOKEN so a rogue container
 * can't drive :8015 (S14).
 */
function sharedTunnelRequest(config: TunnelConfig, signal?: AbortSignal): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = process.env.TUNNEL_AUTH_TOKEN
  if (token) headers['Authorization'] = `Bearer ${token}`
  return fetch('http://kali-sandbox:8015/tunnel/configure', {
    method: 'POST',
    headers,
    body: JSON.stringify(config),
    ...(signal ? { signal } : {}),
  })
}

function pushSharedTunnel(config: TunnelConfig): Promise<SaveWarning | null> {
  return followUpWarning('kali_sandbox', NOT_APPLIED, () => sharedTunnelRequest(config))
}

/** The person a per-user push is for: the settings row's own account. */
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
 * Push a saved tunnel config. STRIDE I19: tunnels activate ONLY when explicitly enabled;
 * otherwise an empty (stop) config goes, so a credential edit alone never brings a tunnel up.
 * Shared mode: the shared container, as before. Per-user mode: `person`'s own sandbox (no person,
 * as from the instance settings: nothing, tunnels are per person there). A mode nobody named
 * pushes no credential; its stop config goes both ways.
 */
export async function pushTunnelConfig(
  settings: TunnelSettings,
  { mode, named }: TunnelMode,
  person: TunnelPerson | null,
): Promise<TunnelPushResult> {
  const enabled = settings.tunnelsEnabled
  if (!named) {
    if (enabled) {
      console.warn('[tunnel] a tunnel save before the orchestrator named the sandbox mode: not pushed')
      return { warning: { service: 'orchestrator', message: NOT_APPLIED, code: 'sandbox_mode_unknown' }, tunnelsEnabled: true }
    }
    const shared = await pushSharedTunnel(EMPTY_TUNNEL)
    const own = person ? await turnPersonTunnelOff(person.userId) : null
    return { warning: shared ?? own, tunnelsEnabled: false }
  }
  if (mode === 'shared') {
    return { warning: await pushSharedTunnel(enabled ? credentialsOf(settings) : EMPTY_TUNNEL), tunnelsEnabled: enabled }
  }
  if (!person) return { warning: null, tunnelsEnabled: enabled }
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
    // With the identity switch on, the instance tunnel group is mirrored into one person's row: in
    // per-user mode those credentials are the instance's, not that person's own.
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
  // The orchestrator switched back to shared since the mode was read (a roll-back): the person's
  // credentials would go to the shared container, which per-user saves never feed.
  if (started.mode !== 'per_user') {
    console.warn('[tunnel] the sandbox mode changed during a tunnel save: not pushed')
    return { warning: { service: 'orchestrator', message: NOT_APPLIED, code: 'sandbox_mode_changed' }, tunnelsEnabled: true }
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

/**
 * The empty config to the person, through the agent, whenever an instance of their own view
 * lives (a draining one included: the agent sends a stop config to every instance of the person's
 * own view). With none there is nothing to turn off (a sandbox starts with no tunnel), and no
 * sandbox is started for it. A status that cannot be read sends it anyway.
 */
async function turnPersonTunnelOff(userId: string): Promise<SaveWarning | null> {
  try {
    const status = await sandboxStatus(userId)
    if (status.mode === 'per_user' && !status.instances.some((i) => i.view === 'own')) return null
  } catch {
    // Unknown: send the stop config.
  }
  const pushed = await pushSandboxTunnel(userId, EMPTY_TUNNEL)
  if (pushed.ok) return null
  return { service: 'agent', message: 'The tunnel was not turned off', code: pushed.code ?? 'agent_error', ...(pushed.status ? { upstreamStatus: pushed.status } : {}) }
}

/**
 * The agent's /tunnel-status path for the tunnel indicator: shared mode the one instance tunnel;
 * per-user mode the signed-in effective person's own (the member under act-as), so nobody sees
 * another person's tunnel host. Null when there is no effective person. Whose tunnel is shown,
 * not who may ask: the route keeps its own login check.
 */
export async function tunnelStatusPath(): Promise<string | null> {
  const { mode, named } = await tunnelMode()
  // No mode named yet: the one instance tunnel may be nobody's, a person's may be anybody's.
  if (!named) return null
  if (mode !== 'per_user') return '/tunnel-status'
  const person = await getEffectiveUser()
  return person ? `/tunnel-status?user_id=${encodeURIComponent(person.userId)}` : null
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

/** Tests only: forget the mode named, the flip, the waits and the locks. */
export function resetTunnelEffectsForTests(): void {
  lastNamedMode = null
  flip.done = false
  flip.running = null
  flip.retryAt = 0
  modeWait = { retryMs: 5_000, maxMs: 120_000 }
  modeWaits.clear()
  personTunnelLocks.clear()
}

/** Tests only: the flip's push, once it was started. */
export function sharedTunnelFlipForTests(): Promise<void> {
  return flip.running ?? Promise.resolve()
}

/** Tests only: how often and how long `afterTunnelModeNamed` asks. */
export function setTunnelModeWaitForTests(retryMs: number, maxMs: number): void {
  modeWait = { retryMs, maxMs }
}

/** Tests only: every `afterTunnelModeNamed` still waiting. */
export async function tunnelModeWaitsForTests(): Promise<void> {
  await Promise.all([...modeWaits])
}
