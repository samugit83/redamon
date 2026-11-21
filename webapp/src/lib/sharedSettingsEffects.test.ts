/**
 * The tunnel push of a settings save (group 1, S17, I9; OD-G1-i, OQ-G1-2 default A).
 *
 * Shared mode keeps today's push: the shared kali-sandbox's tunnel manager takes the config
 * directly, with the tunnel bearer. Per-user mode pushes a person's OWN tunnel fields to that
 * person's own sandbox, through the agent (`pushSandboxTunnel`), never to the shared container
 * and never another person's. The I19 rule holds per person: a sandbox starts with no tunnel and
 * its start turns the person's `tunnelsEnabled` off, so a stored "on" is pushed only when the
 * person turned tunnels on after the sandbox's start: by this very save (after the save started
 * the sandbox itself), or earlier, which the tunnel running in that sandbox proves. A stored "on"
 * whose sandbox runs no tunnel outlived a start whose reset was lost (S13 review P2): it is turned
 * off and the person is told. Turning a tunnel off reaches the person whenever any instance of
 * their own view lives, a draining one included (R2-F2), and starts no sandbox.
 *
 * The first per_user answer a webapp process reads turns the shared container's instance tunnel
 * off once (WI-S17-3), so no instance tunnel outlives the flip.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sharedSettingsEffects.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const g = vi.hoisted(() => ({
  sandboxMode: vi.fn(),
  ensureSandbox: vi.fn(),
  sandboxStatus: vi.fn(),
  pushSandboxTunnel: vi.fn(),
  agentFetch: vi.fn(),
  settingsUpdateMany: vi.fn(),
  settingsFindUnique: vi.fn(),
  instanceUpdateMany: vi.fn(),
  instanceFindUnique: vi.fn(),
  effectiveUser: vi.fn(),
}))
vi.mock('@/lib/session', () => ({ getEffectiveUser: (...a: unknown[]) => g.effectiveUser(...a) }))

vi.mock('@/lib/sandbox/gateway', () => ({
  sandboxMode: (...a: unknown[]) => g.sandboxMode(...a),
  ensureSandbox: (...a: unknown[]) => g.ensureSandbox(...a),
  sandboxStatus: (...a: unknown[]) => g.sandboxStatus(...a),
}))
vi.mock('@/lib/sandbox/agentCalls', () => ({
  pushSandboxTunnel: (...a: unknown[]) => g.pushSandboxTunnel(...a),
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig() as Record<string, unknown>),
  agentFetch: (...a: unknown[]) => g.agentFetch(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      updateMany: (...a: unknown[]) => g.settingsUpdateMany(...a),
      findUnique: (...a: unknown[]) => g.settingsFindUnique(...a),
    },
    instanceSettings: {
      updateMany: (...a: unknown[]) => g.instanceUpdateMany(...a),
      findUnique: (...a: unknown[]) => g.instanceFindUnique(...a),
    },
  },
}))

import {
  EMPTY_TUNNEL, pushTunnelConfig, resetTunnelEffectsForTests, sharedTunnelFlipForTests, tunnelMode, tunnelStatusPath,
  withPersonTunnelLock, type TunnelMode,
} from './sharedSettingsEffects'
import { DEFAULT_MODE } from '@/lib/sandbox/contract'
import { OrchestratorUnreachable, SandboxError } from '@/lib/sandbox/orchestratorClient'
import { setFlagsForTests } from '@/lib/authz/flags'

const WORKER_URL = 'http://kali-sandbox:8015/tunnel/configure'
const NG = 'ngrok-OWN-secret-token'
const CH_AUTH = 'user:OWN-chisel-pass'
const ON = { tunnelsEnabled: true, ngrokAuthtoken: NG, chiselServerUrl: 'http://vps.example:9090', chiselAuth: CH_AUTH }
const OFF = { ...ON, tunnelsEnabled: false }
const CREDS = { ngrokAuthtoken: NG, chiselServerUrl: 'http://vps.example:9090', chiselAuth: CH_AUTH }
const ACTOR = { actorId: 'u1', onBehalfOfUserId: null, actorEmail: null }

const SHARED: TunnelMode = { mode: 'shared', named: true }
const PER_USER: TunnelMode = { mode: 'per_user', named: true }

const running = (fresh: boolean) => ({
  mode: 'per_user', user_id: 'u1', view: 'own', instance: 'a1b2c3', host: 'redamon-kali-x-a1b2c3', token: 't',
  tunnel_token: 'tt', ports: {}, reverse_port: 4444, projects: [], state: 'running', fresh,
  stop_at: null, stop_reason: null, warn: false,
})
const instance = (view: 'own' | 'act_as', state: string) => ({
  instance: 'a1b2c3', view, state, projects_hash: 'h', created_at: 1, last_used: 1, lease_kinds: [],
  stop_at: null, stop_reason: null, warn: false,
})
const tunnelStatus = (active: boolean) =>
  new Response(JSON.stringify({ ngrok: { active }, chisel: { active: false } }), { status: 200 })

let fetchSpy: ReturnType<typeof vi.fn>
const workerPushes = () => fetchSpy.mock.calls
  .filter((c) => c[0] === WORKER_URL)
  .map((c) => ({ headers: (c[1] as RequestInit).headers as Record<string, string>, body: JSON.parse(String((c[1] as RequestInit).body)) }))
const agentPushes = () => g.pushSandboxTunnel.mock.calls as [string, Record<string, string>][]

beforeEach(() => {
  resetTunnelEffectsForTests()
  for (const fn of Object.values(g)) fn.mockReset()
  g.sandboxMode.mockResolvedValue('per_user')
  g.ensureSandbox.mockResolvedValue(running(false))
  g.sandboxStatus.mockResolvedValue({ mode: 'per_user', instances: [instance('own', 'running')] })
  g.pushSandboxTunnel.mockResolvedValue({ ok: true, status: 200 })
  g.agentFetch.mockResolvedValue(tunnelStatus(true))
  g.settingsUpdateMany.mockResolvedValue({ count: 1 })
  g.settingsFindUnique.mockResolvedValue({ tunnelsEnabled: true })
  g.instanceUpdateMany.mockResolvedValue({ count: 0 })
  g.instanceFindUnique.mockResolvedValue(null)
  g.effectiveUser.mockResolvedValue({ userId: 'member-1' })
  process.env.TUNNEL_AUTH_TOKEN = 'ttok'
  fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
  vi.stubGlobal('fetch', fetchSpy)
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  setFlagsForTests(null)
  delete process.env.TUNNEL_AUTH_TOKEN
})

describe('the mode a tunnel save follows', () => {
  test('the orchestrator names it', async () => {
    g.sandboxMode.mockResolvedValue('shared')
    expect(await tunnelMode()).toEqual({ mode: 'shared', named: true })
    g.sandboxMode.mockResolvedValue('per_user')
    expect(await tunnelMode()).toEqual({ mode: 'per_user', named: true })
  })

  test('an orchestrator that cannot answer: the last mode it named in this process', async () => {
    await tunnelMode()
    g.sandboxMode.mockRejectedValue(new OrchestratorUnreachable(new Error('ECONNREFUSED')))
    expect(await tunnelMode()).toEqual({ mode: 'per_user', named: true })
  })

  test('nothing named yet: the contract default, marked as assumed', async () => {
    g.sandboxMode.mockRejectedValue(new SandboxError(500, 'orchestrator_error'))
    expect(await tunnelMode()).toEqual({ mode: DEFAULT_MODE, named: false })
  })
})

describe('the flip: the shared container keeps no instance tunnel (WI-S17-3)', () => {
  test('the first per_user answer pushes the empty config to the shared container once, with its bearer, one log line', async () => {
    await tunnelMode()
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(workerPushes()).toEqual([{ headers: expect.objectContaining({ Authorization: 'Bearer ttok' }), body: EMPTY_TUNNEL }])
    const lines = [...vi.mocked(console.info).mock.calls, ...vi.mocked(console.warn).mock.calls]
    expect(lines).toHaveLength(1)
    expect(JSON.stringify(lines)).not.toContain('ttok')
  })

  test('identity switch on: the unused instance tunnel row reads off too', async () => {
    setFlagsForTests({ identity: true })
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(g.instanceUpdateMany).toHaveBeenCalledWith({ where: { id: 'instance', tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    expect(g.settingsUpdateMany).not.toHaveBeenCalled()
  })

  test('a shared answer pushes nothing; a failed flip push is logged by its code only', async () => {
    g.sandboxMode.mockResolvedValue('shared')
    await tunnelMode()
    expect(fetchSpy).not.toHaveBeenCalled()
    g.sandboxMode.mockResolvedValue('per_user')
    fetchSpy.mockRejectedValue(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } }))
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect([...vi.mocked(console.info).mock.calls, ...vi.mocked(console.warn).mock.calls].flat().join(' '))
      .toMatch(/ENOTFOUND|kali_sandbox_unreachable/)
  })
})

describe('shared mode: today\'s direct push', () => {
  test('on: the credentials, with the tunnel bearer; no agent call, no sandbox started', async () => {
    const result = await pushTunnelConfig(ON, SHARED, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result).toEqual({ warning: null, tunnelsEnabled: true })
    expect(workerPushes()).toEqual([{ headers: expect.objectContaining({ Authorization: 'Bearer ttok' }), body: CREDS }])
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(g.ensureSandbox).not.toHaveBeenCalled()
  })

  test('off: the empty config', async () => {
    expect(await pushTunnelConfig(OFF, SHARED, null)).toEqual({ warning: null, tunnelsEnabled: false })
    expect(workerPushes().map((p) => p.body)).toEqual([EMPTY_TUNNEL])
  })
})

describe('a mode nobody named (the orchestrator never answered this process)', () => {
  const ASSUMED: TunnelMode = { mode: DEFAULT_MODE, named: false }

  test('on: nothing with a credential is pushed anywhere, and the save says why', async () => {
    const result = await pushTunnelConfig(ON, ASSUMED, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result.warning).toMatchObject({ code: 'sandbox_mode_unknown' })
    expect(JSON.stringify(fetchSpy.mock.calls)).not.toContain(NG)
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
  })

  test('off: the empty config goes both ways (the shared container and the person\'s sandboxes)', async () => {
    g.sandboxStatus.mockRejectedValue(new OrchestratorUnreachable(new Error('ECONNREFUSED')))
    await pushTunnelConfig(OFF, ASSUMED, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(workerPushes().map((p) => p.body)).toEqual([EMPTY_TUNNEL])
    expect(agentPushes()).toEqual([['u1', EMPTY_TUNNEL]])
  })
})

describe('per-user: turning it on', () => {
  test('the person\'s own sandbox is started first, then their own credentials go to it through the agent, never to the shared container', async () => {
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result).toEqual({ warning: null, tunnelsEnabled: true })
    expect(g.ensureSandbox).toHaveBeenCalledWith('u1', { wait: true, actor: ACTOR })
    expect(agentPushes()).toEqual([['u1', CREDS]])
    expect(g.ensureSandbox.mock.invocationCallOrder[0]).toBeLessThan(g.pushSandboxTunnel.mock.invocationCallOrder[0])
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('a sandbox this save started turned the flag off at its start: the save turns it on again before the push', async () => {
    g.ensureSandbox.mockResolvedValue(running(true))
    await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(g.settingsUpdateMany).toHaveBeenCalledWith({ where: { userId: 'u1' }, data: { tunnelsEnabled: true } })
    expect(g.settingsUpdateMany.mock.invocationCallOrder[0]).toBeLessThan(g.pushSandboxTunnel.mock.invocationCallOrder[0])
  })

  test.each([
    ['a refused account', new SandboxError(403, 'sandbox_user_refused'), 'sandbox_user_refused'],
    ['no memory', new SandboxError(409, 'sandbox_ram'), 'sandbox_ram'],
    ['an orchestrator out of reach', new SandboxError(503, 'orchestrator_unavailable'), 'orchestrator_unavailable'],
  ])('%s: nothing is pushed and the save says why', async (_name, err, code) => {
    g.ensureSandbox.mockRejectedValue(err)
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result.warning).toMatchObject({ code })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('a start that answers shared after the mode read said per_user: no credential goes anywhere (review F2)', async () => {
    g.ensureSandbox.mockResolvedValue({ mode: 'shared' })
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result.warning).toMatchObject({ code: 'sandbox_mode_changed' })
    expect(JSON.stringify(fetchSpy.mock.calls)).not.toContain(NG)
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
  })

  test('a start between the ensure and the push turned the flag off: the tunnel goes off again and the person is told', async () => {
    g.settingsFindUnique.mockResolvedValue({ tunnelsEnabled: false })
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result).toMatchObject({ tunnelsEnabled: false, warning: { code: 'tunnel_off_sandbox_restarted' } })
    expect(agentPushes()).toEqual([['u1', CREDS], ['u1', EMPTY_TUNNEL]])
  })

  test('the agent did not take it: a warning with its code, never the configuration', async () => {
    g.pushSandboxTunnel.mockResolvedValue({ ok: false, status: 0, code: 'agent_unreachable' })
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result.warning).toMatchObject({ service: 'agent', code: 'agent_unreachable' })
    expect(JSON.stringify(result)).not.toMatch(/OWN/)
  })
})

describe('per-user: a credential change while on (S13 review P2, a lost `fresh`)', () => {
  test('a tunnel runs in the person\'s sandbox (turned on after its start): the new credentials go there', async () => {
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(g.agentFetch).toHaveBeenCalledWith('/tunnel-status?user_id=u1', expect.anything(), expect.anything())
    expect(agentPushes()).toEqual([['u1', CREDS]])
    expect(result).toEqual({ warning: null, tunnelsEnabled: true })
  })

  test('no tunnel runs there: the stored "on" predates the sandbox\'s start, so it is turned off, no credential is pushed, and the person is told', async () => {
    g.agentFetch.mockResolvedValue(tunnelStatus(false))
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(result).toMatchObject({ tunnelsEnabled: false, warning: { code: 'tunnel_off_sandbox_restarted' } })
    expect(g.settingsUpdateMany).toHaveBeenCalledWith({ where: { userId: 'u1', tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
    expect(g.ensureSandbox).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('an agent that cannot say counts as no tunnel', async () => {
    g.agentFetch.mockRejectedValue(new Error('agent down'))
    const result = await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(result.tunnelsEnabled).toBe(false)
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
  })
})

describe('per-user: turning it off reaches every instance of the person (R2-F2)', () => {
  test('the empty config goes to the person while any own instance lives, a draining one included', async () => {
    g.sandboxStatus.mockResolvedValue({ mode: 'per_user', instances: [instance('own', 'draining')] })
    const result = await pushTunnelConfig(OFF, PER_USER, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(result).toEqual({ warning: null, tunnelsEnabled: false })
    expect(agentPushes()).toEqual([['u1', EMPTY_TUNNEL]])
    expect(g.ensureSandbox).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('no own instance: nothing to turn off, and no sandbox is started for it', async () => {
    g.sandboxStatus.mockResolvedValue({ mode: 'per_user', instances: [instance('act_as', 'running')] })
    await pushTunnelConfig(OFF, PER_USER, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(g.ensureSandbox).not.toHaveBeenCalled()
  })

  test('a status that cannot be read: the empty config is sent anyway', async () => {
    g.sandboxStatus.mockRejectedValue(new OrchestratorUnreachable(new Error('ECONNREFUSED')))
    await pushTunnelConfig(OFF, PER_USER, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(agentPushes()).toEqual([['u1', EMPTY_TUNNEL]])
  })

  test('without a person (the instance settings) per-user mode pushes nothing', async () => {
    expect(await pushTunnelConfig(ON, PER_USER, null)).toEqual({ warning: null, tunnelsEnabled: true })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

describe('secrets', () => {
  test('no credential reaches a log, whatever fails', async () => {
    g.ensureSandbox.mockRejectedValue(new SandboxError(503, 'orchestrator_unavailable'))
    await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    g.ensureSandbox.mockResolvedValue(running(false))
    g.pushSandboxTunnel.mockResolvedValue({ ok: false, status: 500, code: 'agent_500' })
    await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ error: NG }), { status: 401 }))
    await pushTunnelConfig(ON, SHARED, { userId: 'u1', turnedOn: true, actor: ACTOR })
    const logged = JSON.stringify([
      vi.mocked(console.info).mock.calls, vi.mocked(console.warn).mock.calls, vi.mocked(console.error).mock.calls,
    ])
    expect(logged).not.toContain(NG)
    expect(logged).not.toContain(CH_AUTH)
  })
})

describe('a mode nobody named answers nothing tied to a person (review F1)', () => {
  test('the indicator path: none', async () => {
    g.sandboxMode.mockRejectedValue(new OrchestratorUnreachable(new Error('ECONNREFUSED')))
    expect(await tunnelStatusPath()).toBeNull()
    expect(g.effectiveUser).not.toHaveBeenCalled()
  })

  test('named modes: shared the one tunnel, per_user the effective person\'s own', async () => {
    g.sandboxMode.mockResolvedValue('shared')
    expect(await tunnelStatusPath()).toBe('/tunnel-status')
    g.sandboxMode.mockResolvedValue('per_user')
    expect(await tunnelStatusPath()).toBe('/tunnel-status?user_id=member-1')
  })
})

describe('the instance credentials never become a person\'s own tunnel (review F3)', () => {
  const INSTANCE = { id: 'instance', tunnelsEnabled: false, ngrokAuthtoken: NG, chiselServerUrl: 'http://vps.example:9090', chiselAuth: CH_AUTH }

  test.each([
    ['the instance ngrok token', { ...ON, chiselServerUrl: '', chiselAuth: '' }],
    ['the instance chisel server with its auth', { ...ON, ngrokAuthtoken: '' }],
  ])('identity switch on, a person\'s row holding %s (the mirror\'s copy): not pushed, turned off, the person asked for their own', async (_name, settings) => {
    setFlagsForTests({ identity: true })
    g.instanceFindUnique.mockResolvedValue(INSTANCE)
    const result = await pushTunnelConfig(settings, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result).toMatchObject({ tunnelsEnabled: false, warning: { code: 'tunnel_instance_credentials' } })
    expect(g.settingsUpdateMany).toHaveBeenCalledWith({ where: { userId: 'u1', tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(CH_AUTH)
    expect(g.ensureSandbox).not.toHaveBeenCalled()
    expect(JSON.stringify(result)).not.toContain(NG)
  })

  test('the person\'s own credentials go through', async () => {
    setFlagsForTests({ identity: true })
    g.instanceFindUnique.mockResolvedValue({ ...INSTANCE, ngrokAuthtoken: 'instance-only-token', chiselAuth: 'instance:only' })
    expect((await pushTunnelConfig(ON, PER_USER, { userId: 'u1', turnedOn: true, actor: ACTOR })).warning).toBeNull()
    expect(agentPushes()).toEqual([['u1', CREDS]])
  })
})

describe('the flip is re-armed and retried (review C1/F7)', () => {
  test('a shared answer re-arms it: a later per_user answer turns the shared tunnel off again', async () => {
    await tunnelMode()
    await sharedTunnelFlipForTests()
    g.sandboxMode.mockResolvedValue('shared')
    await tunnelMode()
    g.sandboxMode.mockResolvedValue('per_user')
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(workerPushes().map((p) => p.body)).toEqual([EMPTY_TUNNEL, EMPTY_TUNNEL])
  })

  test('a failed flip is retried once its delay has passed, and the instance row is marked off only when it worked', async () => {
    setFlagsForTests({ identity: true })
    const now = vi.spyOn(Date, 'now').mockReturnValue(1_000_000)
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }))
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(g.instanceUpdateMany).not.toHaveBeenCalled()
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(workerPushes()).toHaveLength(1)
    now.mockReturnValue(1_000_000 + 61_000)
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(workerPushes()).toHaveLength(2)
    expect(g.instanceUpdateMany).toHaveBeenCalledTimes(1)
    await tunnelMode()
    await sharedTunnelFlipForTests()
    expect(workerPushes()).toHaveLength(2)
  })
})

describe('one person\'s tunnel saves run one at a time in this process (review C2/F6)', () => {
  test('a later save waits for the earlier one; another person\'s does not', async () => {
    const order: string[] = []
    let release!: () => void
    const first = withPersonTunnelLock('u1', () => new Promise<void>((r) => { release = () => { order.push('a'); r() } }))
    const second = withPersonTunnelLock('u1', async () => { order.push('b') })
    const other = withPersonTunnelLock('u2', async () => { order.push('other') })
    await other
    expect(order).toEqual(['other'])
    release()
    await Promise.all([first, second])
    expect(order).toEqual(['other', 'a', 'b'])
  })

  test('a failed save does not hold the next one', async () => {
    await expect(withPersonTunnelLock('u1', async () => { throw new Error('boom') })).rejects.toThrow('boom')
    expect(await withPersonTunnelLock('u1', async () => 'next')).toBe('next')
  })
})
