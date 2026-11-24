/**
 * The tunnel push of a settings save (group 1, S17, I9; OD-G1-i, OQ-G1-2 default A).
 *
 * A save pushes a person's OWN tunnel fields to that person's own sandbox, through the agent
 * (`pushSandboxTunnel`), never anywhere else and never another person's. The I19 rule holds per
 * person: a sandbox starts with no tunnel and
 * its start turns the person's `tunnelsEnabled` off, so a stored "on" is pushed only when the
 * person turned tunnels on after the sandbox's start: by this very save (after the save started
 * the sandbox itself), or earlier, which the tunnel running in that sandbox proves. A stored "on"
 * whose sandbox runs no tunnel outlived a start whose reset was lost (S13 review P2): it is turned
 * off and the person is told. Turning a tunnel off reaches the person whenever any instance of
 * their own view lives, a draining one included (R2-F2), and starts no sandbox.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sharedSettingsEffects.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const g = vi.hoisted(() => ({
  ensureSandbox: vi.fn(),
  sandboxStatus: vi.fn(),
  pushSandboxTunnel: vi.fn(),
  agentFetch: vi.fn(),
  settingsUpdateMany: vi.fn(),
  settingsFindUnique: vi.fn(),
  instanceUpdateMany: vi.fn(),
  instanceFindUnique: vi.fn(),
  identity: vi.fn(),
  held: vi.fn(),
}))
vi.mock('@/lib/authz/sharedTools', () => ({ sharedToolHeldBy: (...a: unknown[]) => g.held(...a) }))
// getEffectiveUser (the acted-as member under act-as) and an orchestrator that names per-user
// mode are what a build that showed the member's tunnel to the acting admin read: the act-as test
// fails on it, not only on a missing mock.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => g.identity(...a),
  getEffectiveUser: async () => {
    const id = await g.identity()
    return id ? { userId: id.actingAs?.id ?? id.session.userId } : null
  },
}))

vi.mock('@/lib/sandbox/gateway', () => ({
  ensureSandbox: (...a: unknown[]) => g.ensureSandbox(...a),
  sandboxStatus: (...a: unknown[]) => g.sandboxStatus(...a),
  sandboxMode: async () => 'per_user',
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

import { readFileSync } from 'node:fs'
import path from 'node:path'
import {
  EMPTY_TUNNEL, enforceTunnelPermission, pushTunnelConfig, resetTunnelEffectsForTests, tunnelStatusPath, withPersonTunnelLock,
} from './sharedSettingsEffects'
import { OrchestratorUnreachable, SandboxError } from '@/lib/sandbox/orchestratorClient'
import { setFlagsForTests } from '@/lib/authz/flags'

const NG = 'ngrok-OWN-secret-token'
const CH_AUTH = 'user:OWN-chisel-pass'
const ON = { tunnelsEnabled: true, ngrokAuthtoken: NG, chiselServerUrl: 'http://vps.example:9090', chiselAuth: CH_AUTH }
const OFF = { ...ON, tunnelsEnabled: false }
const CREDS = { ngrokAuthtoken: NG, chiselServerUrl: 'http://vps.example:9090', chiselAuth: CH_AUTH }
const ACTOR = { actorId: 'u1', onBehalfOfUserId: null, actorEmail: null }

const running = (fresh: boolean) => ({
  user_id: 'u1', view: 'own', instance: 'a1b2c3', host: 'redamon-kali-x-a1b2c3', token: 't',
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
const agentPushes = () => g.pushSandboxTunnel.mock.calls as [string, Record<string, string>][]

beforeEach(() => {
  resetTunnelEffectsForTests()
  for (const fn of Object.values(g)) fn.mockReset()
  g.ensureSandbox.mockResolvedValue(running(false))
  g.sandboxStatus.mockResolvedValue({ instances: [instance('own', 'running')] })
  g.pushSandboxTunnel.mockResolvedValue({ ok: true, status: 200 })
  g.agentFetch.mockResolvedValue(tunnelStatus(true))
  g.settingsUpdateMany.mockResolvedValue({ count: 1 })
  g.settingsFindUnique.mockResolvedValue({ tunnelsEnabled: true })
  g.instanceUpdateMany.mockResolvedValue({ count: 0 })
  g.instanceFindUnique.mockResolvedValue(null)
  g.identity.mockResolvedValue({ session: { userId: 'member-1' }, principal: { id: 'member-1' }, actingAs: null })
  g.held.mockResolvedValue(true)
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
})

describe('no shared container any more', () => {
  test('nothing is ever sent to a fixed Kali address, and no instance tunnel token is read', async () => {
    await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    await pushTunnelConfig(OFF, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(fetchSpy).not.toHaveBeenCalled()
    const source = readFileSync(path.resolve(__dirname, 'sharedSettingsEffects.ts'), 'utf8')
    expect(source).not.toMatch(/kali-sandbox:8015|TUNNEL_AUTH_TOKEN/)
  })
})

describe('turning it on', () => {
  test('the person\'s own sandbox is started first, then their own credentials go to it through the agent', async () => {
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result).toEqual({ warning: null, tunnelsEnabled: true })
    expect(g.ensureSandbox).toHaveBeenCalledWith('u1', { wait: true, actor: ACTOR })
    expect(agentPushes()).toEqual([['u1', CREDS]])
    expect(g.ensureSandbox.mock.invocationCallOrder[0]).toBeLessThan(g.pushSandboxTunnel.mock.invocationCallOrder[0])
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('a sandbox this save started turned the flag off at its start: the save turns it on again before the push', async () => {
    g.ensureSandbox.mockResolvedValue(running(true))
    await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(g.settingsUpdateMany).toHaveBeenCalledWith({ where: { userId: 'u1' }, data: { tunnelsEnabled: true } })
    expect(g.settingsUpdateMany.mock.invocationCallOrder[0]).toBeLessThan(g.pushSandboxTunnel.mock.invocationCallOrder[0])
  })

  test.each([
    ['a refused account', new SandboxError(403, 'sandbox_user_refused'), 'sandbox_user_refused'],
    ['no memory', new SandboxError(409, 'sandbox_ram'), 'sandbox_ram'],
    ['an orchestrator out of reach', new SandboxError(503, 'orchestrator_unavailable'), 'orchestrator_unavailable'],
  ])('%s: nothing is pushed and the save says why', async (_name, err, code) => {
    g.ensureSandbox.mockRejectedValue(err)
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result.warning).toMatchObject({ code })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('a start between the ensure and the push turned the flag off: the tunnel goes off again and the person is told', async () => {
    g.settingsFindUnique.mockResolvedValue({ tunnelsEnabled: false })
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result).toMatchObject({ tunnelsEnabled: false, warning: { code: 'tunnel_off_sandbox_restarted' } })
    expect(agentPushes()).toEqual([['u1', CREDS], ['u1', EMPTY_TUNNEL]])
  })

  test('the agent did not take it: a warning with its code, never the configuration', async () => {
    g.pushSandboxTunnel.mockResolvedValue({ ok: false, status: 0, code: 'agent_unreachable' })
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    expect(result.warning).toMatchObject({ service: 'agent', code: 'agent_unreachable' })
    expect(JSON.stringify(result)).not.toMatch(/OWN/)
  })
})

describe('a credential change while on (S13 review P2, a lost `fresh`)', () => {
  test('a tunnel runs in the person\'s sandbox (turned on after its start): the new credentials go there', async () => {
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(g.agentFetch).toHaveBeenCalledWith('/tunnel-status?user_id=u1', expect.anything(), expect.anything())
    expect(agentPushes()).toEqual([['u1', CREDS]])
    expect(result).toEqual({ warning: null, tunnelsEnabled: true })
  })

  test('no tunnel runs there: the stored "on" predates the sandbox\'s start, so it is turned off, no credential is pushed, and the person is told', async () => {
    g.agentFetch.mockResolvedValue(tunnelStatus(false))
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(result).toMatchObject({ tunnelsEnabled: false, warning: { code: 'tunnel_off_sandbox_restarted' } })
    expect(g.settingsUpdateMany).toHaveBeenCalledWith({ where: { userId: 'u1', tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
    expect(g.ensureSandbox).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('an agent that cannot say counts as no tunnel', async () => {
    g.agentFetch.mockRejectedValue(new Error('agent down'))
    const result = await pushTunnelConfig(ON, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(result.tunnelsEnabled).toBe(false)
    expect(JSON.stringify(g.pushSandboxTunnel.mock.calls)).not.toContain(NG)
  })
})

describe('turning it off reaches every instance of the person (R2-F2)', () => {
  test('the empty config goes to the person while any own instance lives, a draining one included', async () => {
    g.sandboxStatus.mockResolvedValue({ instances: [instance('own', 'draining')] })
    const result = await pushTunnelConfig(OFF, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(result).toEqual({ warning: null, tunnelsEnabled: false })
    expect(agentPushes()).toEqual([['u1', EMPTY_TUNNEL]])
    expect(g.ensureSandbox).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('no own instance: nothing to turn off, and no sandbox is started for it', async () => {
    g.sandboxStatus.mockResolvedValue({ instances: [instance('act_as', 'running')] })
    await pushTunnelConfig(OFF, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(g.ensureSandbox).not.toHaveBeenCalled()
  })

  test('a status that cannot be read: the empty config is sent anyway', async () => {
    g.sandboxStatus.mockRejectedValue(new OrchestratorUnreachable(new Error('ECONNREFUSED')))
    await pushTunnelConfig(OFF, { userId: 'u1', turnedOn: false, actor: ACTOR })
    expect(agentPushes()).toEqual([['u1', EMPTY_TUNNEL]])
  })
})

describe('secrets', () => {
  test('no credential reaches a log, whatever fails', async () => {
    g.ensureSandbox.mockRejectedValue(new SandboxError(503, 'orchestrator_unavailable'))
    await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    g.ensureSandbox.mockResolvedValue(running(false))
    g.pushSandboxTunnel.mockResolvedValue({ ok: false, status: 500, code: 'agent_500' })
    await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })
    const logged = JSON.stringify([
      vi.mocked(console.info).mock.calls, vi.mocked(console.warn).mock.calls, vi.mocked(console.error).mock.calls,
    ])
    expect(logged).not.toContain(NG)
    expect(logged).not.toContain(CH_AUTH)
  })
})

describe('the tunnel indicator shows the signed-in person\'s own tunnel, and none under act-as', () => {
  test('the signed-in person\'s own, the id encoded', async () => {
    expect(await tunnelStatusPath()).toBe('/tunnel-status?user_id=member-1')
    g.identity.mockResolvedValue({ session: { userId: 'a b&c' }, principal: { id: 'a b&c' }, actingAs: null })
    expect(await tunnelStatusPath()).toBe('/tunnel-status?user_id=a%20b%26c')
  })

  test('act-as: none, never the member\'s own tunnel to the acting admin (the act_as sandbox runs no tunnel)', async () => {
    g.identity.mockResolvedValue({ session: { userId: 'admin-1' }, principal: { id: 'admin-1' }, actingAs: { id: 'member-1' } })
    expect(await tunnelStatusPath()).toBeNull()
  })

  test('no session: none', async () => {
    g.identity.mockResolvedValue(null)
    expect(await tunnelStatusPath()).toBeNull()
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
    const result = await pushTunnelConfig(settings, { userId: 'u1', turnedOn: true, actor: ACTOR })
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
    expect((await pushTunnelConfig(ON, { userId: 'u1', turnedOn: true, actor: ACTOR })).warning).toBeNull()
    expect(agentPushes()).toEqual([['u1', CREDS]])
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

describe('a person who lost platform:tunnels keeps no tunnel (enforceTunnelPermission, G-03)', () => {
  test('still held: nothing is changed or pushed', async () => {
    expect(await enforceTunnelPermission('u1')).toEqual({ turnedOff: false, warning: null })
    expect(g.held).toHaveBeenCalledWith('u1', 'tunnels')
    expect(g.settingsUpdateMany).not.toHaveBeenCalled()
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
  })

  test('stored off: the permission is not even read', async () => {
    g.settingsFindUnique.mockResolvedValue({ tunnelsEnabled: false })
    expect(await enforceTunnelPermission('u1')).toEqual({ turnedOff: false, warning: null })
    expect(g.held).not.toHaveBeenCalled()
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
  })

  test('lost: the stored flag goes off and the empty config reaches the person\'s own sandbox only', async () => {
    g.held.mockResolvedValue(false)
    expect(await enforceTunnelPermission('u1')).toEqual({ turnedOff: true, warning: null })
    expect(g.settingsUpdateMany).toHaveBeenCalledWith({ where: { userId: 'u1', tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    expect(agentPushes()).toEqual([['u1', { ...EMPTY_TUNNEL }]])
    expect(g.ensureSandbox).not.toHaveBeenCalled()
  })

  test('lost with no own instance running: the flag goes off, nothing is pushed, nothing started', async () => {
    g.held.mockResolvedValue(false)
    g.sandboxStatus.mockResolvedValue({ instances: [instance('act_as', 'running')] })
    expect(await enforceTunnelPermission('u1')).toEqual({ turnedOff: true, warning: null })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
    expect(g.ensureSandbox).not.toHaveBeenCalled()
  })

  test('lost, and the push fails: turned off in the settings, and the failure is returned', async () => {
    g.held.mockResolvedValue(false)
    g.pushSandboxTunnel.mockResolvedValue({ ok: false, status: 503, code: 'agent_unavailable' })
    const out = await enforceTunnelPermission('u1')
    expect(out.turnedOff).toBe(true)
    expect(out.warning).toMatchObject({ service: 'agent', code: 'agent_unavailable' })
  })

  test('another save that turned it off first: nothing more to do', async () => {
    g.held.mockResolvedValue(false)
    g.settingsUpdateMany.mockResolvedValue({ count: 0 })
    expect(await enforceTunnelPermission('u1')).toEqual({ turnedOff: false, warning: null })
    expect(g.pushSandboxTunnel).not.toHaveBeenCalled()
  })
})
