/**
 * The orchestrator answers' optional keys (D-B, FU-24): the reverse port's state on `ensure`, and the
 * reverse port with its state on each `/sandboxes` entry. They are carried when the orchestrator sends
 * them, so the agent (D-E) and the Operations view read them, and never required: an orchestrator
 * older than them still answers within the contract. Anything else the orchestrator adds is still cut.
 *
 * The orchestrator transport is a double; the client is real.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sandbox/orchestratorClient.optionalKeys.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ answer: { status: 200, body: {} as unknown } }))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: async () => new Response(JSON.stringify(h.answer.body), { status: h.answer.status, headers: { 'content-type': 'application/json' } }),
}))

import { ENSURE_RUNNING_KEYS, ENSURE_RUNNING_OPTIONAL_KEYS, LIST_OPTIONAL_KEYS, STATUS_OPTIONAL_KEYS } from './contract'
import { SandboxError, orchestratorEnsure, orchestratorList, orchestratorStatus } from './orchestratorClient'

const PORTS = {
  network_recon: 8000, nuclei: 8002, metasploit: 8003, nmap: 8004, playwright: 8005, sessions: 8013,
  hydra: 8014, tunnel: 8015, terminal: 8016, ngrok_api: 4040,
}
const running = (over: Record<string, unknown> = {}) => ({
  user_id: 'alice', view: 'own', instance: 'aaaaa1', host: 'redamon-kali-x', token: 'tok-fake', tunnel_token: 'tun-fake',
  ports: PORTS, reverse_port: 31001, projects: ['p1'], state: 'running', fresh: false, stop_at: null, stop_reason: null,
  warn: false, ...over,
})
const ensure = () => orchestratorEnsure({ user_id: 'alice', view: 'own', projects: ['p1'], need_project: null, wait: true, touch: false })
const entry = (over: Record<string, unknown> = {}) => ({
  user_id: 'alice', view: 'own', instance: 'aaaaa1', host: 'redamon-kali-x', token: 'tok-fake', state: 'running', ...over,
})

beforeEach(() => {
  h.answer = { status: 200, body: {} }
})

describe('the contract names the optional keys (P1, D-B)', () => {
  test('ensure and status: the state of the reverse port; the list: the port and its state', () => {
    expect([...ENSURE_RUNNING_OPTIONAL_KEYS]).toEqual(['reverse_port_state'])
    expect([...STATUS_OPTIONAL_KEYS]).toEqual(['reverse_port_state'])
    expect([...LIST_OPTIONAL_KEYS]).toEqual(['reverse_port', 'reverse_port_state'])
    // reverse_port itself stays a required key of a running ensure answer.
    expect(ENSURE_RUNNING_KEYS).toContain('reverse_port')
  })
})

describe('ensure', () => {
  test('with the state: carried as sent', async () => {
    h.answer = { status: 200, body: running({ reverse_port_state: 'assigned' }) }
    expect(await ensure()).toMatchObject({ reverse_port: 31001, reverse_port_state: 'assigned' })
  })

  test('without it (an older orchestrator): still a valid answer, with no state', async () => {
    h.answer = { status: 200, body: running() }
    const answer = await ensure() as unknown as Record<string, unknown>
    expect(answer).toMatchObject({ state: 'running', reverse_port: 31001 })
    expect('reverse_port_state' in answer).toBe(false)
  })

  test('a required key missing is still refused, and an unknown key is still cut', async () => {
    const { reverse_port: _gone, ...partial } = running()
    h.answer = { status: 200, body: partial }
    const err = await ensure().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(SandboxError)
    expect((err as SandboxError).code).toBe('orchestrator_bad_answer')
    h.answer = { status: 200, body: running({ reverse_port_state: 'pool_full', extra_secret: 'x' }) }
    const answer = await ensure() as unknown as Record<string, unknown>
    expect(answer.reverse_port_state).toBe('pool_full')
    expect('extra_secret' in answer).toBe(false)
  })
})

describe('the list (/sandboxes)', () => {
  test('with the port and its state: both carried on each entry', async () => {
    h.answer = { status: 200, body: { sandboxes: [
      entry({ reverse_port: 31001, reverse_port_state: 'assigned' }),
      entry({ user_id: 'bob', instance: 'bbbbb1', reverse_port: 4444, reverse_port_state: 'pool_full' }),
    ] } }
    expect((await orchestratorList()).sandboxes).toEqual([
      entry({ reverse_port: 31001, reverse_port_state: 'assigned' }),
      entry({ user_id: 'bob', instance: 'bbbbb1', reverse_port: 4444, reverse_port_state: 'pool_full' }),
    ])
  })

  test('without them (an older orchestrator): every entry kept, with neither key', async () => {
    h.answer = { status: 200, body: { sandboxes: [entry(), entry({ user_id: 'bob', instance: 'bbbbb1', extra: 1 })] } }
    expect((await orchestratorList()).sandboxes).toEqual([entry(), entry({ user_id: 'bob', instance: 'bbbbb1' })])
  })
})

describe('the status (/sandboxes/{user_id})', () => {
  test("the reverse port's state is carried; an answer without it is unchanged", async () => {
    const instance = {
      instance: 'aaaaa1', view: 'own', state: 'running', projects_hash: '0123456789abcdef', created_at: 1, last_used: 2,
      lease_kinds: [], stop_at: null, stop_reason: null, warn: false, reverse_port: 4444,
    }
    h.answer = { status: 200, body: { instances: [{ ...instance, reverse_port_state: 'no_pool', token: 'tok-fake' }] } }
    expect((await orchestratorStatus('alice')).instances).toEqual([{ ...instance, reverse_port_state: 'no_pool' }])
    h.answer = { status: 200, body: { instances: [instance] } }
    expect((await orchestratorStatus('alice')).instances).toEqual([instance])
  })
})
