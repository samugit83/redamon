/**
 * POST .../[id]/approve and .../[id]/reject (design §6; OQ-08, X8/X9). Approve re-checks the
 * factory against the agent without its cache, re-validates the whole-skill total, stores the
 * next revision and audits; a scopeOwnerId other than the effective user is 403; a stale
 * proposal 409; a lost race 409; an agent with no skill-parts endpoint 503; a total now over
 * the limit 422; cross-origin 403.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as unknown,
  effective: '',
  managed: new Set<string>(),
  agent: null as unknown as (path: string) => Promise<Response>,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
// The account write rule (HD-23) over the session double: an admin acting as the owner
// writes a user scope only while the owner is a passwordless managed account (h.managed).
vi.mock('@/lib/session', async () => {
  const { accountWriteDouble } = await import('@/lib/plugins/__testing__/accountWriteDouble')
  return {
    getSession: async () => h.session,
    getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null),
    requireAccountWrite: accountWriteDouble(() => h),
  }
})
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: (path: string) => h.agent(path) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import {
  OVER_LIMIT_VERDICT,
  agentHandler,
  freshAgent,
  projectScope,
  seedProposal,
  seedWorld,
  userScope,
  type AgentState,
} from '@/lib/plugins/__testing__/reviewHarness'
import { clearSkillPartsCache } from '@/lib/plugins/skillPartsRegistry'
import * as ov from '@/lib/plugins/overrides'
import { POST as approve } from './[id]/approve/route'
import { POST as reject } from './[id]/reject/route'

let db: FakePrisma
let agent: AgentState

const body = (data: Record<string, unknown> = {}, origin = 'http://localhost:3000') =>
  new Request('http://localhost:3000/api/plugins/overrides/change-sets/x/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', origin, host: 'localhost:3000' },
    body: JSON.stringify(data),
  }) as never
const doApprove = (id: string, data?: Record<string, unknown>, origin?: string) => approve(body(data, origin), { params: Promise.resolve({ id }) })


beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  agent = freshAgent()
  h.agent = agentHandler(agent)
  h.session = { userId: 'alice', role: 'standard' }
  h.effective = 'alice'
  h.managed = new Set()
  h.audits = []
  clearSkillPartsCache()
})

describe('approve', () => {
  test('stores the next revision, clears pending, and audits with the real actor', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    const res = await doApprove(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(200)
    expect((await res.json()).revision).toBe(2)
    expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('active')
    const audit = h.audits.find((a) => a.action === 'plugin.override.approve')!
    expect(audit.actorId).toBe('alice')
  })

  test('an admin acting as the owner, a passwordless managed account: the audit actor is the real admin, onBehalfOf the owner', async () => {
    h.session = { userId: 'admin-1', role: 'admin' }
    h.effective = 'alice'
    h.managed = new Set(['alice'])
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    expect((await doApprove(cs, { scopeOwnerId: 'alice' })).status).toBe(200)
    const audit = h.audits.find((a) => a.action === 'plugin.override.approve')!
    expect(audit.actorId).toBe('admin-1')
    expect((audit.after as Record<string, unknown>).onBehalfOf).toBe('alice')
  })

  test('a scopeOwnerId other than the effective user: 403', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    const res = await doApprove(cs, { scopeOwnerId: 'bob' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('wrong_owner')
    expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('proposed')
  })

  test('a project-scope approval needs no scopeOwnerId, only ownership', async () => {
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    expect((await doApprove(cs, {})).status).toBe(200)
  })

  test('another user’s set: 404', async () => {
    const cs = await seedProposal(userScope('bob'), { workflow: 'W2' }, { createdBy: 'bob' })
    expect((await doApprove(cs, { scopeOwnerId: 'bob' })).status).toBe(404)
  })

  test('a proposal built on changed factory text: 409 stale, and it stays proposed', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    agent.registryBody = { skills: [{ id: 'ssrf', maxChars: 4000, parts: [{ partId: 'workflow', constant: 'C', kind: 'plain', placeholders: [], sha256: 'a'.repeat(64), chars: 3, maxChars: 4000, order: 1, gate: 'always', text: 'CHANGED' }] }] }
    clearSkillPartsCache()
    const res = await doApprove(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('stale_proposal')
    expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('proposed')
  })

  test('a lost race (already decided): 409 already_decided', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    await ov.reject(cs, 'alice')
    const res = await doApprove(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('already_decided')
  })

  test('agent without /plugins/skill-parts: 503 agent_outdated, nothing stored', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    agent.registryStatus = 404
    clearSkillPartsCache()
    const res = await doApprove(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('agent_outdated')
    expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('proposed')
  })

  test('the whole-skill total now over the limit: 422', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    agent.verdict = OVER_LIMIT_VERDICT
    const res = await doApprove(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(422)
    expect((await res.json()).code).toBe('over_limit')
    expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('proposed')
  })

  test('cross-origin: 403', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    expect((await doApprove(cs, { scopeOwnerId: 'alice' }, 'https://evil.example')).status).toBe(403)
  })

  test('a non-JSON body is refused before anything is approved (415)', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    const req = new Request('http://localhost:3000/x', { method: 'POST', headers: { origin: 'http://localhost:3000', host: 'localhost:3000' }, body: 'x' }) as never
    expect((await approve(req, { params: Promise.resolve({ id: cs }) })).status).toBe(415)
  })
})

describe('reject', () => {
  test('rejects a pending proposal and audits', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    const res = await reject(body({ scopeOwnerId: 'alice' }), { params: Promise.resolve({ id: cs }) })
    expect(res.status).toBe(200)
    expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('rejected')
    expect(h.audits.some((a) => a.action === 'plugin.override.reject')).toBe(true)
  })

  test('another user’s set: 404', async () => {
    const cs = await seedProposal(userScope('bob'), { workflow: 'W2' }, { createdBy: 'bob' })
    expect((await reject(body({ scopeOwnerId: 'bob' }), { params: Promise.resolve({ id: cs }) })).status).toBe(404)
  })
})
