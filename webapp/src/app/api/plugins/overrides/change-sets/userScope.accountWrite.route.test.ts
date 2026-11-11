/**
 * HD-23 / OQ-49 on the plugin override routes: a user-scope change set belongs to that
 * account's own catalog and prompt, so approving (a built-in skill text, or a
 * `user_skill.text` proposal saved as a new skill), rejecting, deleting and resetting it
 * follow the account write rule. An admin acting as a member who can sign in is refused
 * with 403 `own_account_only` before anything is written or audited; an admin acting as a
 * passwordless managed account, and the owner, still decide. A project scope keeps its
 * owner check.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as unknown,
  effective: '',
  managed: new Set<string>(),
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async () => {
  const { accountWriteDouble } = await import('@/lib/plugins/__testing__/accountWriteDouble')
  return {
    getSession: async () => h.session,
    getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null),
    requireAccountWrite: accountWriteDouble(() => h),
  }
})
vi.mock('@/lib/agentFetch', async () => {
  const { agentHandler, freshAgent } = await import('@/lib/plugins/__testing__/reviewHarness')
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: agentHandler(freshAgent()) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { FACTORY, projectScope, seedProposal, seedWorld, sha256, userScope } from '@/lib/plugins/__testing__/reviewHarness'
import { setNowForTests } from '@/lib/plugins/clock'
import { clearSkillPartsCache } from '@/lib/plugins/skillPartsRegistry'
import * as ov from '@/lib/plugins/overrides'
import { POST as approve } from './[id]/approve/route'
import { POST as reject } from './[id]/reject/route'
import { DELETE as remove } from './[id]/route'
import { POST as reset } from '../reset/route'

let db: FakePrisma

const call = (url: string, method: string, data?: Record<string, unknown>) =>
  new Request(`http://localhost:3000${url}`, {
    method,
    headers: { 'Content-Type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
    ...(data ? { body: JSON.stringify(data) } : {}),
  }) as never
const ctx = (id: string) => ({ params: Promise.resolve({ id }) })

const setRow = (cs: string) => db.rows('pluginOverride').find((r) => r.changeSetId === cs)
const actAs = (target: string) => {
  h.session = { userId: 'admin-1', role: 'admin' }
  h.effective = target
}

async function userSkillProposal(owner: string) {
  const { changeSetId } = await ov.propose({
    pluginId: 'skiller', point: 'user_skill.text', scope: { type: 'user', id: owner }, targetGroup: `sk${owner}`,
    parts: [{ targetKey: `sk${owner}/body`, value: 'Enumerate.\nThen probe every parameter.', baseSha256: sha256('Enumerate.') }],
    platformMeta: { baseText: 'Enumerate.', sourceName: 'Flow', pluginVersion: '1.1.0' },
    createdBy: owner,
  })
  return changeSetId
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  setNowForTests(() => new Date('2026-10-09T10:00:00Z'))
  seedWorld(db)
  db.seed('user', [
    { id: 'admin-1', email: 'admin@example.com', role: 'admin' },
    { id: 'managed', email: 'managed@example.com', role: 'standard' },
  ])
  db.seed('project', [{ id: 'p-managed', userId: 'managed', name: 'M' }])
  db.seed('userAttackSkill', [
    { id: 'skalice', userId: 'alice', name: 'Flow', content: 'Enumerate.' },
    { id: 'skmanaged', userId: 'managed', name: 'Flow', content: 'Enumerate.' },
  ])
  h.session = { userId: 'alice', role: 'standard' }
  h.effective = 'alice'
  h.managed = new Set(['managed'])
  h.audits = []
  clearSkillPartsCache()
})
afterEach(() => setNowForTests(null))

describe('an admin acting as a member who can sign in decides nothing in the member\'s user scope', () => {
  test('approving a built-in skill text: 403 own_account_only, it stays proposed, nothing audited', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    actAs('alice')
    const res = await approve(call('/api/plugins/overrides/change-sets/x/approve', 'POST', { scopeOwnerId: 'alice' }), ctx(cs))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('own_account_only')
    expect(setRow(cs)!.status).toBe('proposed')
    expect(h.audits).toEqual([])
  })

  test('saving a user_skill.text proposal as a new skill: 403, no skill is added to the member\'s catalog', async () => {
    const cs = await userSkillProposal('alice')
    const skillsBefore = db.rows('userAttackSkill')
    actAs('alice')
    const res = await approve(call('/api/plugins/overrides/change-sets/x/approve', 'POST', {
      scopeOwnerId: 'alice', name: 'Flow v2', projectId: 'p-alice', enableNew: true,
    }), ctx(cs))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('own_account_only')
    expect(db.rows('userAttackSkill')).toEqual(skillsBefore)
    expect(setRow(cs)!.status).toBe('proposed')
    expect(h.audits).toEqual([])
  })

  test('rejecting: 403, it stays proposed', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    actAs('alice')
    const res = await reject(call('/api/plugins/overrides/change-sets/x/reject', 'POST', { scopeOwnerId: 'alice' }), ctx(cs))
    expect(res.status).toBe(403)
    expect(setRow(cs)!.status).toBe('proposed')
    expect(h.audits).toEqual([])
  })

  test('deleting: 403, the version is kept', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    actAs('alice')
    const res = await remove(call(`/api/plugins/overrides/change-sets/${cs}`, 'DELETE'), ctx(cs))
    expect(res.status).toBe(403)
    expect(setRow(cs)).toBeDefined()
    expect(h.audits).toEqual([])
  })

  test('resetting the active version: 403, it stays active', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    await ov.approve(cs, 'alice', { 'ssrf/workflow': sha256(FACTORY.workflow) })
    actAs('alice')
    const res = await reset(call('/api/plugins/overrides/reset', 'POST', {
      point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice',
    }))
    expect(res.status).toBe(403)
    expect(setRow(cs)!.status).toBe('active')
    expect(h.audits).toEqual([])
  })
})

describe('who still decides', () => {
  test('an admin acting as a passwordless managed account approves its proposal', async () => {
    const cs = await seedProposal(userScope('managed'), { workflow: 'W2' })
    actAs('managed')
    const res = await approve(call('/api/plugins/overrides/change-sets/x/approve', 'POST', { scopeOwnerId: 'managed' }), ctx(cs))
    expect(res.status).toBe(200)
    expect(setRow(cs)!.status).toBe('active')
    expect(h.audits.find((a) => a.action === 'plugin.override.approve')).toMatchObject({ actorId: 'admin-1', after: { onBehalfOf: 'managed' } })
  })

  test('the owner approves her own proposal', async () => {
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    const res = await approve(call('/api/plugins/overrides/change-sets/x/approve', 'POST', { scopeOwnerId: 'alice' }), ctx(cs))
    expect(res.status).toBe(200)
  })

  test('a project scope keeps its owner check: an admin acting as the owner approves it', async () => {
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    actAs('alice')
    const res = await approve(call('/api/plugins/overrides/change-sets/x/approve', 'POST', {}), ctx(cs))
    expect(res.status).toBe(200)
  })

  test('another account\'s set stays a 404, before the write rule is asked', async () => {
    const cs = await seedProposal(userScope('bob'), { workflow: 'W2' })
    actAs('alice')
    const res = await approve(call('/api/plugins/overrides/change-sets/x/approve', 'POST', { scopeOwnerId: 'alice' }), ctx(cs))
    expect(res.status).toBe(404)
  })
})
