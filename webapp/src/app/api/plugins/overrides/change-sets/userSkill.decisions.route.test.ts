/**
 * Reject (POST .../[id]/reject) and delete (DELETE .../[id]) of a change set record who
 * really decided: the session user as the actor, and `onBehalfOf` the owner when an admin
 * acts as them (plan P6). Both work on a `user_skill.text` proposal as on a built-in one.
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
  return { AgentUnreachableError, agentFetch: async () => Response.json({}, { status: 404 }) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { setNowForTests } from '@/lib/plugins/clock'
import * as ov from '@/lib/plugins/overrides'
import { POST as reject } from './[id]/reject/route'
import { DELETE as remove } from './[id]/route'

const H = 'a'.repeat(64)
let db: FakePrisma

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  setNowForTests(() => new Date('2026-10-09T10:00:00Z'))
  db.seed('user', [
    { id: 'alice', email: 'alice@example.com', role: 'standard' },
    { id: 'user-admin', email: 'admin@example.com', role: 'admin' },
  ])
  db.seed('pluginInstall', [{ pluginId: 'skiller', enabled: true, status: 'ready', activeVersion: '1.1.0', grantedPermissions: ['override:skill.text', 'override:user_skill.text'] }])
  db.seed('project', [{ id: 'p-alice', userId: 'alice', name: 'A' }])
  h.session = { userId: 'alice', role: 'standard' }
  h.effective = 'alice'
  h.managed = new Set()
  h.audits = []
})
afterEach(() => setNowForTests(null))

async function userSkillSet() {
  const { changeSetId } = await ov.propose({
    pluginId: 'skiller', point: 'user_skill.text', scope: { type: 'user', id: 'alice' }, targetGroup: 'skflow',
    parts: [{ targetKey: 'skflow/body', value: 'new', baseSha256: H }],
    platformMeta: { baseText: 'old', sourceName: 'Flow', pluginVersion: '1.1.0' }, createdBy: 'alice',
  })
  return changeSetId
}
async function builtinSet(scope: ov.OverrideScope = { type: 'user', id: 'alice' }) {
  const { changeSetId } = await ov.propose({
    pluginId: 'skiller', point: 'skill.text', scope, targetGroup: 'sqli',
    parts: [{ targetKey: 'sqli/workflow', value: 'w', baseSha256: H }], createdBy: 'alice',
  })
  return changeSetId
}

const post = (id: string, body: Record<string, unknown>, origin = 'http://localhost:3000') =>
  reject(new Request(`http://localhost:3000/api/plugins/overrides/change-sets/${id}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', origin, host: 'localhost:3000' },
    body: JSON.stringify(body),
  }) as never, { params: Promise.resolve({ id }) })
const del = (id: string, origin = 'http://localhost:3000') =>
  remove(new Request(`http://localhost:3000/api/plugins/overrides/change-sets/${id}`, {
    method: 'DELETE', headers: { origin, host: 'localhost:3000' },
  }) as never, { params: Promise.resolve({ id }) })

const actAsAlice = () => {
  h.session = { userId: 'user-admin', role: 'admin' }
  h.effective = 'alice'
}
/** A user scope is written through act-as only for a passwordless managed account (HD-23). */
const actAsManagedAlice = () => {
  actAsAlice()
  h.managed = new Set(['alice'])
}

describe('reject', () => {
  test('a user-skill proposal: rejected and audited at its point by its owner, without onBehalfOf', async () => {
    const cs = await userSkillSet()
    const res = await post(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(200)
    expect(db.rows('pluginOverride')[0]).toMatchObject({ status: 'rejected', decidedBy: 'alice' })
    expect(h.audits).toEqual([{
      actorId: 'alice', action: 'plugin.override.reject', targetType: 'plugin_change_set', targetId: cs, before: undefined,
      after: { point: 'user_skill.text', targetGroup: 'skflow', scope: 'user', scopeId: 'alice', pluginId: 'skiller' },
      source: 'ui',
    }])
  })

  test('an admin acting as the managed owner: decidedBy and the actor are the admin, onBehalfOf the owner', async () => {
    actAsManagedAlice()
    const cs = await userSkillSet()
    expect((await post(cs, { scopeOwnerId: 'alice' })).status).toBe(200)
    expect(db.rows('pluginOverride')[0]).toMatchObject({ status: 'rejected', decidedBy: 'user-admin' })
    expect(h.audits[0]).toMatchObject({ actorId: 'user-admin', after: { onBehalfOf: 'alice', point: 'user_skill.text' } })
  })

  test('the same for a built-in proposal', async () => {
    actAsManagedAlice()
    const cs = await builtinSet()
    expect((await post(cs, { scopeOwnerId: 'alice' })).status).toBe(200)
    expect(h.audits[0]).toMatchObject({ actorId: 'user-admin', after: { onBehalfOf: 'alice', point: 'skill.text' } })
  })

  test('an adopted set cannot be rejected: 409 already_decided', async () => {
    const cs = await userSkillSet()
    await db.$transaction(async (tx) => ov.markAdoptedIn(tx as never, await ov.lockChangeSet(tx as never, cs), 'alice', { skillId: 'sk', name: 'n' }))
    const res = await post(cs, { scopeOwnerId: 'alice' })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('already_decided')
    expect(h.audits).toEqual([])
  })

  test('a scopeOwnerId other than the effective user: 403, nothing changes', async () => {
    actAsAlice()
    const cs = await userSkillSet()
    expect((await post(cs, { scopeOwnerId: 'user-admin' })).status).toBe(403)
    expect(db.rows('pluginOverride')[0].status).toBe('proposed')
  })
})

describe('delete', () => {
  test('by the owner: no onBehalfOf', async () => {
    const cs = await userSkillSet()
    const res = await del(cs)
    expect(res.status).toBe(200)
    expect(db.rows('pluginOverride')).toEqual([])
    expect(h.audits).toEqual([{
      actorId: 'alice', action: 'plugin.override.delete', targetType: 'plugin_change_set', targetId: cs, before: undefined,
      after: { point: 'user_skill.text', targetGroup: 'skflow', scope: 'user', scopeId: 'alice', revision: null, pluginId: 'skiller' },
      source: 'ui',
    }])
  })

  test('an admin acting as the managed owner: the actor is the admin, onBehalfOf the owner', async () => {
    actAsManagedAlice()
    const cs = await userSkillSet()
    expect((await del(cs)).status).toBe(200)
    expect(h.audits[0]).toMatchObject({ actorId: 'user-admin', action: 'plugin.override.delete', after: { onBehalfOf: 'alice', point: 'user_skill.text' } })
  })

  test('a project-scope built-in version deleted by an admin acting as the owner', async () => {
    actAsAlice()
    const cs = await builtinSet({ type: 'project', id: 'p-alice' })
    expect((await del(cs)).status).toBe(200)
    expect(h.audits[0]).toMatchObject({ actorId: 'user-admin', after: { onBehalfOf: 'alice', scope: 'project', scopeId: 'p-alice' } })
  })

  test('cross-origin: 403, nothing deleted', async () => {
    const cs = await userSkillSet()
    expect((await del(cs, 'https://evil.example')).status).toBe(403)
    expect(db.rows('pluginOverride')).toHaveLength(1)
  })
})
