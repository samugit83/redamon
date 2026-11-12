/**
 * GET /api/plugins/overrides/versions (design §6): the versions of a built-in skill in the
 * effective user's scope, plus a project they own; another user's scope is never listed.
 * The active version's dormant state and the factory-in-use flag are derived here.
 *
 * @vitest-environment node
 */
import { test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  effective: '',
  agent: null as unknown as (path: string) => Promise<Response>,
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', () => ({ getSession: async () => ({ userId: h.effective, role: 'standard' }), getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null) }))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: (path: string) => h.agent(path) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { agentHandler, freshAgent, projectScope, seedProposal, seedWorld, sha256, userScope, FACTORY, type AgentState } from '@/lib/plugins/__testing__/reviewHarness'
import { clearSkillPartsCache } from '@/lib/plugins/skillPartsRegistry'
import * as ov from '@/lib/plugins/overrides'
import { GET } from './route'

let db: FakePrisma
let agent: AgentState
const H = () => ({ 'ssrf/workflow': sha256(FACTORY.workflow) })

const get = (qs: string) => GET(new Request(`http://localhost:3000/api/plugins/overrides/versions?${qs}`) as never)

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  agent = freshAgent()
  h.agent = agentHandler(agent)
  h.effective = 'alice'
  clearSkillPartsCache()
})

test('an unknown skill: 404', async () => {
  expect((await get('point=skill.text&group=not_a_skill')).status).toBe(404)
})

test('a bad point: 400', async () => {
  expect((await get('point=nav&group=ssrf')).status).toBe(400)
})

test('the user scope, with the factory in use when nothing is active', async () => {
  const m = await (await get('point=skill.text&group=ssrf')).json()
  expect(m.scopes).toHaveLength(1)
  expect(m.scopes[0].scopeType).toBe('user')
  expect(m.scopes[0].factoryInUse).toBe(true)
  expect(m.scopes[0].versions).toEqual([])
})

test('an approved version is active and applied; factory not in use', async () => {
  const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  clearSkillPartsCache()
  const m = await (await get('point=skill.text&group=ssrf')).json()
  const v = m.scopes[0].versions.find((x: { changeSetId: string }) => x.changeSetId === cs)
  expect(v.status).toBe('active')
  expect(v.applied).toBe(true)
  expect(m.scopes[0].factoryInUse).toBe(false)
})

test('an active version of a disabled plugin is not applied; factory in use', async () => {
  const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  await db.pluginInstall.update({ where: { pluginId: 'skiller' }, data: { enabled: false } })
  clearSkillPartsCache()
  const m = await (await get('point=skill.text&group=ssrf')).json()
  expect(m.scopes[0].dormantReason).toBe('disabled')
  expect(m.scopes[0].factoryInUse).toBe(true)
  expect(m.scopes[0].versions[0].applied).toBe(false)
})

test('the project scope is listed only when the caller owns it', async () => {
  await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
  const owned = await (await get('point=skill.text&group=ssrf&projectId=p-alice')).json()
  expect(owned.scopes.map((s: { scopeType: string }) => s.scopeType)).toEqual(['user', 'project'])

  await seedProposal(projectScope('p-bob'), { workflow: 'W2' })
  const notOwned = await (await get('point=skill.text&group=ssrf&projectId=p-bob')).json()
  expect(notOwned.scopes.map((s: { scopeType: string }) => s.scopeType)).toEqual(['user'])
})

test('lastRevision explains a gap after deletions', async () => {
  const v2 = await seedProposal(userScope('alice'), { workflow: 'W2' })
  await ov.approve(v2, 'alice', H())
  const v3 = await seedProposal(userScope('alice'), { workflow: 'W3' }, { fromRevision: 2 })
  await ov.approve(v3, 'alice', H())
  await ov.reset(userScope('alice'), 'skill.text', 'ssrf', 'alice')
  await ov.deleteChangeSet(v3)
  await ov.deleteChangeSet(v2)
  clearSkillPartsCache()
  const m = await (await get('point=skill.text&group=ssrf')).json()
  expect(m.scopes[0].lastRevision).toBe(3) // counter never lowered
  expect(m.scopes[0].versions).toEqual([]) // both deleted
})

test('factory text is included for the View diff; agent outdated says so', async () => {
  const ok = await (await get('point=skill.text&group=ssrf')).json()
  expect(ok.factoryText.workflow).toBe(FACTORY.workflow)
  agent.registryStatus = 404
  clearSkillPartsCache()
  const stale = await (await get('point=skill.text&group=ssrf')).json()
  expect(stale.registryError).toBe('agent_outdated')
  expect(stale.factoryText).toBeNull()
})
