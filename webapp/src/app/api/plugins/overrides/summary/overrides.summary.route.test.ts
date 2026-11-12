/**
 * GET /api/plugins/overrides/summary (design §6): per built-in skill, what governs this
 * project and whether it applies. Only the project's owner; another's project is a 404.
 *
 * @vitest-environment node
 */
import { test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, effective: '' }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', () => ({ getSession: async () => ({ userId: h.effective, role: 'standard' }), getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null) }))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: async () => new Response('{}', { status: 404 }) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { projectScope, seedProposal, seedWorld, sha256, userScope, FACTORY } from '@/lib/plugins/__testing__/reviewHarness'
import * as ov from '@/lib/plugins/overrides'
import type { SummaryModel } from '@/lib/plugins/summaryModel'
import { GET } from './route'

let db: FakePrisma
const H = () => ({ 'ssrf/workflow': sha256(FACTORY.workflow) })
const get = (projectId?: string) => GET(new Request(`http://localhost:3000/api/plugins/overrides/summary${projectId ? `?projectId=${projectId}` : ''}`) as never)
/** The skill's summary with a non-null `applies` (the tests that read it seed one). */
const forSkill = (body: SummaryModel, id: string) => {
  const s = body.skills.find((x) => x.skillId === id)!
  return { ...s, applies: s.applies! }
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.effective = 'alice'
})

test('missing projectId: 400', async () => {
  expect((await get()).status).toBe(400)
})

test('another user’s project: 404', async () => {
  expect((await get('p-bob')).status).toBe(404)
})

test('no overrides: every skill has a null applies and zero pending', async () => {
  const body = await (await get('p-alice')).json()
  expect(body.skills.length).toBe(14)
  expect(body.skills.every((s: { applies: unknown; pending: number }) => s.applies === null && s.pending === 0)).toBe(true)
})

test('an applied user-scope version shows as applied, scope user, with the plugin name', async () => {
  const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  const body = await (await get('p-alice')).json()
  const ssrf = forSkill(body, 'ssrf')
  expect(ssrf.applies).toMatchObject({ scope: 'user', applied: true, pluginDisplayName: 'Skiller', revision: 2 })
})

test('a project version wins over the owner user version for that skill', async () => {
  const u = await seedProposal(userScope('alice'), { workflow: 'U' })
  await ov.approve(u, 'alice', H())
  const p = await seedProposal(projectScope('p-alice'), { workflow: 'P' })
  await ov.approve(p, 'alice', H())
  const ssrf = forSkill(await (await get('p-alice')).json(), 'ssrf')
  expect(ssrf.applies.scope).toBe('project')
})

test('an active version of a disabled plugin: not applied, with the dormant reason', async () => {
  const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  await db.pluginInstall.update({ where: { pluginId: 'skiller' }, data: { enabled: false } })
  const ssrf = forSkill(await (await get('p-alice')).json(), 'ssrf')
  expect(ssrf.applies.applied).toBe(false)
  expect(ssrf.applies.dormantReason).toBe('disabled')
})

test('a stale PROJECT version is reported stale and not applied (factory text runs)', async () => {
  // A project version stays the governing set while stale; a user-scope stale version does
  // not (the skill falls back to factory), so the chip only appears for a project version.
  const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  await ov.markStale(cs, 'factory_changed', db as never)
  const ssrf = forSkill(await (await get('p-alice')).json(), 'ssrf')
  expect(ssrf.applies.status).toBe('stale')
  expect(ssrf.applies.scope).toBe('project')
  expect(ssrf.applies.applied).toBe(false)
})

test('pending proposals are counted across the project and the owner user scope', async () => {
  await seedProposal(userScope('alice'), { workflow: 'U' })
  await seedProposal(projectScope('p-alice'), { workflow: 'P' })
  const ssrf = forSkill(await (await get('p-alice')).json(), 'ssrf')
  expect(ssrf.pending).toBe(2)
})
