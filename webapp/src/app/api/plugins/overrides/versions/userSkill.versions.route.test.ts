/**
 * GET /api/plugins/overrides/versions?point=user_skill.text&group=<skill id>&projectId=: the
 * versions window of one of the effective user's own skills (lib/plugins/userSkillVersionsModel.ts):
 * its family of saved versions, which of them "Delete older versions" removes (all but the
 * newest and any on in a project), and the proposals made from the family with what each
 * became. Another user's skill is a 404; a point other than the two behaviour points a 400.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, effective: '' }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', () => ({
  getSession: async () => (h.effective ? { userId: h.effective, role: 'standard' } : null),
  getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null),
}))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: async () => Response.json({}, { status: 404 }) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: async () => {} }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { setNowForTests } from '@/lib/plugins/clock'
import * as ov from '@/lib/plugins/overrides'
import { GET } from './route'

const T0 = Date.parse('2026-10-09T10:00:00.000Z')
const H = 'a'.repeat(64)
let db: FakePrisma
let t = T0

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  t = T0
  setNowForTests(() => new Date(t))
  db.seed('user', [
    { id: 'alice', email: 'alice@example.com' },
    { id: 'bob', email: 'bob@example.com' },
  ])
  db.seed('pluginInstall', [
    { pluginId: 'skiller', enabled: true, status: 'ready', activeVersion: '1.1.0', manifest: { id: 'skiller', displayName: 'Skiller' }, grantedPermissions: ['override:user_skill.text'] },
  ])
  db.seed('userAttackSkill', [
    { id: 'skroot', userId: 'alice', name: 'Flow', content: 'v1', lineageRootId: 'skroot', version: 1, createdAt: new Date(T0) },
    { id: 'skv2', userId: 'alice', name: 'Flow v2', content: 'v2', lineageRootId: 'skroot', derivedFromId: 'skroot', version: 2, createdAt: new Date(T0 + 1000) },
    {
      id: 'skv3', userId: 'alice', name: 'Flow v3', content: 'v3', lineageRootId: 'skroot', derivedFromId: 'skv2', version: 3, createdAt: new Date(T0 + 2000),
      quarantinedAt: new Date(T0 + 5000), quarantineReason: 'plugin_version_revoked',
    },
    { id: 'skalone', userId: 'alice', name: 'Alone', content: 'x', createdAt: new Date(T0) },
    // Bob's row naming Alice's root must never join her family.
    { id: 'skbob', userId: 'bob', name: 'Flow v9', content: 'b', lineageRootId: 'skroot', version: 9, createdAt: new Date(T0) },
  ])
  db.seed('project', [
    { id: 'p-alice', userId: 'alice', name: 'A', attackSkillConfig: { builtIn: {}, user: { skroot: true, skv2: false } } },
    { id: 'p-alice-2', userId: 'alice', name: 'A2', attackSkillConfig: { builtIn: {}, user: { skroot: true } } },
    // Bob's project turning on Alice's v2 counts for nothing in her window.
    { id: 'p-bob', userId: 'bob', name: 'B', attackSkillConfig: { builtIn: {}, user: { skv2: true } } },
  ])
  h.effective = 'alice'
})
afterEach(() => setNowForTests(null))

const get = async (qs: string) => {
  const res = await GET(new Request(`http://localhost:3000/api/plugins/overrides/versions?${qs}`) as never)
  return { status: res.status, body: await res.json(), cache: res.headers.get('cache-control') }
}

async function propose(source: string, opts: { owner?: string; point?: 'skill.text' | 'user_skill.text'; note?: string } = {}) {
  const point = opts.point ?? 'user_skill.text'
  const owner = opts.owner ?? 'alice'
  const { changeSetId } = await ov.propose({
    pluginId: 'skiller', point, scope: { type: 'user', id: owner }, targetGroup: source,
    parts: [{ targetKey: `${source}/${point === 'skill.text' ? 'workflow' : 'body'}`, value: 'proposed', baseSha256: H }],
    note: opts.note ?? `from ${source}`,
    platformMeta: point === 'user_skill.text' ? { baseText: 'v', sourceName: `name of ${source} then`, pluginVersion: '1.1.0' } : {},
    createdBy: owner,
  })
  t += 1000
  return changeSetId
}

async function adopt(changeSetId: string, skillId: string, name: string) {
  await db.$transaction(async (tx) => ov.markAdoptedIn(tx as never, await ov.lockChangeSet(tx as never, changeSetId), 'alice', { skillId, name }))
}

describe('the family', () => {
  test('every saved version of the lineage, newest first, with where each is on', async () => {
    const r = await get('point=user_skill.text&group=skv2&projectId=p-alice')
    expect(r.status).toBe(200)
    expect(r.cache).toBe('no-store')
    expect(r.body.kind).toBe('user_skill')
    expect(r.body.skill).toEqual({ id: 'skv2', name: 'Flow v2' })
    expect(r.body.family).toEqual([
      { id: 'skv3', name: 'Flow v3', version: 3, createdAt: new Date(T0 + 2000).toISOString(), enabledInProject: false, enabledProjects: 0, quarantined: true },
      { id: 'skv2', name: 'Flow v2', version: 2, createdAt: new Date(T0 + 1000).toISOString(), enabledInProject: false, enabledProjects: 0, quarantined: false },
      { id: 'skroot', name: 'Flow', version: 1, createdAt: new Date(T0).toISOString(), enabledInProject: true, enabledProjects: 2, quarantined: false },
    ])
  })

  test('the same family whichever member the window is opened on', async () => {
    const ids = async (group: string) => (await get(`point=user_skill.text&group=${group}`)).body.family.map((m: { id: string }) => m.id)
    expect(await ids('skroot')).toEqual(['skv3', 'skv2', 'skroot'])
    expect(await ids('skv3')).toEqual(['skv3', 'skv2', 'skroot'])
  })

  test('without a project, enabledInProject is null', async () => {
    const r = await get('point=user_skill.text&group=skv2')
    expect(r.body.family.map((m: { enabledInProject: unknown }) => m.enabledInProject)).toEqual([null, null, null])
  })

  test('deletable: all but the newest, the one the window shows, and any version on in one of the owner\'s projects', async () => {
    expect((await get('point=user_skill.text&group=skv3')).body.deletable).toEqual(['skv2'])
    // Opened on skv2 (a session that used it): the window never deletes what it shows.
    expect((await get('point=user_skill.text&group=skv2')).body.deletable).toEqual([])
    await db.project.update({ where: { id: 'p-alice' }, data: { attackSkillConfig: { builtIn: {}, user: { skv2: true } } } })
    await db.project.update({ where: { id: 'p-alice-2' }, data: { attackSkillConfig: { builtIn: {}, user: {} } } })
    expect((await get('point=user_skill.text&group=skv3')).body.deletable).toEqual(['skroot'])
  })

  test('a skill with no family: itself, nothing deletable', async () => {
    const r = await get('point=user_skill.text&group=skalone')
    expect(r.body.family.map((m: { id: string }) => m.id)).toEqual(['skalone'])
    expect(r.body.deletable).toEqual([])
    expect(r.body.proposals).toEqual([])
  })
})

describe('the proposals', () => {
  test('those made from any member, newest first, with what each became; others never listed', async () => {
    const fromRoot = await propose('skroot', { note: 'first' })
    await adopt(fromRoot, 'skv2', 'Flow v2')
    const fromV3 = await propose('skv3', { note: 'second' })
    await propose('skalone')
    await propose('skroot', { owner: 'bob' })
    await propose('skroot', { point: 'skill.text' })

    const r = await get('point=user_skill.text&group=skv2')
    expect(r.body.proposals).toEqual([
      {
        changeSetId: fromV3, status: 'proposed', sourceId: 'skv3', sourceName: 'Flow v3', pluginId: 'skiller', pluginDisplayName: 'Skiller',
        note: 'second', createdAt: new Date(T0 + 1000).toISOString(), decidedAt: null, adopted: null,
      },
      {
        changeSetId: fromRoot, status: 'adopted', sourceId: 'skroot', sourceName: 'Flow', pluginId: 'skiller', pluginDisplayName: 'Skiller',
        note: 'first', createdAt: new Date(T0).toISOString(), decidedAt: new Date(T0 + 1000).toISOString(), adopted: { skillId: 'skv2', name: 'Flow v2' },
      },
    ])
  })

  test('the plugin named by its id once it is gone', async () => {
    await propose('skroot')
    await db.pluginInstall.delete({ where: { pluginId: 'skiller' } })
    expect((await get('point=user_skill.text&group=skroot')).body.proposals[0]).toMatchObject({ pluginId: 'skiller', pluginDisplayName: 'skiller' })
  })
})

describe('who may read, and what', () => {
  test("another user's skill, an unknown one, or none named: 404", async () => {
    h.effective = 'bob'
    expect((await get('point=user_skill.text&group=skv2')).status).toBe(404)
    h.effective = 'alice'
    expect((await get('point=user_skill.text&group=skbob')).status).toBe(404)
    expect((await get('point=user_skill.text&group=sknosuch')).status).toBe(404)
    expect((await get('point=user_skill.text')).status).toBe(404)
  })

  test("a project of another user never shows its toggles", async () => {
    const r = await get('point=user_skill.text&group=skv2&projectId=p-bob')
    expect(r.body.family.map((m: { enabledInProject: unknown }) => m.enabledInProject)).toEqual([false, false, false])
  })

  test('a point other than skill.text or user_skill.text, or none: 400 bad_point', async () => {
    expect(await get('point=nav&group=skv2')).toMatchObject({ status: 400, body: { code: 'bad_point' } })
    expect(await get('group=skv2')).toMatchObject({ status: 400, body: { code: 'bad_point' } })
  })

  test('not signed in: 401', async () => {
    h.effective = ''
    expect((await get('point=user_skill.text&group=skv2')).status).toBe(401)
  })
})
