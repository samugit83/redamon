/**
 * GET /api/plugins/[pluginId]/session-skills?sessionId=&projectId= (platform 1.1.0): the skill
 * picker's list. The same ownership check and the same refusals as an action start; only the
 * points the plugin is granted AND declares; a built-in skill carries the version that applies
 * in the project; `running` is the agent's answer; `suggested` the most-used selectable skill.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { createHash } from 'crypto'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  eff: null as { userId: string } | null,
  live: [] as string[] | null,
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', () => ({
  getEffectiveUser: async () => h.eff,
  getSession: async () => (h.eff ? { userId: h.eff.userId, role: 'standard' } : null),
}))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return {
    AgentUnreachableError,
    agentFetch: async (path: string) => {
      if (path.startsWith('/agent-sessions/live')) {
        if (h.live === null) throw new AgentUnreachableError('down')
        return Response.json({ session_ids: h.live })
      }
      return Response.json({ detail: 'Not Found' }, { status: 404 })
    },
  }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { createFakePrisma, type FakePrisma, type Row } from '@/lib/plugins/__testing__/fakePrisma'
import {
  ALICE, ALICE_CONV, ALICE_OTHER_PROJECT, ALICE_OTHER_SESSION, ALICE_PROJECT, ALICE_SESSION, BOB, BOB_PROJECT, BOB_SESSION,
  echoInstall, echoManifest, seedWorld,
} from '@/lib/plugins/__testing__/gatewayHarness'
import { setNowForTests } from '@/lib/plugins/clock'
import * as ov from '@/lib/plugins/overrides'
import { GET } from './route'

const sha16 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16)
const ALL = ['session:read', 'llm:invoke', 'override:skill.text', 'override:user_skill.text']
const T0 = Date.parse('2026-10-09T10:00:00.000Z')
let db: FakePrisma

function world(install: Row = {}) {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db, { install: echoInstall({ grantedPermissions: ALL, manifest: echoManifest({ permissions: ALL }), ...install }) })
  db.seed('userAttackSkill', [
    { id: 'skalice', userId: ALICE, name: 'My SQLi flow', content: 'Enumerate example.com.' },
    { id: 'skcreds', userId: ALICE, name: 'Creds', content: 'Sign with AKIAIOSFODNN7EXAMPLE.' },
    { id: 'skbob', userId: BOB, name: 'Bob flow', content: 'Bob only.' },
  ])
  const turns: [number, Record<string, unknown>][] = [
    [1, { attack_path_type: 'sql_injection' }],
    [2, { skill_workflow: { skillId: 'user_skill:skalice', kind: 'user', contentSha256: sha16('Enumerate example.com.') } }],
    [3, { skill_workflow: { skillId: 'user_skill:skalice', kind: 'user', contentSha256: sha16('Enumerate example.com.') } }],
    [4, { skill_workflow: { skillId: 'user_skill:skcreds', kind: 'user', contentSha256: 'x' } }],
    [5, { skill_workflow: { skillId: 'user_skill:skcreds', kind: 'user', contentSha256: 'x' } }],
    [6, { skill_workflow: { skillId: 'user_skill:skcreds', kind: 'user', contentSha256: 'x' } }],
    [7, { skill_workflow: { skillId: 'user_skill:skbob', kind: 'user', contentSha256: 'x' } }],
    [8, { attack_path_type: 'xss' }],
  ]
  db.seed('chatMessage', turns.map(([n, data]) => ({
    conversationId: ALICE_CONV, sequenceNum: n, type: 'phase_update', createdAt: new Date(T0 + n * 1000),
    data: { current_phase: 'informational', iteration_count: n, ...data },
  })))
}

beforeEach(() => {
  world()
  h.eff = { userId: ALICE }
  h.live = []
  setNowForTests(() => new Date(T0))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setNowForTests(null)
  vi.restoreAllMocks()
})

async function list(qs: Record<string, string> = { sessionId: ALICE_SESSION, projectId: ALICE_PROJECT }, pluginId = 'echo') {
  const url = `http://localhost:3000/api/plugins/${pluginId}/session-skills?${new URLSearchParams(qs)}`
  const res = await GET(new NextRequest(url), { params: Promise.resolve({ pluginId }) })
  return { status: res.status, body: await res.json(), cache: res.headers.get('cache-control') }
}

describe('the list', () => {
  test('every skill of both points, why one cannot be picked, the built-in version, running and the suggestion', async () => {
    const r = await list()
    expect(r.status).toBe(200)
    expect(r.cache).toBe('no-store')
    expect(r.body.running).toBe(false)
    expect(r.body.skills).toEqual([
      expect.objectContaining({ ref: 'user_skill:skcreds', kind: 'user', point: 'user_skill.text', turns: 3, selectable: false, reason: 'credentials', name: 'Creds' }),
      expect.objectContaining({ ref: 'user_skill:skalice', kind: 'user', turns: 2, selectable: true, name: 'My SQLi flow' }),
      { ref: 'xss', kind: 'builtin', point: 'skill.text', target: 'xss', name: 'Cross-Site Scripting', turns: 1, lastSeq: 8, exists: true, selectable: true, byLabel: true, revision: 1 },
      expect.objectContaining({ ref: 'user_skill:skbob', exists: false, selectable: false, reason: 'deleted', name: null }),
      expect.objectContaining({ ref: 'sql_injection', kind: 'builtin', turns: 1, revision: 1 }),
    ])
    // A user skill has no built-in version.
    for (const s of r.body.skills.filter((x: { kind: string }) => x.kind === 'user')) expect(s).not.toHaveProperty('revision')
    // The most turns among those that can be picked.
    expect(r.body.suggested).toBe('user_skill:skalice')
  })

  test("a built-in skill shows the version that applies in the project", async () => {
    // Approved from another plugin: the version belongs to the skill, not to the picker's plugin.
    db.seed('pluginInstall', [echoInstall({ pluginId: 'other', grantedPermissions: ['override:skill.text'], manifest: echoManifest({ id: 'other' }) })])
    const { changeSetId } = await ov.propose({
      pluginId: 'other', point: 'skill.text', scope: { type: 'user', id: ALICE }, targetGroup: 'xss',
      parts: [{ targetKey: 'xss/workflow', value: 'better', baseSha256: 'a'.repeat(64) }], createdBy: ALICE,
    })
    await ov.approve(changeSetId, ALICE, { 'xss/workflow': 'a'.repeat(64) })
    const revision = async () => (await list()).body.skills.find((s: { ref: string }) => s.ref === 'xss').revision
    expect(await revision()).toBe(2)
    // A version whose plugin no longer qualifies does not reach the agent: the factory text runs.
    await db.pluginInstall.update({ where: { pluginId: 'other' }, data: { enabled: false } })
    expect(await revision()).toBe(1)
  })

  test('only the points the plugin is granted AND declares', async () => {
    world({ grantedPermissions: ['session:read', 'override:skill.text'] })
    expect((await list()).body.skills.map((s: { ref: string }) => s.ref).sort()).toEqual(['sql_injection', 'xss'])
    world({ manifest: echoManifest({ permissions: ['session:read', 'override:user_skill.text'] }) })
    expect((await list()).body.skills.every((s: { kind: string }) => s.kind === 'user')).toBe(true)
    world({ grantedPermissions: ['session:read'] })
    expect((await list()).body).toMatchObject({ skills: [], suggested: null })
  })

  test('running is the agent\'s answer, unverified when it cannot be asked', async () => {
    h.live = [ALICE_SESSION]
    expect((await list()).body.running).toBe(true)
    h.live = null
    expect((await list()).body.running).toBe('unverified')
  })

  test('nothing selectable: suggested null', async () => {
    await db.chatMessage.deleteMany({ where: { NOT: { data: { path: ['iteration_count'], equals: 4 } } } })
    const r = await list()
    expect(r.body.skills.map((s: { ref: string }) => s.ref)).toEqual(['user_skill:skcreds'])
    expect(r.body.suggested).toBeNull()
  })
})

describe('refusals', () => {
  test('not signed in: 401', async () => {
    h.eff = null
    expect((await list()).status).toBe(401)
  })

  test('an unknown plugin, a malformed id, or one not installed: 404 plugin_not_found', async () => {
    expect(await list(undefined, 'nobody')).toMatchObject({ status: 404, body: { code: 'plugin_not_found' } })
    expect(await list(undefined, 'Bad_Id')).toMatchObject({ status: 404, body: { code: 'plugin_not_found' } })
    for (const status of ['available', 'installing', 'uninstalling']) {
      world({ status })
      expect((await list()).body.code, status).toBe('plugin_not_found')
    }
  })

  test('being updated: 409 plugin_updating; disabled, revoked or not ready: 409 plugin_unavailable', async () => {
    world({ status: 'updating' })
    expect(await list()).toMatchObject({ status: 409, body: { code: 'plugin_updating' } })
    for (const over of [{ enabled: false }, { revokedReason: 'x' }, { status: 'failed' }, { status: 'updating', enabled: false }, { status: 'updating', revokedReason: 'x' }]) {
      world(over)
      expect(await list(), JSON.stringify(over)).toMatchObject({ status: 409, body: { code: 'plugin_unavailable' } })
    }
  })

  test('no sessionId: 400', async () => {
    expect(await list({ projectId: ALICE_PROJECT })).toMatchObject({ status: 400, body: { code: 'invalid_context' } })
  })

  test("another user's session, a session of another project, a session without its project: 404", async () => {
    const contexts: Record<string, string>[] = [
      { sessionId: BOB_SESSION, projectId: BOB_PROJECT },
      { sessionId: BOB_SESSION, projectId: ALICE_PROJECT },
      { sessionId: ALICE_OTHER_SESSION, projectId: ALICE_PROJECT },
      { sessionId: ALICE_SESSION, projectId: ALICE_OTHER_PROJECT },
      { sessionId: ALICE_SESSION },
      { sessionId: 'session-nobody', projectId: ALICE_PROJECT },
    ]
    for (const qs of contexts) {
      expect((await list(qs)).status, JSON.stringify(qs)).toBe(404)
    }
  })
})
