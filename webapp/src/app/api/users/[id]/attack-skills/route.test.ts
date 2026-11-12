/**
 * GET/POST /api/users/[id]/attack-skills (plan 0.C, 4, 5): the list carries each skill's
 * version, lineage, source name, quarantine, pending proposals and a duplicate-name flag,
 * never the text; the upload goes through createUserSkill and answers its refusals by code.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as { userId: string; role: string } | null,
  denied: null as unknown,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', () => ({
  requireUserAccess: async () => h.denied,
  getSession: async () => h.session,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma, type Row } from '@/lib/plugins/__testing__/fakePrisma'
import { MAX_CONTENT_SIZE } from '@/lib/userSkills'
import { GET, POST } from './route'

let db: FakePrisma
let listCalls: Record<string, unknown>[]

const params = (id: string) => ({ params: Promise.resolve({ id }) })
const get = (id = 'alice') => GET(new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills`), params(id))
const post = (body: unknown, id = 'alice') => POST(new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: typeof body === 'string' ? body : JSON.stringify(body),
}), params(id))

/**
 * The fake has no relation select; the list's `derivedFrom: {select: {name}}` is answered
 * here from the same table, and everything else is the fake's.
 */
function withDerivedFrom(fake: FakePrisma): Record<string, unknown> {
  const skills = fake.userAttackSkill
  const userAttackSkill = {
    ...skills,
    findMany: async (a: { select?: Record<string, unknown> } & Record<string, unknown>) => {
      listCalls.push(a)
      const { derivedFrom, ...select } = a.select ?? {}
      const rows = await skills.findMany({ ...a, select: { ...select, derivedFromId: true } } as never)
      return rows.map((r: Row) => {
        const out: Row = { ...r }
        if (!('derivedFromId' in select)) delete out.derivedFromId
        if (derivedFrom) {
          const parent = fake.rows('userAttackSkill').find((x) => x.id === r.derivedFromId)
          out.derivedFrom = parent ? { name: parent.name } : null
        }
        return out
      })
    },
  }
  return new Proxy(fake as unknown as Record<string, unknown>, {
    get: (t, k) => (k === 'userAttackSkill' ? userAttackSkill : t[k as string]),
  })
}

function override(row: Record<string, unknown>) {
  return {
    pluginId: 'skiller', extensionPoint: 'user_skill.text', scopeType: 'user', scopeId: 'alice', userId: 'alice',
    value: 'v', baseSha256: 'a'.repeat(64), status: 'proposed', createdBy: 'alice', ...row,
    targetKey: `${row.targetGroup}/body`,
  }
}

beforeEach(() => {
  db = createFakePrisma()
  listCalls = []
  h.db = withDerivedFrom(db)
  h.session = { userId: 'alice', role: 'standard' }
  h.denied = null
  h.audits = []
})

describe('GET', () => {
  beforeEach(() => {
    db.seed('userAttackSkill', [
      { id: 'src', userId: 'alice', name: 'My SQLi flow', content: 'SOURCE TEXT', createdAt: new Date('2026-10-01T00:00:00Z'), lineageRootId: 'src', version: 1 },
      {
        id: 'v2', userId: 'alice', name: 'My SQLi flow v2', content: 'V2 TEXT', createdAt: new Date('2026-10-03T00:00:00Z'),
        lineageRootId: 'src', version: 2, derivedFromId: 'src', originPluginId: 'skiller',
        quarantinedAt: new Date('2026-10-05T00:00:00Z'), quarantineReason: 'plugin_version_revoked',
      },
      { id: 'dup_a', userId: 'alice', name: 'Recon', content: 'x', createdAt: new Date('2026-10-02T00:00:00Z') },
      { id: 'dup_b', userId: 'alice', name: 'recon', content: 'x', createdAt: new Date('2026-10-04T00:00:00Z') },
      { id: 'bobs', userId: 'bob', name: 'Recon', content: 'x', createdAt: new Date('2026-10-06T00:00:00Z') },
    ])
    db.seed('pluginOverride', [
      override({ targetGroup: 'src', changeSetId: 'cs-new', createdAt: new Date('2026-10-07T00:00:00Z') }),
      override({ targetGroup: 'src', changeSetId: 'cs-old', createdAt: new Date('2026-10-06T00:00:00Z') }),
      override({ targetGroup: 'src', changeSetId: 'cs-old', createdAt: new Date('2026-10-06T00:00:00Z') }),
      override({ targetGroup: 'src', changeSetId: 'cs-rejected', status: 'rejected' }),
      override({ targetGroup: 'src', changeSetId: 'cs-adopted', status: 'adopted' }),
      override({ targetGroup: 'src', changeSetId: 'cs-bob', scopeId: 'bob', userId: 'bob' }),
      override({ targetGroup: 'src', changeSetId: 'cs-builtin', extensionPoint: 'skill.text' }),
    ])
  })

  test("lists only the user's skills, newest first, without the text", async () => {
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.map((s: Row) => s.id)).toEqual(['dup_b', 'v2', 'dup_a', 'src'])
    for (const s of body) expect(s).not.toHaveProperty('content')
    expect(JSON.stringify(body)).not.toContain('TEXT')
    expect(listCalls[0]).toMatchObject({
      where: { userId: 'alice' },
      orderBy: { createdAt: 'desc' },
      select: { derivedFrom: { select: { name: true } } },
    })
  })

  test('each skill carries version, lineage, its source name and its quarantine', async () => {
    const body = await (await get()).json()
    const v2 = body.find((s: Row) => s.id === 'v2')
    expect(v2).toMatchObject({
      name: 'My SQLi flow v2', version: 2, lineageRootId: 'src', derivedFromId: 'src', derivedFromName: 'My SQLi flow',
      originPluginId: 'skiller', quarantinedAt: '2026-10-05T00:00:00.000Z', quarantineReason: 'plugin_version_revoked',
    })
    expect(v2).not.toHaveProperty('derivedFrom')
    expect(body.find((s: Row) => s.id === 'dup_a')).toMatchObject({ derivedFromName: null, version: null, quarantinedAt: null })
  })

  test("pendingChangeSetIds: the user's proposed user_skill.text sets of that skill, once each, newest first", async () => {
    const body = await (await get()).json()
    expect(body.find((s: Row) => s.id === 'src').pendingChangeSetIds).toEqual(['cs-new', 'cs-old'])
    expect(body.find((s: Row) => s.id === 'v2').pendingChangeSetIds).toEqual([])
  })

  test('duplicateName flags two names equal by the uniqueness key, and only those', async () => {
    const body = await (await get()).json()
    const flag = Object.fromEntries(body.map((s: Row) => [s.id, s.duplicateName]))
    expect(flag).toEqual({ v2: false, dup_b: true, dup_a: true, src: false })
  })

  test('an empty list', async () => {
    expect(await (await get('carol')).json()).toEqual([])
  })

  test('a caller refused by requireUserAccess gets its answer and nothing is read', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    const res = await get()
    expect(res.status).toBe(403)
    expect(listCalls).toEqual([])
  })
})

describe('POST', () => {
  test('201 with the created skill, its normalized name and no text', async () => {
    const res = await post({ name: '  My\tflow ', description: 'Does a thing', content: 'Body' })
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body).toMatchObject({ name: 'My flow', description: 'Does a thing', version: null, lineageRootId: null, quarantinedAt: null })
    expect(typeof body.id).toBe('string')
    expect(body).not.toHaveProperty('content')
    expect(db.rows('userAttackSkill')).toEqual([expect.objectContaining({ id: body.id, userId: 'alice', content: 'Body' })])
  })

  test('409 name_taken carries code and suggestion', async () => {
    db.seed('userAttackSkill', [{ id: 's1', userId: 'alice', name: 'My flow', content: 'x' }])
    const res = await post({ name: 'MY FLOW', content: 'x' })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.code).toBe('name_taken')
    expect(body.suggestion).toBe('MY FLOW v2')
    expect(typeof body.error).toBe('string')
  })

  test('409 skill_limit at 1000 skills', async () => {
    db.seed('userAttackSkill', Array.from({ length: 1000 }, (_, i) => ({ userId: 'alice', name: `S${i}`, content: 'x' })))
    const res = await post({ name: 'One more', content: 'x' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'skill_limit', limit: 1000 })
  })

  test.each([
    ['empty content', { name: 'A', content: '' }, 'content_required'],
    ['content over MAX_CONTENT_SIZE', { name: 'A', content: 'x'.repeat(MAX_CONTENT_SIZE + 1) }, 'content_too_large'],
    ['a description over 500', { name: 'A', content: 'x', description: 'd'.repeat(501) }, 'description_too_long'],
    ['a name over 100', { name: 'n'.repeat(101), content: 'x' }, 'name_too_long'],
    ['no name', { content: 'x' }, 'name_invalid'],
  ])('400 for %s, by code', async (_label, body, code) => {
    const res = await post(body)
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe(code)
    expect(db.rows('userAttackSkill')).toHaveLength(0)
  })

  test.each([['not JSON', '{name:'], ['JSON null', 'null'], ['a JSON string', '"x"'], ['an empty body', '']])(
    '400 when the body is %s',
    async (_label, raw) => {
      const res = await post(raw)
      expect(res.status).toBe(400)
      expect(db.rows('userAttackSkill')).toHaveLength(0)
    },
  )

  test('an admin writing for the user is audited as themself, on behalf of the owner', async () => {
    h.session = { userId: 'admin1', role: 'admin' }
    expect((await post({ name: 'By admin', content: 'x' })).status).toBe(201)
    expect(h.audits).toEqual([expect.objectContaining({
      actorId: 'admin1', action: 'user_attack_skill.create', after: expect.objectContaining({ onBehalfOf: 'alice', userId: 'alice' }),
    })])
  })

  test('a caller refused by requireUserAccess creates nothing', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await post({ name: 'A', content: 'x' }, 'bob')).status).toBe(403)
    expect(db.rows('userAttackSkill')).toHaveLength(0)
    expect(h.audits).toEqual([])
  })
})
