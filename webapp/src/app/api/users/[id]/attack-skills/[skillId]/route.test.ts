/**
 * PUT/DELETE /api/users/[id]/attack-skills/[skillId] (plan 0.C, 4.11): both go through
 * userSkillWrites, so a refusal answers with its code, a skill of another user is the same
 * 404 as an unknown one, and the PUT never writes lineage, provenance or quarantine.
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

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { MAX_CONTENT_SIZE } from '@/lib/userSkills'
import { DELETE, PUT } from './route'

let db: FakePrisma

const params = (id: string, skillId: string) => ({ params: Promise.resolve({ id, skillId }) })
const url = (id: string, skillId: string) => `http://localhost:3000/api/users/${id}/attack-skills/${skillId}`
const put = (skillId: string, body: unknown, id = 'alice') => PUT(new NextRequest(url(id, skillId), {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: typeof body === 'string' ? body : JSON.stringify(body),
}), params(id, skillId))
const del = (skillId: string, id = 'alice') => DELETE(new NextRequest(url(id, skillId), { method: 'DELETE' }), params(id, skillId))
const skill = (id: string) => db.rows('userAttackSkill').find((r) => r.id === id)

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.session = { userId: 'alice', role: 'standard' }
  h.denied = null
  h.audits = []
  db.seed('userAttackSkill', [
    { id: 'sk_mine', userId: 'alice', name: 'My flow', content: 'Original', lineageRootId: 'sk_root', version: 3, derivedFromId: 'sk_root', originPluginId: 'skiller', originPluginVersion: '1.1.0' },
    { id: 'sk_other', userId: 'alice', name: 'Other flow', content: 'x' },
    { id: 'sk_bob', userId: 'bob', name: 'Bob flow', content: 'Bob text' },
  ])
})

describe('PUT', () => {
  test('renames and replaces the text, answering without it', async () => {
    const res = await put('sk_mine', { name: ' Renamed  flow ', content: 'New text' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toMatchObject({ id: 'sk_mine', name: 'Renamed flow' })
    expect(body).not.toHaveProperty('content')
    expect(skill('sk_mine')).toMatchObject({ name: 'Renamed flow', content: 'New text' })
  })

  test("404 not_found for an unknown skill and for another user's", async () => {
    for (const id of ['sk_nope', 'sk_bob']) {
      const res = await put(id, { name: 'Hijack', content: 'Mine now' })
      expect(res.status).toBe(404)
      expect((await res.json()).code).toBe('not_found')
    }
    expect(skill('sk_bob')).toMatchObject({ name: 'Bob flow', content: 'Bob text' })
  })

  test('409 name_taken with a suggestion for a rename onto another skill', async () => {
    const res = await put('sk_mine', { name: 'OTHER flow' })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.code).toBe('name_taken')
    expect(typeof body.suggestion).toBe('string')
  })

  test('a rename to its own name in another case is allowed', async () => {
    expect((await put('sk_mine', { name: 'MY FLOW' })).status).toBe(200)
    expect(skill('sk_mine')!.name).toBe('MY FLOW')
  })

  test.each([
    ['empty content', { content: '' }, 'content_required'],
    ['whitespace content', { content: '   ' }, 'content_required'],
    ['content over MAX_CONTENT_SIZE', { content: 'x'.repeat(MAX_CONTENT_SIZE + 1) }, 'content_too_large'],
    ['a name over 100', { name: 'n'.repeat(101) }, 'name_too_long'],
    ['a blank name', { name: '  ' }, 'name_invalid'],
    ['a description over 500', { description: 'd'.repeat(501) }, 'description_too_long'],
  ])('400 for %s', async (_label, body, code) => {
    const res = await put('sk_mine', body)
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe(code)
    expect(skill('sk_mine')).toMatchObject({ name: 'My flow', content: 'Original' })
  })

  test('lineage, provenance, quarantine and owner in the body are ignored', async () => {
    const res = await put('sk_mine', {
      content: 'Edited', userId: 'bob', lineageRootId: 'evil', version: 99, derivedFromId: 'evil',
      originPluginId: 'evil', originPluginVersion: '9.9.9', originChangeSetId: 'evil',
      quarantinedAt: '2026-10-01T00:00:00Z', quarantineReason: 'none',
    })
    expect(res.status).toBe(200)
    expect(skill('sk_mine')).toMatchObject({
      userId: 'alice', content: 'Edited', lineageRootId: 'sk_root', version: 3, derivedFromId: 'sk_root',
      originPluginId: 'skiller', originPluginVersion: '1.1.0', originChangeSetId: null, quarantinedAt: null, quarantineReason: null,
    })
  })

  test('400 for a body that is not a JSON object', async () => {
    expect((await put('sk_mine', 'nope')).status).toBe(400)
    expect((await put('sk_mine', 'null')).status).toBe(400)
  })

  test('an admin editing for the owner is audited on behalf of the owner', async () => {
    h.session = { userId: 'admin1', role: 'admin' }
    await put('sk_mine', { content: 'By admin' })
    expect(h.audits).toEqual([expect.objectContaining({
      actorId: 'admin1', action: 'user_attack_skill.update', after: expect.objectContaining({ onBehalfOf: 'alice', changed: ['content'] }),
    })])
  })

  test('a caller refused by requireUserAccess changes nothing', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await put('sk_mine', { content: 'Nope' })).status).toBe(403)
    expect(skill('sk_mine')!.content).toBe('Original')
  })
})

describe('DELETE', () => {
  test('deletes the skill, strips its toggles and answers the counts', async () => {
    db.seed('project', [
      { id: 'p1', userId: 'alice', attackSkillConfig: { builtIn: {}, user: { sk_mine: true, sk_other: true } } },
      { id: 'p2', userId: 'alice', attackSkillConfig: { builtIn: {}, user: { sk_other: false } } },
    ])
    db.seed('pluginOverride', [{
      pluginId: 'skiller', extensionPoint: 'user_skill.text', scopeType: 'user', scopeId: 'alice', userId: 'alice',
      targetGroup: 'sk_mine', targetKey: 'sk_mine/body', changeSetId: '11111111-1111-4111-8111-111111111111',
      value: 'v', baseSha256: 'a'.repeat(64), status: 'proposed', createdBy: 'alice',
    }])
    const res = await del('sk_mine')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ success: true, deletedProposals: 1, projectsUpdated: 1 })
    expect(skill('sk_mine')).toBeUndefined()
    expect(db.rows('project').find((p) => p.id === 'p1')!.attackSkillConfig).toEqual({ builtIn: {}, user: { sk_other: true } })
    expect(db.rows('pluginOverride')).toEqual([])
  })

  test("404 not_found for an unknown skill and for another user's", async () => {
    for (const id of ['sk_nope', 'sk_bob']) {
      const res = await del(id)
      expect(res.status).toBe(404)
      expect((await res.json()).code).toBe('not_found')
    }
    expect(skill('sk_bob')).toBeDefined()
  })

  test('a caller refused by requireUserAccess deletes nothing', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await del('sk_mine')).status).toBe(403)
    expect(skill('sk_mine')).toBeDefined()
    expect(h.audits).toEqual([])
  })
})
