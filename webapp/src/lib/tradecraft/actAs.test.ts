/**
 * The act-as rules of a resource's site login (§6.6, T6.5): its use is refused while an
 * administrator acts as the account when the resource holds a login or the request carries
 * one; a change is refused whatever the resource holds. The refusal itself (the switch, the
 * 403, the `act_as.refused` row) is `refuseWhileActingAsOn`'s, tested in
 * `authz/actAsRefusals.test.ts` and end to end in `actAs.tradecraft.test.ts`; the audit row of a
 * login change names fields, never a value.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb, actingAs: false }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as never)[k] }) }))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async (_owner: string, action: string) => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as', action }, { status: 403 }) : null)),
}))

import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditLoginChange, loginChangeRefusal, loginUseRefusal } from './actAs'

beforeEach(() => {
  h.db = createTradecraftDb()
  h.actingAs = true
  vi.mocked(refuseWhileActingAsOn).mockClear()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  h.db.seed('userTradecraftResource', { id: 'login', userId: 'owner', name: 'KB', slug: 'kb', url: 'https://kb.example.test/', credentials: { cookie: 'session=fake-session' }, hasLogin: true })
  h.db.seed('userTradecraftResource', { id: 'public', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/' })
  // A login the flag missed still counts (masking.hasStoredLogin).
  h.db.seed('userTradecraftResource', { id: 'flagless', userId: 'owner', name: 'Old', slug: 'old', url: 'https://old.example.test/', credentials: { cookie: 'a=1' }, hasLogin: false })
  h.db.seed('userTradecraftResource', { id: 'theirs', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/', credentials: { cookie: 'b=2' }, hasLogin: true })
})

describe('loginUseRefusal', () => {
  test('use_refused: a resource with a login is refused as use_site_logins', async () => {
    const res = await loginUseRefusal({ ownerId: 'owner', resourceId: 'login' })
    expect(res?.status).toBe(403)
    expect(await res!.json()).toMatchObject({ action: 'use_site_logins' })
    expect(vi.mocked(refuseWhileActingAsOn)).toHaveBeenCalledWith('owner', 'use_site_logins')
    expect((await loginUseRefusal({ ownerId: 'owner', resourceId: 'flagless' }))?.status).toBe(403)
  })

  test('a resource without a login is never refused here, and the refusal is not even asked', async () => {
    expect(await loginUseRefusal({ ownerId: 'owner', resourceId: 'public' })).toBeNull()
    expect(vi.mocked(refuseWhileActingAsOn)).not.toHaveBeenCalled()
  })

  test("another account's resource reads as none: the route answers its own 404", async () => {
    expect(await loginUseRefusal({ ownerId: 'owner', resourceId: 'theirs' })).toBeNull()
    expect(await loginUseRefusal({ ownerId: 'owner', resourceId: 'missing' })).toBeNull()
  })

  test('a row the caller already read is used as it is, nothing read again', async () => {
    h.db.calls.length = 0
    expect((await loginUseRefusal({ ownerId: 'owner', resource: { hasLogin: true, credentials: {} } }))?.status).toBe(403)
    expect(await loginUseRefusal({ ownerId: 'owner', resource: { hasLogin: false, credentials: {} } })).toBeNull()
    expect(h.db.calls).toEqual([])
  })

  test('a login carried by the request (Check URL of a resource being added) is refused too; an empty one is not', async () => {
    expect((await loginUseRefusal({ ownerId: 'owner', credentials: { cookie: 'session=fake-typed' } }))?.status).toBe(403)
    expect(await loginUseRefusal({ ownerId: 'owner', credentials: {} })).toBeNull()
    expect(await loginUseRefusal({ ownerId: 'owner', credentials: { cookie: '', headers: [], basic_auth: null } })).toBeNull()
  })

  test('not acting as anyone: nothing refused', async () => {
    h.actingAs = false
    expect(await loginUseRefusal({ ownerId: 'owner', resourceId: 'login' })).toBeNull()
  })
})

describe('loginChangeRefusal', () => {
  test('credential_writes_refused: asked as change_site_logins, whatever the resource holds', async () => {
    const res = await loginChangeRefusal('owner')
    expect(res?.status).toBe(403)
    expect(vi.mocked(refuseWhileActingAsOn)).toHaveBeenCalledWith('owner', 'change_site_logins')
    h.actingAs = false
    expect(await loginChangeRefusal('owner')).toBeNull()
  })
})

describe('auditLoginChange', () => {
  test('audit_has_names_only: the changed field and header names, the person and the account acted as; never a value', async () => {
    const audit: Record<string, unknown>[] = []
    const tx = { auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { audit.push(data); return data } } }
    await auditLoginChange(tx, {
      actor: { actorUserId: 'owner', realActorUserId: 'admin-1' }, ownerId: 'owner', resourceId: 'login',
      before: { cookie: 'session=fake-old', headers: [{ name: 'X-Api-Key', value: 'fake-key-1' }], basic_auth: null },
      after: { cookie: 'session=fake-new', headers: [], basic_auth: { username: 'bob', password: 'fake-pass' } },
    })
    expect(audit).toEqual([{
      actorId: 'admin-1', onBehalfOfUserId: 'owner', action: 'tradecraft.credentials_changed', permission: 'self:tradecraft',
      targetType: 'tradecraft_resource', targetId: 'login', source: 'api',
      before: { hasLogin: true },
      after: { hasLogin: true, changed: ['cookie', 'header:X-Api-Key', 'basic_auth.username', 'basic_auth.password'] },
    }])
    expect(JSON.stringify(audit)).not.toMatch(/fake-/)
  })

  test('the owner\'s own write names the owner; no change writes no row', async () => {
    const audit: Record<string, unknown>[] = []
    const tx = { auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { audit.push(data); return data } } }
    const actor = { actorUserId: 'owner', realActorUserId: null }
    await auditLoginChange(tx, { actor, ownerId: 'owner', resourceId: 'r', before: {}, after: {} })
    expect(audit).toEqual([])
    await auditLoginChange(tx, { actor, ownerId: 'owner', resourceId: 'r', before: { cookie: 'a=1' }, after: {} })
    expect(audit).toEqual([expect.objectContaining({ actorId: 'owner', before: { hasLogin: true }, after: { hasLogin: false, changed: ['cookie'] } })])
    expect(audit[0]).not.toHaveProperty('onBehalfOfUserId')
  })
})
