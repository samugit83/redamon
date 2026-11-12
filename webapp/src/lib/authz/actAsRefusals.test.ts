/**
 * Never while acting as someone (step 3.14, IM-08; feature document §4.7): with
 * RBAC_PERMISSIONS_ENABLED on, an admin acting as an account cannot change its password or reset
 * its credentials, change its sign-in email, delete it, mint an MCP token in its name, or write its
 * agent skills on any path (single create, edit, delete, batch, release, saving a plugin proposal).
 * Each attempt answers 403 `not_while_acting_as` naming the account ("not available while acting as
 * Marco") and writes an `act_as.refused` row, before anything is written. The admin's administration
 * of other accounts, the account's own writes and every write with the switch off are unchanged.
 *
 * Real routes, session helpers, tokens and capability resolution; the database is the in-memory
 * accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', '9'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})

import bcrypt from 'bcryptjs'
import type { AccountDb } from './__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import { getSession } from '@/lib/session'
import { ACTING_AS_ACTIONS, refuseWhileActingAs } from './actAsRefusals'
import { UserSkillError } from '@/lib/userSkills'
import {
  createUserSkill, createUserSkillsBatch, deleteUserSkill, releaseUserSkill, updateUserSkill,
} from '@/lib/userSkillWrites'
import { adoptUserSkillVersion } from '@/lib/plugins/userSkillAdoption'
import { PUT as editUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'
import { PUT as setPassword } from '@/app/api/users/[id]/password/route'
import { POST as resetCredentials } from '@/app/api/users/[id]/reset-credentials/route'
import { POST as mintToken } from '@/app/api/users/[id]/mcp-tokens/route'

const db = () => h.db as AccountDb
const ADMIN_PW = 'admin-one-passphrase'
const ADMIN_HASH = bcrypt.hashSync(ADMIN_PW, 4)

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x', {
    method,
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function as(userId: string, actingAs?: string) {
  h.jar.auth = await createToken(userId, String(db().account(userId)!.role), 0)
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs, 3600, { asv: 0 }) : undefined
}

const refusals = () => db().audit().filter((r) => r.action === 'act_as.refused')

async function expectRefused(res: Response, action: string) {
  expect(res.status).toBe(403)
  expect(await res.json()).toEqual({
    error: expect.stringMatching(/^Not available while acting as Marco: .+ stays with them\./),
    code: 'not_while_acting_as',
    action,
  })
  expect(refusals().at(-1)).toMatchObject({
    action: 'act_as.refused', actorId: 'admin-1', onBehalfOfUserId: 'member-1', targetType: 'user', targetId: 'member-1',
    after: { action },
  })
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin', name: 'Laura', password: ADMIN_HASH },
    // A passwordless managed account: run only through act-as, which step 1.6 lets write its data.
    { id: 'member-1', name: 'Marco', password: '' },
    { id: 'member-2', name: 'Nina' },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('the helper', () => {
  test('refuses only while acting, and only on the account acted as when one is named', async () => {
    await as('admin-1', 'member-1')
    const session = (await getSession())!
    expect(await refuseWhileActingAs({ session, targetUserId: 'member-2' }, 'change_email')).toBeNull()
    expect((await refuseWhileActingAs({ session }, 'change_shares'))?.status).toBe(403)
    expect((await refuseWhileActingAs({ session, targetUserId: 'member-1' }, 'transfer_projects'))?.status).toBe(403)
    await as('admin-1')
    expect(await refuseWhileActingAs({ session: (await getSession())! }, 'change_shares')).toBeNull()
    expect(refusals()).toHaveLength(2)
  })

  test('switch off: never refuses, writes nothing', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-1', 'member-1')
    for (const action of ACTING_AS_ACTIONS) {
      expect(await refuseWhileActingAs({ session: (await getSession())! }, action)).toBeNull()
    }
    expect(refusals()).toEqual([])
  })
})

describe('each never-list action is refused and audited', () => {
  test('changing the password of the account acted as', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await setPassword(req('PUT', { newPassword: 'a-long-new-passphrase-42', reason: 'x' }), params('member-1')), 'change_password')
    expect(db().account('member-1')!.password).toBe('')
  })

  test('resetting its credentials', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await resetCredentials(req('POST', { mode: 'link', reason: 'x' }), params('member-1')), 'change_password')
    expect(db().invites()).toEqual([])
  })

  test('changing its sign-in email; its name stays the admin\'s users:edit to change', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await editUser(req('PUT', { email: 'new@e2e.local' }), params('member-1')), 'change_email')
    expect(db().account('member-1')!.email).toBe('member-1@e2e.local')
    expect((await editUser(req('PUT', { name: 'Marco R.' }), params('member-1'))).status).toBe(200)
  })

  test('deleting its account', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await deleteUser(req('DELETE'), params('member-1')), 'delete_account')
    expect(db().account('member-1')).toBeDefined()
  })

  test('minting an MCP token in its name: refused, as it always was (real-only)', async () => {
    await as('admin-1', 'member-1')
    const res = await mintToken(req('POST', { name: 't', scopes: ['read'] }), params('member-1'))
    expect(res.status).toBe(403)
    expect(db().tokens()).toEqual([])
  })

  test('another account stays the admin\'s to administer while acting', async () => {
    await as('admin-1', 'member-1')
    // An email change takes the admin's own password (step 2.11).
    expect((await editUser(req('PUT', { email: 'nina@e2e.local', stepUpPassword: ADMIN_PW }), params('member-2'))).status).toBe(200)
    expect(refusals()).toEqual([])
  })

  test('switch off: the admin\'s administration as before', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-1', 'member-1')
    expect((await editUser(req('PUT', { email: 'marco@e2e.local', stepUpPassword: ADMIN_PW }), params('member-1'))).status).toBe(200)
    expect(refusals()).toEqual([])
  })
})

describe('writing the agent skills of the account acted as, on every path (the userSkillWrites chokepoint)', () => {
  const ADMIN = { actorId: 'admin-1', onBehalfOf: 'member-1', source: 'ui' as const }
  const writes: Array<[string, () => Promise<unknown>]> = [
    ['single create', () => createUserSkill({ userId: 'member-1', name: 'x', description: null, content: 'x' }, ADMIN)],
    ['batch upload', () => createUserSkillsBatch({ userId: 'member-1', items: [{ name: 'x', content: 'x' }] }, ADMIN)],
    ['edit', () => updateUserSkill({ userId: 'member-1', skillId: 's1', name: 'y' }, ADMIN)],
    ['delete', () => deleteUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)],
    ['release', () => releaseUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)],
    ["saving a plugin's proposal", () => adoptUserSkillVersion({
      changeSetId: 'cs-1', ownerId: 'member-1', actor: ADMIN, name: 'x', description: null, projectId: null,
      enableNew: false, disableSource: false, acknowledgedRiskLines: undefined,
    } as unknown as Parameters<typeof adoptUserSkillVersion>[0])],
  ]

  test.each(writes)('%s: 403 not_while_acting_as, audited, before any transaction', async (_name, write) => {
    await as('admin-1', 'member-1')
    const tx = vi.spyOn(db(), '$transaction')
    const err = await write().catch((e: unknown) => e) as UserSkillError
    expect(err).toBeInstanceOf(UserSkillError)
    expect(err).toMatchObject({ status: 403, code: 'not_while_acting_as', extra: { action: 'write_agent_skills' } })
    expect(err.message).toMatch(/^Not available while acting as Marco: writing their agent skills stays with them\./)
    expect(tx).not.toHaveBeenCalled()
    expect(refusals().at(-1)).toMatchObject({ onBehalfOfUserId: 'member-1', after: { action: 'write_agent_skills' } })
  })

  test('the account\'s own write and the switch off read no session and refuse nothing', async () => {
    await as('admin-1', 'member-1')
    const own = { actorId: 'member-1', source: 'ui' as const }
    const tx = vi.spyOn(db(), '$transaction').mockRejectedValue(new Error('reached the write'))
    await expect(deleteUserSkill({ userId: 'member-1', skillId: 's1' }, own)).rejects.toThrow('reached the write')
    setFlagsForTests({ identity: true, permissions: false })
    await expect(deleteUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)).rejects.toThrow('reached the write')
    expect(tx).toHaveBeenCalledTimes(2)
    expect(refusals()).toEqual([])
  })

  test('an admin not acting (a plugin approval of someone else\'s proposal) is not refused here', async () => {
    await as('admin-1')
    vi.spyOn(db(), '$transaction').mockRejectedValue(new Error('reached the write'))
    await expect(deleteUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)).rejects.toThrow('reached the write')
  })
})
