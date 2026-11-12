/**
 * AU-01, AU-08: one actor convention for every audit row. `actorId` is the person
 * signed in (the login cookie), never the account an admin acts as; under act-as that
 * account goes in `onBehalfOfUserId`; `actorEmail` snapshots the actor's address.
 * `lib/auditActor.ts` is the one reader of the real person: the per-feature helpers
 * that used to compare the session with the effective user themselves delegate to it
 * and answer as before.
 *
 * Real login and act-as tokens, the real session helpers; only the cookie store and
 * Prisma are doubled.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/auditConvention.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

let authCookie: string | undefined
let actAsCookie: string | undefined

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && authCookie) return { value: authCookie }
      if (name === 'redamon-act-as' && actAsCookie) return { value: actAsCookie }
      return undefined
    },
  })),
}))

const accounts = new Map<string, string>() // id -> role; absent = deleted
const auditRows: Record<string, unknown>[] = []
vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => {
        const role = accounts.get(where.id)
        return role
          ? { id: where.id, email: `${where.id}@e2e.local`, role, password: 'hash', createdAt: new Date(0), legacyGrants: [] }
          : null
      },
    },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { auditRows.push(data); return data } },
  },
}))

import { createToken, createActAsToken } from '@/lib/auth'
import { getSession, getEffectiveUser } from '@/lib/session'
import { auditActor, auditActorOf } from '@/lib/auditActor'
import { writeUserAudit } from '@/lib/userAudit'
import { realActorUserId } from '@/lib/triageClient'
import { actingAdminId } from '@/lib/roe/actor'
import { actingAsUserId as workspaceActingAs } from '@/lib/workspaceImport/audit'
import { auditActorFor } from '@/lib/userSkillWrites'

async function signIn(id: string, actingAs?: string, mintedBy = id) {
  authCookie = await createToken(id, accounts.get(id) ?? 'standard')
  actAsCookie = actingAs ? await createActAsToken(mintedBy, actingAs) : undefined
}

function requestWithCookies(): NextRequest {
  const cookie = [authCookie && `redamon-auth=${authCookie}`, actAsCookie && `redamon-act-as=${actAsCookie}`]
    .filter(Boolean).join('; ')
  return new NextRequest('http://x/api/users/member-1', { headers: cookie ? { cookie } : {} })
}

beforeEach(() => {
  authCookie = undefined
  actAsCookie = undefined
  auditRows.length = 0
  accounts.clear()
  accounts.set('admin-1', 'admin')
  accounts.set('admin-2', 'admin')
  accounts.set('member-1', 'standard')
  accounts.set('member-2', 'standard')
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

describe('auditActor', () => {
  test('under act-as actorId is the admin and onBehalfOfUserId the target', async () => {
    await signIn('admin-1', 'member-1')
    expect(await auditActor()).toEqual({ actorId: 'admin-1', onBehalfOfUserId: 'member-1', actorEmail: 'admin-1@e2e.local' })
  })

  test('without act-as the actor is the signed-in account and nobody is acted for', async () => {
    await signIn('member-1')
    expect(await auditActor()).toEqual({ actorId: 'member-1', onBehalfOfUserId: null, actorEmail: 'member-1@e2e.local' })
  })

  test('an act-as cookie of a member, or one another admin minted, acts for nobody', async () => {
    await signIn('member-1', 'member-2')
    expect((await auditActor()).onBehalfOfUserId).toBeNull()
    await signIn('admin-1', 'member-1', 'admin-2')
    expect(await auditActor()).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: null })
  })

  test('an act-as target that no longer exists acts for nobody', async () => {
    await signIn('admin-1', 'member-1')
    accounts.delete('member-1')
    expect((await auditActor()).onBehalfOfUserId).toBeNull()
  })

  test('no session: no actor', async () => {
    expect(await auditActor()).toEqual({ actorId: null, onBehalfOfUserId: null, actorEmail: null })
  })

  test('the effective user the caller already resolved is taken as is', async () => {
    await signIn('admin-1', 'member-1')
    const eff = await getEffectiveUser()
    expect(await auditActor(eff)).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'member-1' })
    expect(await auditActor({ userId: 'admin-1' })).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: null })
  })

  test('auditActorOf: the same rule from what a writer already holds', () => {
    expect(auditActorOf({ id: 'a', email: 'a@x' }, 'b')).toEqual({ actorId: 'a', onBehalfOfUserId: 'b', actorEmail: 'a@x' })
    expect(auditActorOf({ id: 'a' }, 'a')).toEqual({ actorId: 'a', onBehalfOfUserId: null, actorEmail: null })
    expect(auditActorOf(null, 'b')).toEqual({ actorId: null, onBehalfOfUserId: null, actorEmail: null })
  })
})

describe('a Phase 1 writer (user administration) under act-as', () => {
  test('the row names the admin, the account acted for in its column and in after, and the admin email', async () => {
    await signIn('admin-1', 'member-1')
    const session = await getSession()
    await writeUserAudit(requestWithCookies(), session!, { action: 'user.update', targetId: 'member-1', after: { name: 'n' } })
    expect(auditRows).toEqual([expect.objectContaining({
      actorId: 'admin-1',
      onBehalfOfUserId: 'member-1',
      actorEmail: 'admin-1@e2e.local',
      after: { name: 'n', actingAsUserId: 'member-1' },
    })])
  })

  test('without act-as the row carries no onBehalfOfUserId and the same after as before', async () => {
    await signIn('member-1')
    const session = await getSession()
    await writeUserAudit(requestWithCookies(), session!, { action: 'user.update', targetId: 'member-1', after: { name: 'n' } })
    expect(auditRows[0]).not.toHaveProperty('onBehalfOfUserId')
    expect(auditRows[0]).toMatchObject({ actorId: 'member-1', actorEmail: 'member-1@e2e.local', after: { name: 'n' } })
  })
})

describe('the per-feature helpers answer as before, through auditActor', () => {
  test('under act-as', async () => {
    await signIn('admin-1', 'member-1')
    const eff = await getEffectiveUser()
    expect(await realActorUserId()).toBe('admin-1')
    expect(await actingAdminId(eff!)).toBe('admin-1')
    expect(await workspaceActingAs()).toBe('member-1')
    expect(auditActorFor('admin-1', 'member-1')).toEqual({ actorId: 'admin-1', onBehalfOf: 'member-1', source: 'ui' })
  })

  test('without act-as', async () => {
    await signIn('member-1')
    const eff = await getEffectiveUser()
    expect(await realActorUserId()).toBe('member-1')
    expect(await actingAdminId(eff!)).toBeNull()
    expect(await workspaceActingAs()).toBeUndefined()
    expect(auditActorFor('member-1', 'member-1')).toEqual({ actorId: 'member-1', source: 'ui' })
    expect(auditActorFor(null, 'member-1', 'api')).toEqual({ actorId: null, source: 'system' })
  })

  // A helper that compares the session with the effective user by itself is a second
  // convention waiting to drift; each one reads the real person through lib/auditActor.
  test.each([
    'lib/triageClient.ts',
    'lib/roe/actor.ts',
    'lib/workspaceImport/audit.ts',
    'lib/plugins/actions.ts',
    'lib/userSkillWrites.ts',
    'app/api/plugins/overrides/change-sets/[id]/route.ts',
    'app/api/plugins/overrides/change-sets/[id]/approve/route.ts',
    'app/api/plugins/overrides/change-sets/[id]/reject/route.ts',
    'app/api/users/[id]/attack-skills/route.ts',
    'app/api/users/[id]/attack-skills/[skillId]/route.ts',
    'app/api/users/[id]/attack-skills/import-community/route.ts',
    'app/api/users/[id]/attack-skills/batch/route.ts',
    'app/api/users/[id]/attack-skills/generate-metadata/route.ts',
  ])('%s reads the real person through lib/auditActor', (file) => {
    const src = readFileSync(path.resolve(__dirname, '../..', file), 'utf8')
    expect(src).toMatch(/from '@\/lib\/auditActor'/)
    expect(src).not.toMatch(/session\??\.userId\s*!==\s*eff/)
    expect(src).not.toMatch(/auditActorFor\(\s*(session\??\.|\(await getSession)/)
  })
})
