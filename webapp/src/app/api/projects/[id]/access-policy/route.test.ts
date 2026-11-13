/**
 * GET/POST /api/projects/[id]/access-policy (step 5.6, C1; SH-32, OQ-06): the owner, and only the
 * owner, lets collaborators spend the project's credentials. Granting needs the password; the change
 * and its audit row are one transaction; a withdrawal then ends what collaborators still spend there.
 * With write sharing not in force the route does not exist.
 *
 * The guard is doubled with the context each person's access gives (the real requireLevel decides
 * the owner-only rule); the store is the real ownerConsent.ts over a Prisma double whose transaction
 * undoes its writes when the callback throws.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  person: 'owner' as 'owner' | 'coowner' | 'reader',
  policyInForce: true,
  maxLevel: 'write',
  consent: null as { ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null } | null,
  withTable: true,
  audit: [] as Array<Record<string, unknown>>,
  auditFails: false,
  acting: false,
  ended: vi.fn(),
}))

const ACCESS = {
  owner: { level: 'owner', toggles: { rawData: true }, via: 'owner' },
  coowner: { level: 'write', toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: true }, via: 'share' },
  reader: { level: 'read', toggles: { rawData: false }, via: 'share' },
} as const

vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return {
    ...real,
    requirePermission: async (_request: Request, permission: string, opts: { projectId?: string } = {}) => {
      if (h.person === 'reader') return real.forbiddenResponse('project:share')
      return {
        session: { userId: h.person, role: 'standard' }, principal: { id: h.person, role: 'standard' }, actingAs: null,
        effective: { userId: h.person }, permission, capabilities: {},
        access: { project: { id: opts.projectId, userId: 'owner' }, ...ACCESS[h.person] },
      }
    },
  }
})
vi.mock('@/lib/authz/projectShares', () => ({ sharingPolicyForRoutes: async () => (h.policyInForce ? { enabled: true, maxLevel: h.maxLevel } : null) }))
vi.mock('@/lib/authz/stepUp', () => ({
  requireStepUp: async (_request: unknown, password: unknown) =>
    (password === 'right-password' ? null : NextResponse.json({ error: 'Enter your password', code: 'step_up_required' }, { status: 403 })),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAs: async () => (h.acting ? NextResponse.json({ code: 'not_while_acting_as', action: 'change_shares' }, { status: 403 }) : null),
}))
vi.mock('@/lib/authz/ownerCredentials', () => ({ endCollaboratorSpending: (...a: unknown[]) => h.ended(...a) }))

function tables() {
  return {
    projectAccessPolicy: {
      findUnique: async () => (h.consent ? { ...h.consent } : null),
      upsert: async ({ update }: { update: { ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null } }) => {
        h.consent = { ...update }
        return { ...update }
      },
    },
    auditLog: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        if (h.auditFails) throw new Error('audit insert failed')
        h.audit.push(data)
        return data
      },
    },
  }
}
vi.mock('@/lib/prisma', () => ({
  default: new Proxy({}, {
    get: (_t, name) => {
      if (name === '$transaction') {
        return async (fn: (tx: unknown) => Promise<unknown>) => {
          const saved = { consent: h.consent, audit: [...h.audit] }
          const t = tables()
          const tx = h.withTable ? t : { auditLog: t.auditLog }
          try {
            return await fn(tx)
          } catch (err) {
            h.consent = saved.consent
            h.audit = saved.audit
            throw err
          }
        }
      }
      if (name === 'projectAccessPolicy') return h.withTable ? tables().projectAccessPolicy : undefined
      return (tables() as Record<string, unknown>)[name as string]
    },
  }),
}))

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { GET, POST } from './route'

const NOW = new Date('2026-11-13T12:00:00Z')
const params = { params: Promise.resolve({ id: 'P1' }) }
const get = () => GET(new NextRequest('http://localhost:3000/api/projects/P1/access-policy'), params)
const post = (body: unknown, headers: Record<string, string> = {}) => POST(new NextRequest('http://localhost:3000/api/projects/P1/access-policy', {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', ...headers },
  body: JSON.stringify(body),
}), params)

beforeEach(() => {
  h.person = 'owner'
  h.policyInForce = true
  h.maxLevel = 'write'
  h.consent = null
  h.withTable = true
  h.audit = []
  h.auditFails = false
  h.acting = false
  h.ended.mockReset().mockResolvedValue({ collaborators: 1, runsStopped: 1, socketsClosed: 2, scansCancelled: 1, triageStopped: false, failed: [] })
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  setNowForTests(() => NOW)
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('the owner consents', () => {
  test('grant with the password: stored, audited in the same transaction, read back', async () => {
    const res = await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ownerCredentialConsent: true, consentAt: NOW.toISOString(), changed: true })
    expect(h.consent).toEqual({ ownerCredentialConsentAt: NOW, ownerCredentialConsentById: 'owner' })
    expect(h.audit).toEqual([{
      actorId: 'owner', projectId: 'P1', permission: 'project:share', action: 'project.owner_consent.grant',
      targetType: 'project', targetId: 'P1', before: { ownerCredentialConsent: false }, after: { ownerCredentialConsent: true }, source: 'api',
    }])
    expect(await (await get()).json()).toEqual({ ownerCredentialConsent: true, consentAt: NOW.toISOString() })
    expect(h.ended).not.toHaveBeenCalled()
  })

  test('grant without the password or with a wrong one: refused, nothing written', async () => {
    for (const body of [{ ownerCredentialConsent: true }, { ownerCredentialConsent: true, stepUpPassword: 'nope' }]) {
      const res = await post(body)
      expect(res.status).toBe(403)
      expect((await res.json()).code).toBe('step_up_required')
    }
    expect(h.consent).toBeNull()
    expect(h.audit).toEqual([])
  })

  test('the same answer twice changes nothing and writes no second row', async () => {
    await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    const again = await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    expect(await again.json()).toMatchObject({ ownerCredentialConsent: true, changed: false })
    expect(h.audit).toHaveLength(1)
    h.consent = null
    expect(await (await post({ ownerCredentialConsent: false })).json()).toMatchObject({ ownerCredentialConsent: false, changed: false })
    expect(h.audit).toHaveLength(1)
    expect(h.ended).not.toHaveBeenCalled()
  })

  test('no audit row, no change: a failed row rolls the consent back', async () => {
    h.auditFails = true
    const res = await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    expect(res.status).toBe(500)
    expect(h.consent).toBeNull()
    expect(h.audit).toEqual([])
  })

  test('before the consent table exists: 503 consent_unavailable, nothing recorded', async () => {
    h.withTable = false
    const res = await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('consent_unavailable')
    expect(h.audit).toEqual([])
    expect(await (await get()).json()).toEqual({ ownerCredentialConsent: false, consentAt: null })
  })
})

describe('withdrawing the consent', () => {
  test('withdrawing turns the toggles off, stops the collaborators\' runs and closes their sockets: no password asked', async () => {
    h.consent = { ownerCredentialConsentAt: new Date(NOW.getTime() - 3_600_000), ownerCredentialConsentById: 'owner' }
    const res = await post({ ownerCredentialConsent: false })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ownerCredentialConsent: false, consentAt: null, changed: true, ended: { collaborators: 1 } })
    expect(h.consent).toEqual({ ownerCredentialConsentAt: null, ownerCredentialConsentById: null })
    expect(h.audit).toEqual([expect.objectContaining({
      action: 'project.owner_consent.withdraw', before: { ownerCredentialConsent: true }, after: { ownerCredentialConsent: false },
    })])
    expect(h.ended).toHaveBeenCalledWith('P1', 'owner')
  })

  test('the agent down: the withdrawal stands and says which steps failed', async () => {
    h.consent = { ownerCredentialConsentAt: new Date(NOW.getTime() - 3_600_000), ownerCredentialConsentById: 'owner' }
    h.ended.mockResolvedValueOnce({ collaborators: 1, runsStopped: 0, socketsClosed: 0, scansCancelled: 1, triageStopped: false, failed: ['stop_runs', 'close_sockets'] })
    const res = await post({ ownerCredentialConsent: false })
    expect(res.status).toBe(200)
    expect((await res.json()).ended.failed).toEqual(['stop_runs', 'close_sockets'])
    expect(h.consent?.ownerCredentialConsentAt).toBeNull()
  })
})

describe('only the owner', () => {
  test('co-owner cannot consent: 403 naming the permission and the owner level; may read the state', async () => {
    h.person = 'coowner'
    const res = await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:share', level: 'O' })
    expect(await (await post({ ownerCredentialConsent: false })).json()).toMatchObject({ level: 'O' })
    expect(h.audit).toEqual([])
    expect((await get()).status).toBe(200)
  })

  test('a read collaborator: refused by the guard, nothing read', async () => {
    h.person = 'reader'
    expect((await get()).status).toBe(403)
    expect((await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })).status).toBe(403)
    expect(h.audit).toEqual([])
  })

  test('refused while an admin acts as the owner', async () => {
    h.acting = true
    const res = await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('not_while_acting_as')
    expect(h.consent).toBeNull()
  })

  test('same-origin JSON only; the answer must be a boolean', async () => {
    expect((await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' }, { origin: 'https://evil.example' })).status).toBe(403)
    const bad = await post({ ownerCredentialConsent: 'yes', stepUpPassword: 'right-password' })
    expect(bad.status).toBe(400)
    expect(await bad.json()).toMatchObject({ code: 'invalid_field', field: 'ownerCredentialConsent' })
    const form = await POST(new NextRequest('http://localhost:3000/api/projects/P1/access-policy', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'ownerCredentialConsent=true',
    }), params)
    expect(form.status).toBe(415)
    expect(h.audit).toEqual([])
  })
})

describe('with write sharing not in force the route does not exist', () => {
  test.each([
    ['every switch off', {}],
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }],
  ])('%s: 404 for GET and POST, nothing read or written', async (_what, flags) => {
    setFlagsForTests(flags)
    h.consent = { ownerCredentialConsentAt: NOW, ownerCredentialConsentById: 'owner' }
    expect((await get()).status).toBe(404)
    expect((await post({ ownerCredentialConsent: false })).status).toBe(404)
    expect(h.consent.ownerCredentialConsentAt).toEqual(NOW)
    expect(h.audit).toEqual([])
    expect(h.ended).not.toHaveBeenCalled()
  })

  test("sharing not in force by Root's policy, or Root's policy at Read: 404", async () => {
    h.policyInForce = false
    expect((await get()).status).toBe(404)
    expect((await post({ ownerCredentialConsent: true, stepUpPassword: 'right-password' })).status).toBe(404)
    h.policyInForce = true
    h.maxLevel = 'read'
    expect((await get()).status).toBe(404)
    expect((await post({ ownerCredentialConsent: false })).status).toBe(404)
    expect(h.audit).toEqual([])
  })
})
