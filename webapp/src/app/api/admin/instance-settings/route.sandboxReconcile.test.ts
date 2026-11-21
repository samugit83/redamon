/**
 * A change of Root's sharing policy reaches the Kali sandboxes at once (group 1, S14; first review F1):
 * turned off, or its highest level lowered to Read, every write share counts as Read, so the shared
 * projects leave people's sandbox lists and the running sandboxes that mount them are reconciled right
 * after the change, in the background, with Root as the actor. The RBAC sweep's backstop
 * (lib/sandbox/lifecycle.ts) converges the same within one sweep for any change it misses (a switch
 * rolled back at a restart). An unchanged policy and a refused save reconcile nothing.
 *
 * Same doubles as route.sharingPolicy.test.ts (real session, principal, Root, policy and audit helpers
 * over an in-memory Prisma; the step-up is a double); the lifecycle hook is a double.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/instance-settings/route.sandboxReconcile.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  cookies: new Map<string, string>(),
  accounts: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
  userSettings: new Map<string, Record<string, unknown>>(),
  audit: [] as Record<string, unknown>[],
  failAudit: false,
  orch: vi.fn(),
  fetch: vi.fn(),
  sandbox: [] as unknown[][],
  backstop: vi.fn(),
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (h.cookies.has(name) ? { value: h.cookies.get(name) } : undefined),
    delete: (name: string) => { h.cookies.delete(name) },
  })),
}))

vi.mock('@/lib/prisma', () => {
  const clone = <T,>(v: T): T => structuredClone(v)
  const client = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => clone(h.accounts.get(where.id) ?? null),
      findFirst: async ({ where, orderBy }: { where: { role: string }; orderBy: unknown }) => {
        expect(orderBy).toEqual([{ createdAt: 'asc' }, { id: 'asc' }])
        const admins = [...h.accounts.values()].filter((a) => a.role === where.role)
          .sort((x, y) => (x.createdAt as Date).getTime() - (y.createdAt as Date).getTime() || String(x.id).localeCompare(String(y.id)))
        return admins[0] ? { id: admins[0].id } : null
      },
    },
    instanceSettings: {
      findUnique: async () => clone(h.instance),
      update: async ({ data }: { data: Row }) => {
        h.instance = { ...h.instance!, ...clone(data), updatedAt: new Date() }
        return clone(h.instance)
      },
    },
    userSettings: {
      upsert: async ({ where, update, create }: { where: { userId: string }; update: Row; create: Row }) => {
        const prev = h.userSettings.get(where.userId)
        h.userSettings.set(where.userId, prev ? { ...prev, ...clone(update) } : clone(create))
        return clone(h.userSettings.get(where.userId))
      },
    },
    auditLog: {
      // The legacy-grants cutoff the escape hatch reads.
      findFirst: async ({ where }: { where: { action: string } }) =>
        clone(h.audit.find((r) => r.action === where.action) ?? null),
      create: async ({ data }: { data: Row }) => {
        if (h.failAudit && data.action === 'instance.settings_changed') throw new Error('audit table unavailable')
        h.audit.push(clone(data))
        return data
      },
    },
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
      const snapshot = { instance: clone(h.instance), settings: clone([...h.userSettings]), audit: clone(h.audit) }
      try {
        return await fn(client)
      } catch (err) {
        h.instance = snapshot.instance
        h.userSettings = new Map(snapshot.settings)
        h.audit = snapshot.audit
        throw err
      }
    },
  }
  return { default: client }
})

vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orch(...a) }))
vi.mock('@/lib/authz/stepUp', () => ({
  requireStepUp: async (_req: unknown, password: unknown) => {
    const { NextResponse } = await import('next/server')
    return password === 'right-password'
      ? null
      : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
  },
}))

vi.mock('@/lib/sandbox/lifecycle', async (orig) => ({
  ...(await orig<typeof import('@/lib/sandbox/lifecycle')>()),
  reconcileRunningSandboxes: (...a: unknown[]) => { h.sandbox.push(a); return h.backstop() },
}))
import { PUT } from './route'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { CAPTURE_DEFAULTS } from '@/lib/sharedInstanceSettings'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'

const CUTOFF = new Date('2026-11-11T08:00:00Z')

function account(id: string, role: string, over: Row = {}) {
  h.accounts.set(id, {
    id, email: `${id}@e2e.local`, name: id, role, password: 'hash', createdAt: new Date('2026-01-01T00:00:00Z'),
    legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, ...over,
  })
}

async function signIn(id: string, actAs?: string) {
  const a = h.accounts.get(id)!
  h.cookies.set('redamon-auth', await createToken(id, a.role as string))
  if (actAs) h.cookies.set('redamon-act-as', await createActAsToken(id, actAs))
}

const POLICY = {
  passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12,
  adminIdleMinutes: 60, inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: null,
  impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: true,
}

function instanceRow(over: Row = {}): Row {
  return {
    id: 'instance', rootUserId: null, rootConfirmedAt: null,
    tunnelsEnabled: false, ngrokAuthtoken: 'fake-ngrok-token-1234', chiselServerUrl: 'https://chisel.old.test',
    chiselAuth: 'user:fake-pass-9876', tunnelSourceUserId: 'member-tun',
    ...structuredClone(CAPTURE_DEFAULTS), captureSourceUserId: 'admin-a', updatedById: null, ...POLICY,
    sharingPolicy: {}, ...over,
  }
}

const put = (body: unknown, headers: Record<string, string> = {}) =>
  PUT(new NextRequest('http://redamon.test/api/admin/instance-settings', {
    method: 'PUT',
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }))

beforeEach(() => {
  h.cookies.clear(); h.accounts.clear(); h.userSettings.clear()
  h.audit = [{ action: 'system.rbac_legacy_grants_cutoff', createdAt: CUTOFF }]
  h.failAudit = false
  h.instance = instanceRow({ rootUserId: 'root-1', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  h.orch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  h.fetch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', h.fetch)
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  resetSharedToolsForTests()
  account('root-1', 'admin', { createdAt: new Date('2026-01-01T00:00:00Z') })
  account('admin-a', 'admin', { createdAt: new Date('2026-01-05T00:00:00Z') })
  account('member-tun', 'standard', { legacyGrants: ['tunnels'] })
  h.sandbox = []
  h.backstop.mockReset().mockResolvedValue({ mode: 'per_user', stopped: 1 })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const ROOT_ACTOR = { actorId: 'root-1', onBehalfOfUserId: null, actorEmail: 'root-1@e2e.local' }

describe("a sharing-policy change reconciles the running sandboxes at once", () => {
  test.each([
    ['sharing turned off', { enabled: false }],
    ['the highest level lowered to read', { maxLevel: 'read' }],
  ])('%s: one reconcile of every running sandbox, with Root as the actor', async (_what, patch) => {
    h.instance!.sharingPolicy = { enabled: true, maxLevel: 'write' }
    await signIn('root-1')
    const res = await put({ sharingPolicy: patch, stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    expect(h.instance!.sharingPolicy).toMatchObject(patch)
    expect(h.sandbox).toEqual([[ROOT_ACTOR]])
  })

  test("never awaited: a reconcile still running does not hold Root's answer", async () => {
    h.instance!.sharingPolicy = { enabled: true, maxLevel: 'write' }
    h.backstop.mockImplementation(() => new Promise(() => {}))
    await signIn('root-1')
    expect((await put({ sharingPolicy: { enabled: false }, stepUpPassword: 'right-password' })).status).toBe(200)
    expect(h.sandbox).toHaveLength(1)
  })

  test('an unchanged policy, a refused save and an admin who is not Root reconcile nothing', async () => {
    h.instance!.sharingPolicy = { enabled: true, maxLevel: 'write' }
    await signIn('root-1')
    expect((await put({ sharingPolicy: { enabled: true }, stepUpPassword: 'right-password' })).status).toBe(200)
    expect((await put({ sharingPolicy: { enabled: false }, stepUpPassword: 'wrong' })).status).toBe(403)
    await signIn('admin-a')
    expect((await put({ sharingPolicy: { enabled: false }, stepUpPassword: 'right-password' })).status).toBe(403)
    expect(h.sandbox).toEqual([])
  })
})
