/**
 * Integration tests for /api/users/[id] GET + PUT.
 *
 * Run: npx vitest run "src/app/api/users/[id]/route.test.ts"
 *
 * Focus: the per-user remembered-model defaults (defaultAgentModel /
 * defaultAiPipelineModel) added for the project model-gate feature — that GET
 * returns them, PUT persists them, the typeof-string guard holds, and a
 * standard user can update their OWN defaults without admin rights.
 *
 * @/lib/prisma and @/lib/session are mocked so handlers run without a DB or
 * a real auth cookie.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockDelete = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()
const mockProjectFindMany = vi.fn()
const mockPurge = vi.fn()
const mockQueryRaw = vi.fn()
const mockCount = vi.fn()
const mockExecuteRaw = vi.fn()
const mockTransaction = vi.fn()
const mockProjectDelete = vi.fn()

vi.mock('@/lib/prisma', () => {
  const db: Record<string, unknown> = {
    user: {
      findUnique: (...args: unknown[]) => mockFindUnique(...args),
      update: (...args: unknown[]) => mockUpdate(...args),
      delete: (...args: unknown[]) => mockDelete(...args),
      count: (...args: unknown[]) => mockCount(...args),
    },
    capturedHttpTransaction: { findMany: vi.fn().mockResolvedValue([]) },
    project: {
      findMany: (...args: unknown[]) => mockProjectFindMany(...args),
      delete: (...args: unknown[]) => mockProjectDelete(...args),
    },
    // The rest of what the project teardown (lib/projectTeardown.ts) reads or writes.
    jobQueue: { updateMany: vi.fn().mockResolvedValue({ count: 0 }) },
    conversation: { findMany: vi.fn().mockResolvedValue([]) },
    engagementAuthorization: { count: vi.fn().mockResolvedValue(0) },
    $queryRaw: (...args: unknown[]) => mockQueryRaw(...args),
    $executeRaw: (...args: unknown[]) => mockExecuteRaw(...args),
  }
  // An interactive transaction runs its callback on the same delegates.
  db.$transaction = (fn: (tx: unknown) => Promise<unknown>) => { mockTransaction(); return fn(db) }
  return { default: db }
})

vi.mock('@/lib/workspacePurge', () => ({
  purgeProjectWorkspace: (...args: unknown[]) => mockPurge(...args),
}))
// The teardown's other external boundaries: no network in a unit test.
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: vi.fn().mockResolvedValue({ ok: true, json: async () => ({ deleted: [], runs: [] }) }),
}))
vi.mock('@/lib/agentFetch', async () => ({
  ...(await vi.importActual<typeof import('@/lib/agentFetch')>('@/lib/agentFetch')),
  agentFetch: vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) }),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))

vi.mock('@/lib/session', () => ({
  getSession: (...args: unknown[]) => mockGetSession(...args),
  isInternalRequest: (...args: unknown[]) => mockIsInternal(...args),
}))

import bcrypt from 'bcryptjs'
import { __resetThrottle } from '@/lib/loginThrottle'
import { GET, PUT, DELETE } from './route'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(userId = 'user-1', role: 'admin' | 'standard' = 'standard') {
  return { userId, role }
}

function makeParams(id: string) {
  return { params: Promise.resolve({ id }) }
}

function getReq() {
  return new Request('http://localhost/api/users/user-1') as never
}

function putReq(body: unknown) {
  return new Request('http://localhost/api/users/user-1', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

beforeEach(() => {
  mockFindUnique.mockReset()
  mockUpdate.mockReset()
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
  mockIsInternal.mockReturnValue(false)
  mockProjectFindMany.mockReset()
  mockProjectFindMany.mockResolvedValue([])
  mockProjectDelete.mockReset()
  mockProjectDelete.mockResolvedValue({})
  mockPurge.mockReset()
  mockPurge.mockResolvedValue(undefined)
  mockQueryRaw.mockReset()
  mockQueryRaw.mockResolvedValue([])
  mockCount.mockReset()
  mockExecuteRaw.mockReset()
  mockExecuteRaw.mockResolvedValue(1)
  mockTransaction.mockReset()
  __resetThrottle()
})

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

describe('GET /api/users/[id]', () => {
  test('401 when no session (not internal)', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(401)
  })

  test('403 when a standard user requests another user', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await GET(getReq(), makeParams('user-2'))
    expect(res.status).toBe(403)
  })

  test('returns the user including the new default-model fields (self)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({
      id: 'user-1',
      name: 'Sam',
      email: 's@example.com',
      role: 'standard',
      defaultAgentModel: 'deepseek/deepseek-chat',
      defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      projects: [],
    })
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect(body.defaultAiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('each project names its target from its scope, a batch included', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({ id: 'user-1', projects: [
      { id: 'p1', name: 'Batch', targetDomain: '', ipMode: false, domainBatchMode: true,
        domainBatchHosts: ['www.acme.co.uk', 'shop.acme.co.uk'], subdomainList: [], targetIps: [] },
      { id: 'p2', name: 'Single', targetDomain: 'api.example.com', ipMode: false, domainBatchMode: false,
        domainBatchHosts: [], subdomainList: [], targetIps: [] },
    ] })
    const body = await (await GET(getReq(), makeParams('user-1'))).json()
    expect(body.projects.map((p: { targetLabel: string }) => p.targetLabel)).toEqual(
      ['acme.co.uk: www, shop (listed)', 'api.example.com'])
    // The scope columns are read for the label, not passed through.
    expect(body.projects[0]).not.toHaveProperty('domainBatchHosts')
  })

  test('select clause requests the new default-model fields', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({ id: 'user-1', projects: [] })
    await GET(getReq(), makeParams('user-1'))
    const select = mockFindUnique.mock.calls[0][0].select
    expect(select.defaultAgentModel).toBe(true)
    expect(select.defaultAiPipelineModel).toBe(true)
  })

  test('internal request bypasses session checks', async () => {
    mockIsInternal.mockReturnValue(true)
    mockFindUnique.mockResolvedValue({ id: 'user-9', defaultAgentModel: null, projects: [] })
    const res = await GET(getReq(), makeParams('user-9'))
    expect(res.status).toBe(200)
    expect(mockGetSession).not.toHaveBeenCalled()
  })

  test('404 when user not found', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(404)
  })

  test('500 when prisma throws', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockRejectedValue(new Error('db down'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })

  test('the 500 names the Prisma code, never the message', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET(getReq(), makeParams('user-1'))
    expect(await res.json()).toEqual({ error: 'Failed to fetch user', code: 'P1001' })
    errSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

describe('PUT /api/users/[id]', () => {
  test('401 when no session', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(401)
  })

  test('403 when a standard user updates another user', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-2'))
    expect(res.status).toBe(403)
  })

  test('standard user persists their OWN default models (no admin needed)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
      id: 'user-1',
      ...data,
    }))
    const res = await PUT(
      putReq({
        defaultAgentModel: 'deepseek/deepseek-chat',
        defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      }),
      makeParams('user-1'),
    )
    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect(data.defaultAiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('only the provided default field is written (partial update)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    await PUT(putReq({ defaultAgentModel: 'deepseek/deepseek-chat' }), makeParams('user-1'))
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect('defaultAiPipelineModel' in data).toBe(false)
  })

  test('non-string default values are ignored (typeof guard)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    // numbers / objects must not reach the DB write
    await PUT(
      putReq({ defaultAgentModel: 123, defaultAiPipelineModel: { nope: true } }),
      makeParams('user-1'),
    )
    const data = mockUpdate.mock.calls[0][0].data
    expect('defaultAgentModel' in data).toBe(false)
    expect('defaultAiPipelineModel' in data).toBe(false)
  })

  test('the new default fields are returned in the select clause', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockResolvedValue({ id: 'user-1' })
    await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    const select = mockUpdate.mock.calls[0][0].select
    expect(select.defaultAgentModel).toBe(true)
    expect(select.defaultAiPipelineModel).toBe(true)
  })

  test('updating name/email still works alongside the new fields', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    await PUT(
      putReq({ name: 'New Name', defaultAgentModel: 'deepseek/deepseek-chat' }),
      makeParams('user-1'),
    )
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.name).toBe('New Name')
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
  })

  test('404 (P2025) when user not found', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(Object.assign(new Error('not found'), { code: 'P2025' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(404)
    errSpy.mockRestore()
  })

  test('500 on other prisma errors', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(new Error('write failed'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

describe('DELETE /api/users/[id]', () => {
  const delReq = () => new Request('http://localhost/api/users/user-2', { method: 'DELETE' }) as never

  test('a cascade the database refused names its code, never its message', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockDelete.mockRejectedValue(Object.assign(new Error('Foreign key constraint failed on the field: `user_id`'), { code: 'P2003' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete user', code: 'P2003' })
    errSpy.mockRestore()
  })

  test("deleting a user purges each of their projects' workspaces, after the delete", async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockProjectFindMany.mockResolvedValue([{ id: 'proj-a', userId: 'user-2' }, { id: 'proj-b', userId: 'user-2' }])
    const order: string[] = []
    mockProjectDelete.mockImplementation(async ({ where }: { where: { id: string } }) => { order.push(`project-delete ${where.id}`) })
    mockDelete.mockImplementation(async () => { order.push('delete') })
    mockPurge.mockImplementation(async (pid: string) => { order.push(`purge ${pid}`) })
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(200)
    expect(mockProjectFindMany).toHaveBeenCalledWith({
      where: { userId: 'user-2' }, select: { id: true, userId: true }, orderBy: { createdAt: 'asc' },
    })
    // The agent refuses a purge while the web app still answers for the project:
    // each project's teardown purges after that project's row is gone (HD-11).
    expect(order).toEqual(['project-delete proj-a', 'purge proj-a', 'project-delete proj-b', 'purge proj-b', 'delete'])
  })

  test('a failed purge never fails the user delete', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockProjectFindMany.mockResolvedValue([{ id: 'proj-a', userId: 'user-2' }])
    mockProjectDelete.mockResolvedValue({ id: 'proj-a' })
    mockDelete.mockResolvedValue({})
    mockPurge.mockRejectedValue(new Error('agent down'))
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(200)
  })

  test('a user already gone is still a 404', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockDelete.mockRejectedValue(Object.assign(new Error('Record to delete does not exist.'), { code: 'P2025' }))
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(404)
  })
})


describe('PUT /api/users/[id]: Agent in the Loop is never a default model', () => {
  test.each([
    [{ defaultAgentModel: 'loop/mcp', defaultAiPipelineModel: 'gpt-5' }],
    [{ defaultAiPipelineModel: 'loop/mcp' }],
  ])('%j -> 400, nothing written', async (body) => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    const res = await PUT(putReq(body), makeParams('user-1'))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'Agent in the Loop cannot be a default model; pick it per project.',
      code: 'loop_model_not_allowed',
    })
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('PUT /api/users/[id]: email edit lowercased and collision 409 (NF-09)', () => {
  beforeEach(() => {
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
  })

  test('the new email is stored lowercased', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    const res = await PUT(putReq({ email: 'Sam.New@Example.TEST' }), makeParams('user-1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.email).toBe('sam.new@example.test')
  })

  test('an email another account holds in any case -> 409 email_taken, nothing written', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockQueryRaw.mockResolvedValue([{ id: 'user-2' }])
    const res = await PUT(putReq({ email: 'Admin@x.test' }), makeParams('user-1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'A user with this email already exists', code: 'email_taken' })
    expect(mockUpdate).not.toHaveBeenCalled()
    const [strings, ...values] = mockQueryRaw.mock.calls[0] as [string[], ...unknown[]]
    expect(strings.join('$')).toMatch(/lower\(email\)\s*=\s*lower\(\$\)/)
    expect(values).toEqual(['admin@x.test'])
  })

  test('the account recasing its own email is not a collision', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockQueryRaw.mockResolvedValue([{ id: 'user-1' }])
    const res = await PUT(putReq({ email: 'SAM@x.test' }), makeParams('user-1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.email).toBe('sam@x.test')
  })

  test('an admin editing another account checks against everyone but that account', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockQueryRaw.mockResolvedValue([{ id: 'user-2' }])
    const res = await PUT(putReq({ email: 'member@x.test' }), makeParams('user-2'))
    expect(res.status).toBe(200)
  })

  test('the unique index still answers a race with 409 email_taken', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(Object.assign(new Error('Unique constraint failed'), { code: 'P2002' }))
    const res = await PUT(putReq({ email: 'x@x.test' }), makeParams('user-1'))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('email_taken')
  })

  test('no email in the body: no lookup', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    await PUT(putReq({ name: 'Only Name' }), makeParams('user-1'))
    expect(mockQueryRaw).not.toHaveBeenCalled()
  })

  test('a refused caller reads nothing', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await PUT(putReq({ email: 'x@x.test' }), makeParams('user-2'))
    expect(res.status).toBe(403)
    expect(mockQueryRaw).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Admin-on-admin guards (HD-09) and step-up (ID-25)
// ---------------------------------------------------------------------------

describe('the last admin and admin-on-admin step-up', () => {
  type Row = { id: string; role: string; password: string }
  const table = new Map<string, Row>()
  const PW = { 'admin-1': 'admin-one-passphrase', 'admin-2': 'admin-two-passphrase' } as Record<string, string>
  const hash = (pw: string) => bcrypt.hashSync(pw, 4)
  const order: string[] = []

  function users(rows: Row[]) {
    table.clear()
    for (const r of rows) table.set(r.id, { ...r })
  }
  const admin = (id: string, withPassword = true): Row => ({ id, role: 'admin', password: withPassword ? hash(PW[id] ?? 'x') : '' })
  const member = (id: string): Row => ({ id, role: 'standard', password: hash('member-passphrase') })
  const delReq = (body?: unknown) => new Request('http://localhost/api/users/x', {
    method: 'DELETE',
    ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  }) as never

  beforeEach(() => {
    order.length = 0
    mockFindUnique.mockImplementation(async ({ where }: { where: { id: string } }) => {
      order.push('read')
      const r = table.get(where.id)
      return r ? { ...r } : null
    })
    mockCount.mockImplementation(async ({ where }: { where: { role: string; id: { not: string }; password: { not: string } } }) => {
      order.push('count')
      return [...table.values()].filter(r =>
        r.role === where.role && r.id !== where.id.not && r.password !== where.password.not).length
    })
    mockUpdate.mockImplementation(async ({ where, data }: { where: { id: string }; data: Partial<Row> }) => {
      order.push('update')
      const r = table.get(where.id)
      if (!r) throw Object.assign(new Error('missing'), { code: 'P2025' })
      Object.assign(r, data)
      return { id: r.id, role: r.role }
    })
    mockDelete.mockReset()
    mockDelete.mockImplementation(async ({ where }: { where: { id: string } }) => {
      order.push('delete')
      if (!table.delete(where.id)) throw Object.assign(new Error('missing'), { code: 'P2025' })
      return {}
    })
    mockExecuteRaw.mockImplementation(async () => { order.push('lock'); return 1 })
  })

  test('demoting the last admin is refused', async () => {
    // admin-1 lost its role a moment ago (another request); its session was read before.
    users([member('admin-1'), admin('admin-2'), admin('managed-admin', false)])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    table.get('admin-1')!.password = hash(PW['admin-1'])
    const res = await PUT(putReq({ role: 'standard', stepUpPassword: PW['admin-1'] }), makeParams('admin-2'))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({
      error: 'This is the last admin with a password: promote another account first.', code: 'last_admin',
    })
    expect(table.get('admin-2')!.role).toBe('admin')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('self-demotion of the last admin is refused', async () => {
    users([admin('admin-1'), member('member-1')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const res = await PUT(putReq({ role: 'standard' }), makeParams('admin-1'))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('last_admin')
    expect(table.get('admin-1')!.role).toBe('admin')
  })

  test('self-demotion while another admin with a password remains is allowed, with no step-up', async () => {
    users([admin('admin-1'), admin('admin-2')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const res = await PUT(putReq({ role: 'standard' }), makeParams('admin-1'))
    expect(res.status).toBe(200)
    expect(table.get('admin-1')!.role).toBe('standard')
  })

  test('a passwordless admin does not count as the remaining admin', async () => {
    users([admin('admin-1'), admin('managed-admin', false)])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    expect((await PUT(putReq({ role: 'standard' }), makeParams('admin-1'))).status).toBe(409)
  })

  test('the check and the write run in one transaction holding the admin-set lock', async () => {
    users([admin('admin-1'), admin('admin-2')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    await PUT(putReq({ role: 'standard' }), makeParams('admin-1'))
    expect(mockTransaction).toHaveBeenCalledOnce()
    const [strings, ...values] = mockExecuteRaw.mock.calls[0] as [string[], ...unknown[]]
    expect(strings.join('?')).toBe('SELECT pg_advisory_xact_lock(hashtext(?))')
    expect(values).toEqual(['rbac.admin_set'])
    // Lock first, then the target and the count read under it, then the write.
    expect(order).toEqual(['lock', 'read', 'count', 'update'])
  })

  test('demoting another admin needs step-up', async () => {
    users([admin('admin-1'), admin('admin-2')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))

    const missing = await PUT(putReq({ role: 'standard' }), makeParams('admin-2'))
    expect(missing.status).toBe(403)
    expect((await missing.json()).code).toBe('step_up_required')

    const wrong = await PUT(putReq({ role: 'standard', stepUpPassword: PW['admin-2'] }), makeParams('admin-2'))
    expect(wrong.status).toBe(403)
    expect((await wrong.json()).code).toBe('step_up_failed')
    expect(table.get('admin-2')!.role).toBe('admin')
    expect(mockUpdate).not.toHaveBeenCalled()

    const ok = await PUT(putReq({ role: 'standard', stepUpPassword: PW['admin-1'] }), makeParams('admin-2'))
    expect(ok.status).toBe(200)
    expect(table.get('admin-2')!.role).toBe('standard')
  })

  test('demoting a member needs no step-up', async () => {
    users([admin('admin-1'), member('member-1')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const res = await PUT(putReq({ role: 'standard' }), makeParams('member-1'))
    expect(res.status).toBe(200)
  })

  test('a member still cannot change a role', async () => {
    users([admin('admin-1'), member('member-1')])
    mockGetSession.mockResolvedValue(makeSession('member-1', 'standard'))
    expect((await PUT(putReq({ role: 'standard' }), makeParams('member-1'))).status).toBe(403)
    expect(mockTransaction).not.toHaveBeenCalled()
  })

  test('deleting another admin leaves the deleter', async () => {
    users([admin('admin-1'), admin('admin-2')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const res = await DELETE(delReq({ stepUpPassword: PW['admin-1'] }), makeParams('admin-2'))
    expect(res.status).toBe(200)
    expect(table.has('admin-2')).toBe(false)
    expect(table.get('admin-1')!.role).toBe('admin')
    expect(order).toContain('lock')
  })

  test('deleting another admin needs step-up', async () => {
    users([admin('admin-1'), admin('admin-2')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const missing = await DELETE(delReq(), makeParams('admin-2'))
    expect(missing.status).toBe(403)
    expect((await missing.json()).code).toBe('step_up_required')
    const wrong = await DELETE(delReq({ stepUpPassword: 'guess-guess-guess' }), makeParams('admin-2'))
    expect((await wrong.json()).code).toBe('step_up_failed')
    expect(table.has('admin-2')).toBe(true)
    expect(mockProjectFindMany).not.toHaveBeenCalled()
  })

  test('deleting an admin while the deleter lost its role meanwhile keeps the last admin', async () => {
    users([member('admin-1'), admin('admin-2')])
    table.get('admin-1')!.password = hash(PW['admin-1'])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const res = await DELETE(delReq({ stepUpPassword: PW['admin-1'] }), makeParams('admin-2'))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('last_admin')
    expect(table.has('admin-2')).toBe(true)
  })

  test('deleting a member needs no step-up and takes no lock', async () => {
    users([admin('admin-1'), member('member-1')])
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    const res = await DELETE(delReq(), makeParams('member-1'))
    expect(res.status).toBe(200)
    expect(table.has('member-1')).toBe(false)
    expect(mockExecuteRaw).not.toHaveBeenCalled()
  })
})
