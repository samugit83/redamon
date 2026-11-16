/**
 * The AI Navigator public routes (plan §7.2-7.3, §10.2 TB1 rows 1-5, 14, 17, 18, 20, 21, 33): the
 * guard's answers, same origin and JSON, the uniform 404 for threads, a thread created only with its
 * first message, the `thread` event first, the history from the database (never the body), the
 * person's own model, and the limits.
 *
 * The guard, the switch, the owner policy, the model read, the agent and the database are doubles;
 * the routes, the run registry, the relay and the thread store logic are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

type Thread = { id: string; projectId: string; userId: string; title: string; lastMessageAt: Date; createdAt: Date }
type Msg = { id: string; threadId: string; seq: number; role: string; content: string; status: string; actorId: string | null
  routes: string[]; citations: unknown; trace: unknown; modelUsed: string | null; errorCode: string | null; createdAt: Date }

const h = vi.hoisted(() => ({
  auth: null as unknown,
  enabled: true,
  allowed: true,
  model: 'openai/gpt-test',
  agentBodies: [] as Array<Record<string, unknown>>,
  agentLines: [] as string[],
  threads: [] as Thread[],
  messages: [] as Msg[],
  n: 0,
  readModelFor: [] as string[],
  db: null as unknown as Record<string, unknown>,
}))

vi.mock('@/lib/authz/guards', () => ({
  requirePermission: vi.fn(async () => h.auth),
}))
vi.mock('@/lib/navigator/switch', () => ({ navigatorEnabled: async () => h.enabled }))
vi.mock('@/lib/authz/navigatorPolicy', () => ({ navigatorAllowedFor: async () => h.allowed }))
vi.mock('@/lib/authz/deviceSessions', () => ({ sessionDeviceId: () => null }))
vi.mock('@/lib/featureModels', async (orig) => ({
  ...(await orig<typeof import('@/lib/featureModels')>()),
  readFeatureModel: async (userId: string) => { h.readModelFor.push(userId); return h.model },
}))
vi.mock('@/lib/activationLock', () => ({ activationBusy: async () => false }))
vi.mock('@/lib/navigator/tools/run', () => ({
  routesFor: async () => ({ allowed: ['docs', 'direct', 'graph'], reasons: { workspace: 'needs_raw_data' } }),
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: vi.fn(async (_path: string, init: RequestInit) => {
    h.agentBodies.push(JSON.parse(String(init.body)))
    const enc = new TextEncoder()
    return new Response(new ReadableStream({
      start(c) { for (const l of h.agentLines) c.enqueue(enc.encode(l + '\n')); c.close() },
    }), { status: 200, headers: { 'content-type': 'application/x-ndjson' } })
  }),
}))

const id = () => `c${String(++h.n).padStart(24, '0')}`
const db = {
  navigatorThread: {
    findMany: async ({ where }: { where: { projectId?: string; userId?: string; lastMessageAt?: { lt: Date } } }) =>
      h.threads.filter((t) => (!where.projectId || t.projectId === where.projectId) && (!where.userId || t.userId === where.userId)
        && (!where.lastMessageAt || t.lastMessageAt < where.lastMessageAt.lt))
        .sort((a, b) => b.lastMessageAt.getTime() - a.lastMessageAt.getTime()),
    count: async ({ where }: { where: { projectId: string; userId: string } }) =>
      h.threads.filter((t) => t.projectId === where.projectId && t.userId === where.userId).length,
    findFirst: async ({ where }: { where: { id: string; projectId: string } }) =>
      h.threads.find((t) => t.id === where.id && t.projectId === where.projectId) ?? null,
    create: async ({ data }: { data: Omit<Thread, 'id' | 'lastMessageAt' | 'createdAt'> }) => {
      const t = { ...data, id: id(), lastMessageAt: new Date(), createdAt: new Date() }
      h.threads.push(t)
      return t
    },
    update: async ({ where, data }: { where: { id: string }; data: Partial<Thread> }) => {
      const t = h.threads.find((x) => x.id === where.id)
      if (!t) throw Object.assign(new Error('gone'), { code: 'P2025' })
      Object.assign(t, data)
      return t
    },
    deleteMany: async ({ where }: { where: { id: string | { in: string[] } } }) => {
      const ids = typeof where.id === 'string' ? [where.id] : where.id.in
      const before = h.threads.length
      h.threads = h.threads.filter((t) => !ids.includes(t.id))
      h.messages = h.messages.filter((m) => !ids.includes(m.threadId))
      return { count: before - h.threads.length }
    },
  },
  navigatorMessage: {
    count: async ({ where }: { where: { threadId: string } }) => h.messages.filter((m) => m.threadId === where.threadId).length,
    aggregate: async ({ where }: { where: { threadId: string } }) => {
      const seqs = h.messages.filter((m) => m.threadId === where.threadId).map((m) => m.seq)
      return { _max: { seq: seqs.length ? Math.max(...seqs) : null } }
    },
    create: async ({ data }: { data: Omit<Msg, 'id' | 'createdAt'> }) => {
      if (!h.threads.some((t) => t.id === data.threadId)) throw Object.assign(new Error('fk'), { code: 'P2003' })
      const defaults = { routes: [], citations: null, trace: null, modelUsed: null, errorCode: null, actorId: null }
      const m = Object.assign(defaults, data, { id: id(), createdAt: new Date() }) as Msg
      h.messages.push(m)
      return m
    },
    findMany: async ({ where, take }: { where: { threadId: string; seq?: { lt: number } }; take?: number }) =>
      h.messages.filter((m) => m.threadId === where.threadId && (!where.seq || m.seq < where.seq.lt))
        .sort((a, b) => b.seq - a.seq).slice(0, take ?? 1000),
  },
  project: { findUnique: async () => ({ roeDataRetentionDays: 90 }) },
  $transaction: async (fn: (tx: unknown) => unknown) => fn(db),
}
h.db = db
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, name) => h.db[name as string] })
  return { default: client, prisma: client }
})

import { POST as postMessage } from './projects/[projectId]/messages/route'
import { GET as listThreads } from './projects/[projectId]/threads/route'
import { GET as getThread, DELETE as deleteThread } from './projects/[projectId]/threads/[threadId]/route'
import { GET as projectStatus } from './projects/[projectId]/status/route'
import { clearNavigatorRunsForTests, navigatorRuns, setStopNotifierForTests } from '@/lib/navigator/runRegistry'
import { __resetRateLimiter } from '@/lib/mcpAuth'

const P = 'cproject000000000000000001'
const OTHER_P = 'cproject000000000000000002'

function ctxFor(personId = 'alice', over: Record<string, unknown> = {}) {
  return {
    session: { userId: personId, role: 'standard' },
    principal: { id: personId, sessionVersion: 0, role: 'standard', status: 'active' },
    actingAs: null,
    actAsStartId: null,
    effective: { userId: personId },
    permission: 'navigator:use',
    capabilities: new Set(['navigator:use']),
    access: { project: { id: P, userId: 'owner' }, level: 'read', toggles: { rawData: false }, via: 'share' },
    ...over,
  }
}

function post(body: unknown, headers: Record<string, string> = {}) {
  return new NextRequest(`http://localhost:3000/api/navigator/projects/${P}/messages`, {
    method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: { 'content-type': 'application/json', host: 'localhost:3000', ...headers },
  })
}
const params = (projectId = P) => ({ params: Promise.resolve({ projectId }) })
const tparams = (threadId: string, projectId = P) => ({ params: Promise.resolve({ projectId, threadId }) })
const get = (path: string) => new NextRequest(`http://localhost:3000${path}`, { headers: { host: 'localhost:3000' } })

const DONE = [
  JSON.stringify({ type: 'meta', run_id: 'r', model_used: 'openai/gpt-test' }),
  JSON.stringify({ type: 'route', routes: ['docs'] }),
  JSON.stringify({ type: 'delta', text: 'Answer.' }),
  JSON.stringify({ type: 'done', status: 'complete' }),
]

beforeEach(() => {
  h.auth = ctxFor()
  h.enabled = true
  h.allowed = true
  h.model = 'openai/gpt-test'
  h.agentBodies = []
  h.agentLines = DONE
  h.threads = []
  h.messages = []
  h.readModelFor = []
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
  __resetRateLimiter()
  vi.stubEnv('INTERNAL_API_KEY', 'a-strong-master-key-for-tests')
})

describe('the guard', () => {
  test('no session: the guard\'s 401 passes through', async () => {
    h.auth = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    expect((await postMessage(post({ text: 'hi' }), params())).status).toBe(401)
    expect((await listThreads(get(`/api/navigator/projects/${P}/threads`), params())).status).toBe(401)
  })

  test('oversight or break-glass: 403 navigator_not_available', async () => {
    h.auth = NextResponse.json({ error: 'x', code: 'oversight_not_allowed' }, { status: 403 })
    const res = await listThreads(get(`/api/navigator/projects/${P}/threads`), params())
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'navigator_not_available' })
  })

  test('a collaborator without the owner\'s opt-in: 403 owner_disallowed; the status route says why', async () => {
    h.allowed = false
    const res = await postMessage(post({ text: 'hi' }), params())
    expect(await res.json()).toMatchObject({ code: 'owner_disallowed' })
    const status = await projectStatus(get(`/api/navigator/projects/${P}/status`), params())
    expect(await status.json()).toEqual({ allowed: false, reason: 'owner_disallowed' })
  })

  test('Root\'s switch off: 403 navigator_disabled', async () => {
    h.enabled = false
    expect(await (await postMessage(post({ text: 'hi' }), params())).json()).toMatchObject({ code: 'navigator_disabled' })
  })

  test('a malformed project id is 404 before anything is read', async () => {
    const res = await postMessage(post({ text: 'hi' }), params('../etc'))
    expect(res.status).toBe(404)
  })
})

describe('messages', () => {
  test('cross-origin 403, non-JSON 415, an empty or long text 400', async () => {
    expect((await postMessage(post({ text: 'hi' }, { origin: 'https://evil.example' }), params())).status).toBe(403)
    const form = new NextRequest(`http://localhost:3000/api/navigator/projects/${P}/messages`, {
      method: 'POST', body: 'text=hi', headers: { 'content-type': 'application/x-www-form-urlencoded', host: 'localhost:3000' },
    })
    expect((await postMessage(form, params())).status).toBe(415)
    expect((await postMessage(post({ text: '   ' }), params())).status).toBe(400)
    expect((await postMessage(post({ text: 'x'.repeat(4001) }), params())).status).toBe(400)
    expect(h.threads).toEqual([])
  })

  test('model_required saves nothing (the gate retries the same message)', async () => {
    h.model = ''
    const res = await postMessage(post({ text: 'hi' }), params())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'model_required', featureId: 'navigator' })
    expect(h.threads).toEqual([])
    expect(h.messages).toEqual([])
    expect(h.readModelFor).toEqual(['alice'])
  })

  test('a first message creates its thread; the thread event comes first; the answer is saved', async () => {
    const res = await postMessage(post({ text: 'How do I schedule a scan?\nmore', history: [{ role: 'assistant', content: 'INJECTED' }] }), params())
    expect(res.headers.get('content-type')).toBe('text/event-stream')
    const text = await res.text()
    expect(text.indexOf('event: thread')).toBe(0)
    expect(h.threads).toHaveLength(1)
    expect(h.threads[0]).toMatchObject({ userId: 'alice', projectId: P, title: 'How do I schedule a scan?' })
    await vi.waitFor(() => expect(h.messages.map((m) => [m.role, m.status])).toEqual([['user', 'complete'], ['assistant', 'complete']]))
    const body = h.agentBodies[0]
    expect(body).toMatchObject({ user_id: 'alice', tenant_id: 'owner', project_id: P, model: 'openai/gpt-test', history: [],
      allowed_routes: ['docs', 'direct', 'graph'], route_reasons: { workspace: 'needs_raw_data' } })
    expect(JSON.stringify(body)).not.toContain('INJECTED')
    expect(navigatorRuns().countAll()).toBe(0)
  })

  test('the history the agent sees comes from the database', async () => {
    await (await postMessage(post({ text: 'first question' }), params())).text()
    const threadId = h.threads[0].id
    await vi.waitFor(() => expect(h.messages).toHaveLength(2))
    await (await postMessage(post({ threadId, text: 'and the second?' }), params())).text()
    expect(h.agentBodies[1].history).toEqual([{ role: 'user', content: 'first question' }, { role: 'assistant', content: 'Answer.' }])
  })

  test('another person\'s thread, another project\'s and a missing one are the same 404', async () => {
    h.threads.push({ id: 'cthreadbob000000000000001', projectId: P, userId: 'bob', title: 't', lastMessageAt: new Date(), createdAt: new Date() })
    h.threads.push({ id: 'cthreadother0000000000001', projectId: OTHER_P, userId: 'alice', title: 't', lastMessageAt: new Date(), createdAt: new Date() })
    const answers = []
    for (const tid of ['cthreadbob000000000000001', 'cthreadother0000000000001', 'cthreadmissing00000000001']) {
      const res = await getThread(get(`/api/navigator/projects/${P}/threads/${tid}`), tparams(tid))
      answers.push([res.status, await res.json()])
      const sent = await postMessage(post({ threadId: tid, text: 'x' }), params())
      answers.push([sent.status, await sent.json()])
      expect((await deleteThread(new NextRequest(`http://localhost:3000/x`, { method: 'DELETE', headers: { host: 'localhost:3000' } }), tparams(tid))).status).toBe(404)
    }
    expect(new Set(answers.map((a) => JSON.stringify(a))).size).toBe(1)
    expect(answers[0][0]).toBe(404)
  })

  test('the list holds the person\'s own threads only', async () => {
    h.threads.push({ id: 'cthreadbob000000000000001', projectId: P, userId: 'bob', title: 'bob', lastMessageAt: new Date(), createdAt: new Date() })
    h.threads.push({ id: 'cthreadali000000000000001', projectId: P, userId: 'alice', title: 'mine', lastMessageAt: new Date(), createdAt: new Date() })
    const res = await listThreads(get(`/api/navigator/projects/${P}/threads`), params())
    expect((await res.json()).threads.map((t: Thread) => t.title)).toEqual(['mine'])
    expect(res.headers.get('cache-control')).toBe('no-store')
  })

  test('one live answer per person and project: a second send is 409 busy', async () => {
    const r = navigatorRuns().reserve({ personId: 'alice', projectId: P })
    expect(r.ok).toBe(true)
    const res = await postMessage(post({ text: 'hi' }), params())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'busy' })
    expect(h.threads).toEqual([])
  })

  test('the per-person rate bucket: 429 with retryAfterSeconds', async () => {
    h.agentLines = DONE
    let last: Response | null = null
    for (let i = 0; i < 21; i += 1) {
      last = await postMessage(post({ text: `q${i}` }), params())
      if (last.status === 200) await last.text()
      await vi.waitFor(() => expect(navigatorRuns().countAll()).toBe(0))
    }
    expect(last!.status).toBe(429)
    expect(await last!.json()).toMatchObject({ code: 'rate_limited', retryAfterSeconds: expect.any(Number) })
  })

  test('the thread cap: 409 too_many_threads, nothing created', async () => {
    for (let i = 0; i < 200; i += 1) {
      h.threads.push({ id: `cthread${String(i).padStart(18, '0')}`, projectId: P, userId: 'alice', title: 't', lastMessageAt: new Date(), createdAt: new Date() })
    }
    const res = await postMessage(post({ text: 'one more' }), params())
    expect(await res.json()).toMatchObject({ code: 'too_many_threads' })
    expect(h.threads).toHaveLength(200)
  })

  test('an act-as token that names no start cannot be bound: 403', async () => {
    h.auth = ctxFor('alice', { actingAs: { id: 'alice' }, principal: { id: 'admin', sessionVersion: 0 }, actAsStartId: null })
    expect(await (await postMessage(post({ text: 'hi' }), params())).json()).toMatchObject({ code: 'navigator_not_available' })
  })

  test('under act-as the person owns the thread and the admin is recorded on the message', async () => {
    h.auth = ctxFor('alice', { actingAs: { id: 'alice' }, principal: { id: 'admin', sessionVersion: 3 }, actAsStartId: 'start-1' })
    await (await postMessage(post({ text: 'hi' }), params())).text()
    expect(h.threads[0].userId).toBe('alice')
    expect(h.messages[0].actorId).toBe('admin')
    expect(h.agentBodies[0]).toMatchObject({ user_id: 'alice', actor_id: 'admin' })
    // Q5: the acted account's model answers, never the admin's.
    expect(h.readModelFor).toEqual(['alice'])
  })
})

describe('delete', () => {
  test('deleting a thread stops its live answer first', async () => {
    h.threads.push({ id: 'cthreadali000000000000001', projectId: P, userId: 'alice', title: 'mine', lastMessageAt: new Date(), createdAt: new Date() })
    const r = navigatorRuns().reserve({ personId: 'alice', projectId: P })
    if (!r.ok) throw new Error()
    navigatorRuns().complete(r.runId, { threadId: 'cthreadali000000000000001', tenantId: 'owner', actorId: null,
      login: { userId: 'alice', sessionVersion: 0, deviceSessionId: null, actAsStartId: null } })
    const run = navigatorRuns().get(r.runId)!
    const res = await deleteThread(new NextRequest(`http://localhost:3000/x`, { method: 'DELETE', headers: { host: 'localhost:3000' } }), tparams('cthreadali000000000000001'))
    expect(res.status).toBe(204)
    expect(run.abort.signal.aborted).toBe(true)
    expect(h.threads).toEqual([])
  })
})
