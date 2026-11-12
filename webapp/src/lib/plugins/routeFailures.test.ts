/**
 * A plugin route that hits an unexpected failure (a database timeout) answers in the
 * platform's own shape, `{error, code}`, with the error's safe code: never Next's empty 500,
 * which no client can read, and never the exception's message, which can quote a query's
 * values. The code (P2024 here) is what tells a pool timeout from a lost database.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const SECRET = 'SELECT value FROM plugin_data WHERE key = target.example'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, resetCommits: false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => {
  const { accountWriteDouble } = await import('@/lib/plugins/__testing__/accountWriteDouble')
  return {
    ...((await orig()) as Record<string, unknown>),
    getSession: async () => ({ userId: 'u1', role: 'standard' }),
    getEffectiveUser: async () => ({ userId: 'u1' }),
    requireAccountWrite: accountWriteDouble(() => ({ session: { userId: 'u1', role: 'standard' }, effective: 'u1' })),
  }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
// For the one case of a reset that commits before the failing read.
vi.mock('@/lib/plugins/overrides', async (orig) => {
  const m = (await orig()) as typeof import('./overrides')
  return {
    ...m,
    reset: async (...a: Parameters<typeof m.reset>) => (h.resetCommits ? { changeSetId: '1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f', revision: 4 } : m.reset(...a)),
  }
})

import { GET as pluginsPage } from '@/app/api/plugins/route'
import { GET as pluginDetail } from '@/app/api/plugins/[pluginId]/route'
import { GET as contributions } from '@/app/api/plugins/contributions/route'
import { GET as llmFeatures } from '@/app/api/plugins/llm-features/route'
import { GET as jobRead } from '@/app/api/plugins/jobs/[jobId]/route'
import { POST as jobCancel } from '@/app/api/plugins/jobs/[jobId]/cancel/route'
import { GET as sessionSkills } from '@/app/api/plugins/[pluginId]/session-skills/route'
import { GET as summary } from '@/app/api/plugins/overrides/summary/route'
import { GET as versions } from '@/app/api/plugins/overrides/versions/route'
import { DELETE as changeSetDelete, GET as changeSetRead } from '@/app/api/plugins/overrides/change-sets/[id]/route'
import { POST as approve } from '@/app/api/plugins/overrides/change-sets/[id]/approve/route'
import { POST as reject } from '@/app/api/plugins/overrides/change-sets/[id]/reject/route'
import { POST as reset } from '@/app/api/plugins/overrides/reset/route'
import { POST as action } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'
import { POST as install } from '@/app/api/plugins/[pluginId]/install/route'
import { GET as logs } from '@/app/api/plugins/[pluginId]/logs/route'
import { LifecycleError } from './lifecycleCommon'
import { lifecycleErrorResponse, pluginRoute } from './lifecycleRoutes'

const APP = 'http://localhost:3000'
// Ids in the shape the routes accept, so the read reaches the database.
const JOB = '0b9a7c1e-4d2f-4a8b-9c3d-5e6f7a8b9c0d'
const CS = '1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f'

function prismaTimeout(): Error {
  return Object.assign(new Error(`Timed out fetching a new connection from the connection pool: ${SECRET}`), {
    name: 'PrismaClientKnownRequestError',
    code: 'P2024',
  })
}

/** Every model method and transaction of the database fails as a pool timeout. */
function failingDb(): Record<string, unknown> {
  const fail = async () => {
    throw prismaTimeout()
  }
  return new Proxy({}, { get: (_t, k) => (String(k).startsWith('$') ? fail : new Proxy({}, { get: () => fail })) }) as Record<string, unknown>
}

const get = (path: string) => new NextRequest(`${APP}${path}`, { method: 'GET', headers: { host: 'localhost:3000' } })
const post = (path: string, body: unknown = {}, method = 'POST') =>
  new NextRequest(`${APP}${path}`, {
    method,
    headers: { host: 'localhost:3000', origin: APP, 'content-type': 'application/json' },
    body: method === 'DELETE' ? undefined : JSON.stringify(body),
  })
const ctx = <T extends Record<string, string>>(params: T) => ({ params: Promise.resolve(params) })

beforeEach(() => {
  h.db = failingDb()
  h.resetCommits = false
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

async function read(res: Response) {
  const text = await res.text()
  return { status: res.status, text, body: JSON.parse(text) as Record<string, unknown> }
}

describe('a route without a catch of its own answers {error, code} on a database failure', () => {
  test.each<[string, () => Promise<Response>, string]>([
    ['GET /api/plugins', () => pluginsPage(new NextRequest('http://localhost/api/plugins')), 'The Plugins page could not be read; see the webapp log.'],
    ['GET /api/plugins/[id]', () => pluginDetail(get('/api/plugins/echo'), ctx({ pluginId: 'echo' })), "The plugin's details could not be read; see the webapp log."],
    ['GET contributions', () => contributions(new NextRequest('http://localhost/api/plugins')), 'The plugin items could not be read; see the webapp log.'],
    ['GET llm-features', () => llmFeatures(new NextRequest('http://localhost/api/plugins')), 'The plugin model features could not be read; see the webapp log.'],
    ['GET a job', () => jobRead(get(`/api/plugins/jobs/${JOB}`), ctx({ jobId: JOB })), 'The job could not be read; see the webapp log.'],
    ['POST cancel', () => jobCancel(post(`/api/plugins/jobs/${JOB}/cancel`), ctx({ jobId: JOB })), 'The job could not be cancelled; see the webapp log.'],
    [
      'GET session-skills',
      () => sessionSkills(get('/api/plugins/echo/session-skills?sessionId=s1&projectId=p1'), ctx({ pluginId: 'echo' })),
      'The skills of this session could not be read; see the webapp log.',
    ],
    ['GET summary', () => summary(get('/api/plugins/overrides/summary?projectId=p1')), 'The plugin skill versions could not be read; see the webapp log.'],
    ['GET versions', () => versions(get('/api/plugins/overrides/versions?point=user_skill.text&group=sk1')), 'The versions could not be read; see the webapp log.'],
    ['GET a change set', () => changeSetRead(get(`/api/plugins/overrides/change-sets/${CS}`), ctx({ id: CS })), 'The proposal could not be read; see the webapp log.'],
    [
      'DELETE a change set',
      () => changeSetDelete(post(`/api/plugins/overrides/change-sets/${CS}`, undefined, 'DELETE'), ctx({ id: CS })),
      'The version could not be deleted; see the webapp log.',
    ],
    ['POST approve', () => approve(post(`/api/plugins/overrides/change-sets/${CS}/approve`), ctx({ id: CS })), 'The proposal could not be approved; see the webapp log.'],
    ['POST reject', () => reject(post(`/api/plugins/overrides/change-sets/${CS}/reject`), ctx({ id: CS })), 'The proposal could not be rejected; see the webapp log.'],
    [
      'POST reset',
      () => reset(post('/api/plugins/overrides/reset', { point: 'skill.text', group: 'sql_injection', scopeType: 'user', scopeOwnerId: 'u1' })),
      'The skill could not be reset; see the webapp log.',
    ],
  ])('%s: 500 with the Prisma code, never its message', async (_name, call, error) => {
    const res = await read(await call())
    expect(res.status).toBe(500)
    expect(res.body).toEqual({ error, code: 'P2024' })
    expect(res.text).not.toContain('target.example')
  })

  test('an action names the step it failed at', async () => {
    const res = await read(await action(post('/api/plugins/echo/actions/run', { params: {} }), ctx({ pluginId: 'echo', actionId: 'run' })))
    expect(res.status).toBe(500)
    expect(res.body).toEqual({
      error: 'The plugin action failed while reading the plugin; the webapp log has the details.',
      code: 'P2024',
      step: 'reading the plugin',
    })
    expect(res.text).not.toContain('target.example')
  })

  test("a lifecycle route whose admin check cannot read the database: 500 JSON, not Next's empty one", async () => {
    const res = await read(await install(post('/api/plugins/echo/install', { version: '1.0.0', acceptedPermissions: [] }), ctx({ pluginId: 'echo' })))
    expect(res).toMatchObject({ status: 500, body: { error: 'The plugin operation failed; see the webapp log.', code: 'P2024' } })
    const logsRes = await read(await logs(get('/api/plugins/echo/logs'), ctx({ pluginId: 'echo' })))
    expect(logsRes).toMatchObject({ status: 500, body: { code: 'P2024' } })
  })
})

test('a reset that took effect before the failing read says committed, so it is not retried as a failure', async () => {
  h.resetCommits = true
  const res = await read(await reset(post('/api/plugins/overrides/reset', { point: 'skill.text', group: 'sql_injection', scopeType: 'user', scopeOwnerId: 'u1' })))
  expect(res).toEqual({
    status: 500,
    text: expect.any(String),
    body: {
      error: 'The skill was reset, but its audit entry could not be written; see the webapp log.',
      code: 'P2024',
      committed: true,
      cleared: true,
      revision: 4,
    },
  })
})

describe('the helpers', () => {
  test('pluginRoute: an error without a code is named by its class; a bare Error is internal_error', async () => {
    class SomethingBroke extends Error {
      name = 'SomethingBroke'
    }
    const named = await read(await pluginRoute('x', 'X failed.', async () => { throw new SomethingBroke(SECRET) })())
    expect(named).toMatchObject({ status: 500, body: { error: 'X failed.', code: 'SomethingBroke' } })
    expect(named.text).not.toContain('target.example')
    const bare = await read(await pluginRoute('x', 'X failed.', async () => { throw new Error(SECRET) })())
    expect(bare.body).toEqual({ error: 'X failed.', code: 'internal_error' })
  })

  test('lifecycleErrorResponse: a 500 carries the safe code; a failure after the commit says committed', async () => {
    expect((await read(lifecycleErrorResponse(prismaTimeout(), 'install echo'))).body).toEqual({
      error: 'The plugin operation failed; see the webapp log.',
      code: 'P2024',
    })
    const after = new LifecycleError(500, 'P2024', 'The install of echo 1.0.0 took effect, but a step after it failed (P2024).', undefined, { committed: true })
    expect(await read(lifecycleErrorResponse(after, 'install echo'))).toMatchObject({
      status: 500,
      body: { code: 'P2024', committed: true, error: expect.stringContaining('took effect') },
    })
  })
})
