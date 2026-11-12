/**
 * Every attack-skills route answers a failure it did not expect with its fixed sentence and
 * the cause's code (here the Prisma code of a database that is down), never with the
 * exception's text, which can quote the query and so the skill itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => {
  const dbError = () => Object.assign(
    new Error('Invalid `prisma.userAttackSkill.findMany()` invocation: SELECT "SECRET-SKILL-TEXT"'),
    { name: 'PrismaClientKnownRequestError', code: 'P1001' },
  )
  // Every model, method and raw query throws, the way a client with no database does.
  const down: unknown = new Proxy(function failing() {}, {
    get: () => down,
    apply: () => { throw dbError() },
  })
  return { down }
})

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({ default: h.down }))
vi.mock('@/lib/session', () => ({
  requireUserAccess: async () => null,
  getSession: async () => ({ userId: 'alice', role: 'standard' }),
}))
vi.mock('@/lib/userSkillRouteGuard', () => ({ requireOwnBrowserRequest: async () => ({ userId: 'alice' }) }))
vi.mock('@/lib/plugins/sameOrigin', () => ({ sameOrigin: () => true, crossOriginResponse: () => new Response(null, { status: 403 }) }))

import { GET as listSkills, POST as createSkill } from './route'
import { GET as getSkill, PUT as putSkill, DELETE as deleteSkill } from './[skillId]/route'
import { POST as releaseSkill } from './[skillId]/release/route'
import { GET as checkName, POST as checkNames } from './name-check/route'
import { GET as listAvailable } from './available/route'

const base = 'http://localhost:3000/api/users/alice/attack-skills'
const user = { params: Promise.resolve({ id: 'alice' }) }
const oneSkill = { params: Promise.resolve({ id: 'alice', skillId: 'sk1' }) }
const json = (url: string, method: string, body: unknown) =>
  new NextRequest(url, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })

const CASES: [string, () => Promise<Response>, string][] = [
  ['GET the list', () => listSkills(new NextRequest(base), user), 'Failed to fetch attack skills'],
  ['POST a skill', () => createSkill(json(base, 'POST', { name: 'Flow', content: 'Text' }), user), 'Failed to create attack skill'],
  ['GET one skill', () => getSkill(new NextRequest(`${base}/sk1`), oneSkill), 'Failed to fetch attack skill'],
  ['PUT one skill', () => putSkill(json(`${base}/sk1`, 'PUT', { name: 'Renamed' }), oneSkill), 'Failed to update attack skill'],
  ['DELETE one skill', () => deleteSkill(new NextRequest(`${base}/sk1`, { method: 'DELETE' }), oneSkill), 'Failed to delete attack skill'],
  ['POST release', () => releaseSkill(new NextRequest(`${base}/sk1/release`, { method: 'POST' }), oneSkill), 'Failed to release the skill'],
  ['GET name-check', () => checkName(new NextRequest(`${base}/name-check?name=Flow`), user), 'Failed to check the name'],
  ['POST name-check', () => checkNames(json(`${base}/name-check`, 'POST', { names: ['Flow'] }), user), 'Failed to check the names'],
  ['GET available', () => listAvailable(new NextRequest(`${base}/available`), user), 'Failed to fetch available attack skills'],
]

beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })
afterEach(() => { vi.restoreAllMocks() })

describe('a database that is down', () => {
  test.each(CASES)('%s: 500 with the fixed sentence and the Prisma code, never the query', async (_name, call, error) => {
    const res = await call()
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error, code: 'P1001' })
    expect(text).not.toContain('SECRET-SKILL-TEXT')
    expect(text).not.toContain('SELECT')
  })
})
