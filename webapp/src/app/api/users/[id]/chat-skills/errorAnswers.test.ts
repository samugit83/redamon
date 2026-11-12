/**
 * Every chat-skills route answers a failure it did not expect with its fixed sentence and the
 * cause's code (the Prisma code of a database that is down), never with the exception's text,
 * which can quote the query and so the skill itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => {
  const dbError = () => Object.assign(
    new Error('Invalid `prisma.userChatSkill.create()` invocation: INSERT "SECRET-SKILL-TEXT"'),
    { name: 'PrismaClientKnownRequestError', code: 'P2024' },
  )
  const down: unknown = new Proxy(function failing() {}, {
    get: () => down,
    apply: () => { throw dbError() },
  })
  return { down }
})

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({ default: h.down }))
vi.mock('@/lib/session', () => ({ requireUserAccess: async () => null }))

import { GET as listSkills, POST as createSkill } from './route'
import { GET as getSkill, PUT as putSkill, DELETE as deleteSkill } from './[skillId]/route'

const base = 'http://localhost:3000/api/users/alice/chat-skills'
const user = { params: Promise.resolve({ id: 'alice' }) }
const oneSkill = { params: Promise.resolve({ id: 'alice', skillId: 'cs1' }) }
const json = (url: string, method: string, body: unknown) =>
  new NextRequest(url, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })

const CASES: [string, () => Promise<Response>, string][] = [
  ['GET the list', () => listSkills(new NextRequest(base), user), 'Failed to fetch chat skills'],
  ['POST a skill', () => createSkill(json(base, 'POST', { name: 'Flow', content: 'Text' }), user), 'Failed to create chat skill'],
  ['GET one skill', () => getSkill(new NextRequest(`${base}/cs1`), oneSkill), 'Failed to fetch chat skill'],
  ['PUT one skill', () => putSkill(json(`${base}/cs1`, 'PUT', { description: 'New' }), oneSkill), 'Failed to update chat skill'],
  ['DELETE one skill', () => deleteSkill(new NextRequest(`${base}/cs1`, { method: 'DELETE' }), oneSkill), 'Failed to delete chat skill'],
]

beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })
afterEach(() => { vi.restoreAllMocks() })

describe('a database that is down', () => {
  test.each(CASES)('%s: 500 with the fixed sentence and the Prisma code, never the query', async (_name, call, error) => {
    const res = await call()
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error, code: 'P2024' })
    expect(text).not.toContain('SECRET-SKILL-TEXT')
  })
})

describe('a body that is not JSON', () => {
  test('POST answers the class of the parse failure as its code', async () => {
    const res = await createSkill(new NextRequest(base, { method: 'POST', body: '{not json' }), user)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to create chat skill', code: 'SyntaxError' })
  })
})
