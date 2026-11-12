/**
 * DV-11, master §9.8 (step 2.9): an invite or reset token never reaches a log line or an audit
 * row, and neither does its hash. Every flow that touches one runs here through the real routes,
 * with every console method captured: inviting, resending, cancelling, opening a valid and an
 * unknown link, reading the page state, failed accepts up to the lock, a successful accept, and a
 * database failure while a link is looked up (the error path is where a value most easily leaks
 * into a log).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createHash } from 'node:crypto'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests } from './principal'
import { resetInviteLimitsForTests } from './inviteLimits'
import { newLinkToken } from './invites'
import { POST as invite } from '@/app/api/users/invite/route'
import { POST as resend } from '@/app/api/users/[id]/invite/resend/route'
import { POST as cancel } from '@/app/api/users/[id]/invite/cancel/route'
import { GET as openLink } from '@/app/invite/[token]/route'
import { GET as state } from '@/app/api/invite/state/route'
import { POST as accept } from '@/app/api/invite/accept/route'

const db = () => h.db as AccountDb
const METHODS = ['log', 'info', 'warn', 'error', 'debug'] as const
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
const tokenOf = (link: string) => link.slice(link.lastIndexOf('/') + 1)

function post(body: unknown, cookie?: string): NextRequest {
  return new NextRequest('http://redamon.test/api/x', {
    method: 'POST',
    headers: { host: 'redamon.test', 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  })
}
const params = <T extends string>(key: T, value: string) => ({ params: Promise.resolve({ [key]: value } as Record<T, string>) })

function printable(v: unknown): string {
  if (v instanceof Error) return `${v.name} ${v.message} ${v.stack ?? ''} ${printable((v as { cause?: unknown }).cause)}`
  if (typeof v === 'string') return v
  try {
    return JSON.stringify(v) ?? String(v)
  } catch {
    return String(v)
  }
}

let spies: ReturnType<typeof vi.spyOn>[] = []
function logged(): string {
  return spies.flatMap((s) => s.mock.calls.flat().map(printable)).join('\n')
}

/** Opens the link as a browser would and returns the invite cookie it sets. */
async function cookieFor(token: string): Promise<string> {
  const res = await openLink(new NextRequest(`http://redamon.test/invite/${token}`), params('token', token))
  const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-invite='))!
  return line.split(';')[0]
}

beforeEach(async () => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin', email: 'ada@e2e.local' }])
  db().seedInstance({ inviteTtlHours: 168, publicBaseUrl: 'https://redamon.example.com' })
  setFlagsForTests({ identity: true })
  setNowForTests(() => new Date('2026-11-12T10:00:00Z'))
  clearPrincipalCacheForTests()
  resetInviteLimitsForTests()
  h.jar = { auth: await createToken('admin-1', 'admin') }
  spies = METHODS.map((m) => vi.spyOn(console, m).mockImplementation(() => {}))
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('tokens never logged, never audited', () => {
  test('the token string never reaches a log call or an audit row, nor does its hash', async () => {
    const tokens: string[] = []
    const make = async (name: string) => {
      const res = await invite(post({ name, email: `${name}@e2e.local` }))
      expect(res.status).toBe(201)
      const body = await res.json()
      tokens.push(tokenOf(body.link))
      return body as { id: string; link: string }
    }

    // Invite, resend, cancel.
    const nina = await make('nina')
    const omar = await make('omar')
    const resent = await (await resend(post({}), params('id', omar.id))).json()
    tokens.push(tokenOf(resent.link))
    expect((await cancel(post({}), params('id', omar.id))).status).toBe(200)

    // Open the link, read the page state, fail once, then accept.
    h.jar = {}
    const unknown = newLinkToken()
    tokens.push(unknown)
    await cookieFor(unknown)
    const cookie = await cookieFor(tokenOf(nina.link))
    expect((await state(new NextRequest('http://redamon.test/api/invite/state', { headers: { cookie } }))).status).toBe(200)
    expect((await accept(post({ password: 'short' }, cookie))).status).toBe(400)
    expect((await accept(post({ password: 'violet-harbour-lantern-42' }, cookie))).status).toBe(200)

    // Five failed accepts lock a link.
    h.jar = { auth: await createToken('admin-1', 'admin') }
    const pia = await make('pia')
    h.jar = {}
    const piaCookie = await cookieFor(tokenOf(pia.link))
    for (let i = 0; i < 5; i++) await accept(post({ password: 'short' }, piaCookie))
    expect(db().audit().map((r) => r.action)).toContain('user.invite_locked')

    // The database fails while a link is looked up.
    const broken = newLinkToken()
    tokens.push(broken)
    vi.spyOn(db().userInvite, 'findUnique').mockRejectedValueOnce(
      new Error(`Invalid prisma.userInvite.findUnique() invocation: where { tokenHash: "${sha256(broken)}" }`),
    )
    const failed = await openLink(new NextRequest(`http://redamon.test/invite/${broken}`), params('token', broken))
    expect(failed.status).toBe(500)
    expect(await failed.text()).not.toContain(broken)

    const lines = logged()
    expect(lines).toContain('[audit] user.invite ')
    expect(lines).toContain('[rbac] invite link lookup failed')
    const audit = JSON.stringify(db().audit())
    expect(tokens).toHaveLength(6)
    for (const token of tokens) {
      expect(lines).not.toContain(token)
      expect(lines).not.toContain(sha256(token))
      expect(audit).not.toContain(token)
      expect(audit).not.toContain(sha256(token))
    }
    expect(audit).not.toContain('violet-harbour-lantern-42')
    expect(audit).not.toMatch(/\$2[aby]\$/)
  })
})
