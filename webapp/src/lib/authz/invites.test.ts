/**
 * Invite and reset links (step 2.9, ID-14, DV-11): 32 random bytes shown once, stored as their
 * SHA-256 only; a new link cancels the account's earlier open link of the same kind; the expiry
 * comes from the instance settings (`inviteTtlHours` / `resetTtlHours`); the link is built from
 * `publicBaseUrl` (else the deploy's public origin, else localhost with a warning), never from
 * a request's Host. A link is usable once, before it expires, while nobody cancelled it, and
 * while its account is still in the state the link was made for.
 *
 * The database is the in-memory accountDb (transactions roll back); the clock is injected.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { setNowForTests } from './clock'
import { createToken } from '@/lib/auth'
import {
  INVITE_COOKIE_MAX_AGE,
  createLink,
  findLinkById,
  findLinkByToken,
  hashLinkToken,
  newLinkToken,
  readInviteCookie,
  resolveLinkBase,
  signInviteCookie,
} from './invites'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
let clock = T0
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
const tokenOf = (link: string) => link.slice(link.lastIndexOf('/') + 1)

async function link(userId: string, kind: 'invite' | 'reset' = 'invite') {
  return db().$transaction((tx) => createLink(tx as never, { userId, kind, createdById: 'admin-1' }))
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin' },
    { id: 'invited-1', status: 'invited', password: '' },
    { id: 'member-1' },
  ])
  db().seedInstance({ inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: 'https://redamon.example.com' })
  clock = T0
  setNowForTests(() => clock)
  vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')
  vi.stubEnv('MCP_ALLOWED_ORIGIN', '')
})
afterEach(() => {
  setNowForTests(null)
  vi.unstubAllEnvs()
  vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
})

describe('the token', () => {
  test('token stored hashed, shown once', async () => {
    const made = await link('invited-1')
    const token = tokenOf(made.link)
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/) // 32 bytes, base64url, no padding
    const [row] = db().invites()
    expect(row.tokenHash).toBe(sha256(token))
    expect(JSON.stringify(db().invites())).not.toContain(token)
    expect(JSON.stringify(db().audit())).not.toContain(token)
    // Reading it back gives the account and the link's state, never the token.
    const found = await findLinkByToken(token)
    expect(found).toMatchObject({ id: row.id, kind: 'invite', userId: 'invited-1' })
    expect(JSON.stringify(found)).not.toContain(token)
  })

  test('each link is new: 32 random bytes every time', () => {
    const seen = new Set(Array.from({ length: 50 }, () => newLinkToken()))
    expect(seen.size).toBe(50)
    expect(hashLinkToken('abc')).toBe(sha256('abc'))
  })
})

describe('one open link per account and kind', () => {
  test('resend cancels the old link', async () => {
    const first = await link('invited-1')
    clock = new Date(T0.getTime() + 60_000)
    const second = await link('invited-1')
    expect(second.cancelledLinks).toBe(1)
    expect(await findLinkByToken(tokenOf(first.link))).toBeNull()
    expect(await findLinkByToken(tokenOf(second.link))).not.toBeNull()
    const rows = db().invites()
    expect(rows.find((r) => r.id === first.linkId)!.cancelledAt).toEqual(clock)
    expect(rows.find((r) => r.id === second.linkId)!.cancelledAt).toBeNull()
  })

  test('a link of the other kind, or of another account, stays open', async () => {
    const reset = await link('member-1', 'reset')
    db().seedUsers([{ id: 'invited-2', status: 'invited', password: '' }])
    const other = await link('invited-2')
    await link('invited-1')
    expect(await findLinkByToken(tokenOf(reset.link))).not.toBeNull()
    expect(await findLinkByToken(tokenOf(other.link))).not.toBeNull()
  })
})

describe('the expiry', () => {
  test('an invite lives inviteTtlHours, a reset resetTtlHours', async () => {
    db().seedInstance({ inviteTtlHours: 48, resetTtlHours: 2, publicBaseUrl: null })
    expect((await link('invited-1')).expiresAt).toEqual(new Date(T0.getTime() + 48 * 3600_000))
    expect((await link('member-1', 'reset')).expiresAt).toEqual(new Date(T0.getTime() + 2 * 3600_000))
  })

  test('no instance row: the schema defaults (168 h, 4 h)', async () => {
    db().seedInstance(null)
    expect((await link('invited-1')).expiresAt).toEqual(new Date(T0.getTime() + 168 * 3600_000))
    expect((await link('member-1', 'reset')).expiresAt).toEqual(new Date(T0.getTime() + 4 * 3600_000))
  })

  test('the row records who made it and why', async () => {
    await db().$transaction((tx) => createLink(tx as never, { userId: 'member-1', kind: 'reset', createdById: 'admin-1', reason: 'lost laptop' }))
    expect(db().invites()[0]).toMatchObject({ userId: 'member-1', kind: 'reset', createdById: 'admin-1', reason: 'lost laptop', usedAt: null })
  })
})

describe('what makes a link invalid', () => {
  test('expired, used, cancelled → invalid', async () => {
    const made = await link('invited-1')
    const token = tokenOf(made.link)
    clock = new Date(made.expiresAt.getTime() - 1)
    expect(await findLinkByToken(token)).not.toBeNull()
    clock = made.expiresAt
    expect(await findLinkByToken(token)).toBeNull()
    expect(await findLinkById(made.linkId)).toBeNull()

    clock = T0
    const used = await link('invited-1')
    await db().userInvite.updateMany({ where: { id: used.linkId }, data: { usedAt: T0 } })
    expect(await findLinkByToken(tokenOf(used.link))).toBeNull()

    const cancelled = await link('invited-1')
    await db().userInvite.updateMany({ where: { id: cancelled.linkId }, data: { cancelledAt: T0 } })
    expect(await findLinkByToken(tokenOf(cancelled.link))).toBeNull()
  })

  test('unknown token → invalid', async () => {
    await link('invited-1')
    expect(await findLinkByToken(newLinkToken())).toBeNull()
    expect(await findLinkByToken('')).toBeNull()
    expect(await findLinkById('invite-404')).toBeNull()
  })

  test('an invite whose account is no longer invited, a reset whose account is not active → invalid', async () => {
    const invite = await link('invited-1')
    await db().user.updateMany({ where: { id: 'invited-1' }, data: { status: 'active' } })
    expect(await findLinkByToken(tokenOf(invite.link))).toBeNull()
    const reset = await link('member-1', 'reset')
    await db().user.updateMany({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    expect(await findLinkByToken(tokenOf(reset.link))).toBeNull()
  })

  test('a deleted account takes its links with it', async () => {
    const made = await link('invited-1')
    await db().user.delete({ where: { id: 'invited-1' } })
    expect(await findLinkByToken(tokenOf(made.link))).toBeNull()
    expect(db().invites()).toEqual([])
  })
})

describe('the address of the link', () => {
  test('link uses publicBaseUrl not Host', async () => {
    db().seedInstance({ publicBaseUrl: 'https://redamon.example.com/team' })
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'https://deploy.example.org')
    const made = await link('invited-1')
    expect(made.link).toMatch(/^https:\/\/redamon\.example\.com\/team\/invite\/[A-Za-z0-9_-]{43}$/)
    expect(made.localhostWarning).toBe(false)
    expect(createLink.length).toBe(2) // (tx, link): no request, so no Host to read
  })

  test('publicBaseUrl empty: the deploy origin (E12: PLUGINS_ALLOWED_ORIGIN, then MCP_ALLOWED_ORIGIN)', () => {
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'https://deploy.example.org:8443')
    expect(resolveLinkBase(null)).toEqual({ base: 'https://deploy.example.org:8443', localhostWarning: false, source: 'deploy' })
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'https://mcp.example.org')
    expect(resolveLinkBase('')).toEqual({ base: 'https://mcp.example.org', localhostWarning: false, source: 'deploy' })
    vi.stubEnv('MCP_ALLOWED_ORIGIN', 'not a url')
    expect(resolveLinkBase(null).source).toBe('default')
  })

  test('localhost warning', () => {
    expect(resolveLinkBase(null)).toEqual({ base: 'http://localhost:3000', localhostWarning: true, source: 'default' })
    for (const local of ['http://127.0.0.1:3000', 'http://localhost:8080', 'http://[::1]:3000', 'http://0.0.0.0:3000', 'http://app.localhost']) {
      expect(resolveLinkBase(local), local).toMatchObject({ base: local, localhostWarning: true, source: 'instance' })
    }
    expect(resolveLinkBase('https://redamon.example.com').localhostWarning).toBe(false)
    expect(resolveLinkBase('http://10.0.0.5:3000').localhostWarning).toBe(false)
  })
})

describe('the invite cookie', () => {
  test('names the link for 30 minutes', async () => {
    expect(INVITE_COOKIE_MAX_AGE).toBe(30 * 60)
    const value = await signInviteCookie('invite-7')
    expect(await readInviteCookie(value)).toBe('invite-7')
    clock = new Date(T0.getTime() + 30 * 60_000 - 1000)
    expect(await readInviteCookie(value)).toBe('invite-7')
    clock = new Date(T0.getTime() + 30 * 60_000 + 1000)
    expect(await readInviteCookie(value)).toBeNull()
  })

  test('a login token is no invite cookie, a tampered or empty one names nothing', async () => {
    expect(await readInviteCookie(await createToken('member-1', 'standard'))).toBeNull()
    const value = await signInviteCookie('invite-7')
    expect(await readInviteCookie(value.slice(0, -2) + 'xx')).toBeNull()
    expect(await readInviteCookie('')).toBeNull()
    expect(await readInviteCookie(undefined)).toBeNull()
  })
})
