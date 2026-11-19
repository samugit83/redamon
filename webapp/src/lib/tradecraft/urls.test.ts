/**
 * The URL check and slug helpers both route branches use (moved from the 1.x route, same
 * behaviour), plus the refusal of a login in the URL (D-43).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { USERINFO_REFUSED, hasUserinfo, isPrivateHost, slugify, uniqueSlug, validateUrl } from './urls'
import { SLUG_RE } from './agentContract'

beforeEach(() => { h.db = createTradecraftDb() })

describe('validateUrl', () => {
  test.each([
    ['https://user:pass@wiki.example.test/', 'user and password'],
    ['https://user@wiki.example.test/', 'user only'],
    ['https://:pass@wiki.example.test/', 'password only'],
    ['http://admin:x@10.0.0.5/', 'on a private host too'],
  ])('userinfo_refused: %s (%s)', (url) => {
    expect(validateUrl(url)).toEqual({ ok: false, error: USERINFO_REFUSED, code: 'userinfo_refused' })
  })

  test('the refusal tells where a login goes', () => {
    expect(USERINFO_REFUSED).toBe("Put a site login in the resource's Access settings, not in its URL")
  })

  test('an @ in the path or the query is not a login', () => {
    expect(validateUrl('https://wiki.example.test/users/@me?mail=a@b.test')).toEqual({ ok: true })
  })

  test.each([
    ['ftp://wiki.example.test/', 'Only http(s) URLs are allowed'],
    ['not a url', 'Invalid URL'],
    [42, 'Invalid URL'],
    ['http://127.0.0.1/x', 'private address blocked'],
    ['http://localhost:3000/', 'private address blocked'],
    ['http://192.168.1.10/', 'private address blocked'],
    ['http://intranet.internal/', 'private address blocked'],
  ])('unchanged from 1.x: %s', (url, error) => {
    expect(validateUrl(url)).toEqual({ ok: false, error })
  })

  test('a public https URL passes', () => {
    expect(validateUrl('https://wiki.example.test/docs/')).toEqual({ ok: true })
    expect(isPrivateHost('wiki.example.test')).toBe(false)
  })

  test('hasUserinfo: the 1.x edit refuses only this', () => {
    expect(hasUserinfo('https://u:p@h.example.test/')).toBe(true)
    expect(hasUserinfo('https://h.example.test/')).toBe(false)
    expect(hasUserinfo('nonsense')).toBe(false)
  })
})

describe('slugs', () => {
  test('slugify: lowercase, accents dropped, dashes, at most 64, a fallback; always a contract slug', () => {
    expect(slugify('HackTricks Wiki!')).toBe('hacktricks-wiki')
    expect(slugify('Écoles  Sûres')).toBe('ecoles-sures')
    expect(slugify('???')).toBe('resource')
    expect(slugify('a'.repeat(100))).toHaveLength(64)
    for (const name of ['HackTricks Wiki!', '???', `${'x'.repeat(63)} y`]) expect(slugify(name)).toMatch(SLUG_RE)
  })

  test('uniqueSlug: the first free one of base, base-2, base-3, per account', async () => {
    for (const slug of ['wiki', 'wiki-2']) h.db.seed('userTradecraftResource', { userId: 'owner', slug, name: slug, url: `https://${slug}.example.test/` })
    h.db.seed('userTradecraftResource', { userId: 'other', slug: 'wiki-3', name: 'w', url: 'https://w.example.test/' })
    expect(await uniqueSlug('owner', 'wiki')).toBe('wiki-3')
    expect(await uniqueSlug('other', 'wiki')).toBe('wiki')
  })
})
