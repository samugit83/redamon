/**
 * The stale badge's rule (§3.3, §6.13, R-174): a changed settings hash or forced type, or a
 * Stored resource whose live version holds no stored text because it was ingested Live. A Stored
 * ingestion that the quota or a size limit left without text is current: re-ingesting would
 * store nothing more, so the badge would never clear.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { IngestionReport } from './agentContract'
import { ingestionHash, isStale } from './staleness'

const HASH = 'a1b2c3d4e5f60718'
const report = (stored: Partial<IngestionReport['stored']> = {}, kept = 5): IngestionReport =>
  IngestionReport.parse({ visited: kept, kept, stored: { pages: 0, bytes: 0, notStoredQuota: 0, notStoredSize: 0, ...stored } })
const row = (over: Partial<{ settingsHash: string; forcedType: string; resourceType: string; storageMode: string }> = {}) =>
  ({ settingsHash: HASH, forcedType: '', resourceType: 'mkdocs-wiki', storageMode: 'stored', ...over })

describe('isStale', () => {
  test('a resource 2.0 never ingested is never stale', () => {
    expect(isStale(row({ settingsHash: '' }), HASH, null)).toBe(false)
  })

  test('the settings hash or the forced type changed', () => {
    expect(isStale(row(), 'another-hash', report({ pages: 5 }))).toBe(true)
    expect(isStale(row({ forcedType: 'gitbook' }), HASH, report({ pages: 5 }))).toBe(true)
    expect(isStale(row({ forcedType: 'gitbook', settingsHash: ingestionHash(HASH, { forcedType: 'gitbook' }) }), HASH, report({ pages: 5 }))).toBe(false)
  })

  test('focus_change_is_stale (§6.13): a changed focus makes the resource stale; no focus keeps the plain hash', () => {
    const focus = { mode: 'focused', topics: ['sql_injection'], kinds: [], keep: '', skip: '', skipMode: 'add', strictness: 'balanced' }
    expect(ingestionHash(HASH, { focus: {} })).toBe(HASH)
    expect(ingestionHash(HASH, { forcedType: 'gitbook', focus: {} })).toBe(ingestionHash(HASH, { forcedType: 'gitbook' }))
    const withFocus = ingestionHash(HASH, { focus })
    expect(withFocus).toMatch(/^[0-9a-f]{16}$/)
    expect(withFocus).not.toBe(HASH)
    expect(isStale({ ...row({ settingsHash: withFocus }), focus }, HASH, report({ pages: 5 }))).toBe(false)
    expect(isStale({ ...row({ settingsHash: withFocus }), focus: { ...focus, strictness: 'strict' } }, HASH, report({ pages: 5 }))).toBe(true)
    expect(isStale({ ...row({ settingsHash: withFocus }), focus: {} }, HASH, report({ pages: 5 }))).toBe(true)
    expect(isStale({ ...row(), focus }, HASH, report({ pages: 5 }))).toBe(true)
    // The key order of a stored JSON object is not the focus.
    const reordered = Object.fromEntries(Object.entries(focus).reverse())
    expect(isStale({ ...row({ settingsHash: withFocus }), focus: reordered }, HASH, report({ pages: 5 }))).toBe(false)
  })

  test('Stored after a Live ingestion: stale until an ingestion takes the Stored path', () => {
    expect(isStale(row(), HASH, report())).toBe(true)
    expect(isStale(row(), HASH, report({ pages: 5, bytes: 500 }))).toBe(false)
    expect(isStale(row({ storageMode: 'live' }), HASH, report())).toBe(false)
  })

  test('a Stored ingestion the quota or a size limit left without text is current', () => {
    expect(isStale(row(), HASH, report({ notStoredQuota: 5 }))).toBe(false)
    expect(isStale(row(), HASH, report({ notStoredSize: 5 }))).toBe(false)
  })

  test('nothing kept, or a type that never stores text, is not stale for its mode', () => {
    expect(isStale(row(), HASH, report({}, 0))).toBe(false)
    expect(isStale(row({ resourceType: 'cve-poc-db' }), HASH, report())).toBe(false)
  })

  test('recipe_not_in_hash (review H): only what the agent reads; a recipe or Everything with chips changes nothing', () => {
    const focus = { mode: 'focused', topics: ['xss'], kinds: [], keep: 'k', skip: '', skipMode: 'add', strictness: 'balanced' }
    const h0 = ingestionHash(HASH, { focus })
    expect(ingestionHash(HASH, { focus: { ...focus, recipe: 'web_payload_library' } })).toBe(h0)
    expect(ingestionHash(HASH, { focus: { ...focus, recipe: 'rcp-mine' } })).toBe(h0)
    expect(ingestionHash(HASH, { focus: { ...focus, mode: 'everything' } })).toBe(HASH)
    expect(ingestionHash(HASH, { focus: { ...focus, keep: 'other' } })).not.toBe(h0)
  })

  test('access_change_is_stale (review F, §6.13 "access field ... marked stale"): a login or a token added, removed or renamed; never a value', () => {
    const base = ingestionHash(HASH, {})
    expect(base).toBe(HASH)
    const cookie = ingestionHash(HASH, { credentials: { cookie: 'session=fake-1', headers: [], basic_auth: null } })
    expect(cookie).not.toBe(HASH)
    // Rotating a value is not a change of what the site serves: not stale.
    expect(ingestionHash(HASH, { credentials: { cookie: 'session=fake-2', headers: [], basic_auth: null } })).toBe(cookie)
    const header = ingestionHash(HASH, { credentials: { cookie: '', headers: [{ name: 'X-Api-Key', value: 'fake-a' }], basic_auth: null } })
    expect(header).not.toBe(HASH)
    expect(ingestionHash(HASH, { credentials: { cookie: '', headers: [{ name: 'x-api-key', value: 'fake-b' }], basic_auth: null } })).toBe(header)
    expect(ingestionHash(HASH, { credentials: { cookie: '', headers: [{ name: 'X-Team', value: 'fake-a' }], basic_auth: null } })).not.toBe(header)
    const basic = ingestionHash(HASH, { credentials: { basic_auth: { username: 'bob', password: 'fake-1' } } })
    expect(ingestionHash(HASH, { credentials: { basic_auth: { username: 'bob', password: 'fake-2' } } })).toBe(basic)
    expect(ingestionHash(HASH, { credentials: { basic_auth: { username: 'alice', password: 'fake-1' } } })).not.toBe(basic)
    expect(ingestionHash(HASH, { credentials: {} })).toBe(HASH)
    const token = ingestionHash(HASH, { githubTokenOverride: 'ghp_fake_1' })
    expect(token).not.toBe(HASH)
    expect(ingestionHash(HASH, { githubTokenOverride: 'ghp_fake_2' })).toBe(token)
    expect(ingestionHash(HASH, { githubTokenOverride: '' })).toBe(HASH)
    expect(isStale({ ...row({ settingsHash: HASH }), credentials: { cookie: 'session=fake-1' } }, HASH, report({ pages: 5 }))).toBe(true)
    expect(isStale({ ...row({ settingsHash: cookie }), credentials: { cookie: 'session=fake-9' } }, HASH, report({ pages: 5 }))).toBe(false)
  })
})
