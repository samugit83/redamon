/**
 * Effective settings: spec default, then the user, then the resource, clamped to the
 * ceilings (§6.1, AC-03), with each value's provenance and a stable hash.
 *
 * @vitest-environment node
 */
import { createHash } from 'node:crypto'
import { describe, expect, test } from 'vitest'
import { canonicalJson, effectiveSettings, settingsHash, sha256Hex } from './effectiveSettings'
import { settingDef, specDefaults } from './settingsSpec'

describe('effectiveSettings', () => {
  test('levels: system, then user, then resource; most specific wins', () => {
    const system = effectiveSettings({})
    expect(system.values['crawl.maxPages']).toBe(200)
    const user = effectiveSettings({ user: { ingestion: { 'crawl.maxPages': 300 } } })
    expect(user.values['crawl.maxPages']).toBe(300)
    const both = effectiveSettings({ user: { ingestion: { 'crawl.maxPages': 300 } }, resource: { 'crawl.maxPages': 40 } })
    expect(both.values['crawl.maxPages']).toBe(40)
  })

  test('override_removed_falls_back to the user value, then to the default', () => {
    const user = { ingestion: { 'crawl.maxDepth': 5 } }
    expect(effectiveSettings({ user, resource: { 'crawl.maxDepth': 9 } }).values['crawl.maxDepth']).toBe(9)
    expect(effectiveSettings({ user, resource: {} }).values['crawl.maxDepth']).toBe(5)
    expect(effectiveSettings({ user: { ingestion: {} }, resource: {} }).values['crawl.maxDepth']).toBe(3)
  })

  test('ceiling_both_cases: a stored user value and a stored resource value over the ceiling are clamped', () => {
    const user = effectiveSettings({ user: { ingestion: { 'crawl.maxPages': 9999 } } })
    expect(user.values['crawl.maxPages']).toBe(500)
    const res = effectiveSettings({ resource: { 'fetching.browserMaxChars': 5_000_000 } })
    expect(res.values['fetching.browserMaxChars']).toBe(1_000_000)
    const low = effectiveSettings({ resource: { 'fetching.requestTimeoutSec': 0 } })
    expect(low.values['fetching.requestTimeoutSec']).toBe(5)
  })

  test('list_modes: add appends to the inherited list without duplicates, replace replaces it', () => {
    const user = { ingestion: { 'knownTypes.githubFileTypes': ['.md', '.txt'] } }
    const added = effectiveSettings({ user, resource: { 'knownTypes.githubFileTypes': { mode: 'add', items: ['.yml', '.md'] } } })
    expect(added.values['knownTypes.githubFileTypes']).toEqual(['.md', '.txt', '.yml'])
    const replaced = effectiveSettings({ user, resource: { 'knownTypes.githubFileTypes': { mode: 'replace', items: ['.yar'] } } })
    expect(replaced.values['knownTypes.githubFileTypes']).toEqual(['.yar'])
    const text = effectiveSettings({
      user: { ingestion: { 'summary.extraInstructions': 'List vulnerability classes.' } },
      resource: { 'summary.extraInstructions': { mode: 'add', text: 'Name the databases.' } },
    })
    expect(text.values['summary.extraInstructions']).toBe('List vulnerability classes.\nName the databases.')
  })

  test('provenance names where each value came from', () => {
    const r = effectiveSettings({
      user: { ingestion: { 'crawl.maxPages': 300, 'crawl.maxDepth': 4 } },
      resource: { 'crawl.maxDepth': 2, 'type.github.branch': 'dev' },
    })
    expect(r.provenance['crawl.maxPages']).toBe('user')
    expect(r.provenance['crawl.maxDepth']).toBe('resource')
    expect(r.provenance['crawl.strategy']).toBe('system')
    expect(r.provenance['type.github.branch']).toBe('resource')
    expect(Object.keys(r.provenance).sort()).toEqual(Object.keys(r.values).sort())
  })

  test('a user-only value on a resource and a resource-only value on the user are ignored', () => {
    const r = effectiveSettings({
      user: { ingestion: { 'type.github.branch': 'dev' } },
      resource: { 'storage.userQuotaMb': 5000 },
    })
    expect(r.values['type.github.branch']).toBe('')
    expect(r.values['storage.userQuotaMb']).toBe(1024)
  })

  test('stored values that no longer fit the spec are skipped, unknown keys dropped', () => {
    const r = effectiveSettings({
      user: { ingestion: { 'crawl.strategy': 'magic', 'crawl.gone': 1, 'crawl.requireTitle': 'no' } },
      resource: { 'crawl.excludePaths': ['/no-mode/'] },
    })
    expect(r.values['crawl.strategy']).toBe('llm')
    expect(r.values['crawl.requireTitle']).toBe(true)
    expect(r.values).not.toHaveProperty('crawl.gone')
    expect(r.values['crawl.excludePaths']).toEqual(settingDef('crawl.excludePaths')!.default)
  })

  test('failure_policy_override: a resource overrides the user refresh-failure policy (R-170)', () => {
    const user = { ingestion: { 'refreshing.onFailure': 'replace' } }
    expect(effectiveSettings({ user }).values['refreshing.onFailure']).toBe('replace')
    expect(effectiveSettings({ user, resource: { 'refreshing.onFailure': 'keep' } }).values['refreshing.onFailure']).toBe('keep')
  })

  test('the search scope reads the user search JSON and no resource override', () => {
    const r = effectiveSettings({ scope: 'search', user: { search: { 'search.results': 12 } }, resource: { 'search.results': 3 } })
    expect(r.values['search.results']).toBe(12)
    expect(Object.keys(r.values).every(k => !k.startsWith('crawl.'))).toBe(true)
  })

  test('hash_stable_and_order_independent', () => {
    const a = effectiveSettings({ user: { ingestion: { 'crawl.maxPages': 300, 'crawl.maxDepth': 4 } } })
    const b = effectiveSettings({ user: { ingestion: { 'crawl.maxDepth': 4, 'crawl.maxPages': 300 } } })
    expect(a.hash).toBe(b.hash)
    expect(a.hash).toMatch(/^[0-9a-f]{16}$/)
    const reordered = Object.fromEntries(Object.entries(a.values).reverse())
    expect(settingsHash(reordered)).toBe(a.hash)
    expect(effectiveSettings({}).hash).not.toBe(a.hash)
    expect(effectiveSettings({}).hash).toBe(settingsHash(specDefaults('ingestion')))
  })
})

describe('the hash primitives', () => {
  test('canonicalJson sorts keys at every level', () => {
    expect(canonicalJson({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: 'x' } })).toBe('{"a":{"c":"x","d":[2,{"y":2,"z":1}]},"b":1}')
  })

  test('sha256Hex equals Node crypto on edge lengths and non-ASCII text', () => {
    const inputs = ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'a'.repeat(1000), 'pg_sleep · é 漢字 🙂']
    for (const s of inputs) expect(sha256Hex(s), JSON.stringify(s.slice(0, 10))).toBe(createHash('sha256').update(s, 'utf8').digest('hex'))
  })
})
