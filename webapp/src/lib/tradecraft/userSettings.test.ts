/**
 * The account's ingestion settings (Configure ingestion, §3.2, §4): only the values a person
 * changed are stored, a value equal to its default is removed, a reset clears a section or
 * everything, and one account's values never reach another's (AC-04).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as never)[k] }) }))

import {
  INGESTION_SECTIONS, MAX_USER_SYNONYMS, editRecipes, ingestionDefaults, readIngestionSettings, readRecipes, readSearchSettings,
  resetIngestionSettings, resetSearchSettings, saveIngestionSettings, saveSearchSettings, searchDefaults, validateSynonyms,
} from './userSettings'
import { SETTINGS } from './settingsSpec'

function stored(userId: string): Record<string, unknown> {
  const row = h.db.rows('tradecraftUserSettings', { userId })[0]
  return (row?.ingestion ?? {}) as Record<string, unknown>
}

beforeEach(() => {
  h.db = createTradecraftDb()
})

describe('readIngestionSettings', () => {
  test('get_values_changed_defaults: defaults without a row, then the saved value marked changed', async () => {
    const empty = await readIngestionSettings('u1')
    expect(empty.changed).toEqual([])
    expect(empty.values['crawl.maxPages']).toBe(200)
    expect(empty.defaults['crawl.maxPages']).toBe(200)
    h.db.seed('tradecraftUserSettings', { userId: 'u1', ingestion: { 'crawl.maxPages': 50 } })
    const saved = await readIngestionSettings('u1')
    expect(saved.values['crawl.maxPages']).toBe(50)
    expect(saved.defaults['crawl.maxPages']).toBe(200)
    expect(saved.changed).toEqual(['crawl.maxPages'])
  })

  test('answers every ingestion setting a person may set and no resource-only or search key', async () => {
    const r = await readIngestionSettings('u1')
    const expected = SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource').map(s => s.key).sort()
    expect(Object.keys(r.values).sort()).toEqual(expected)
    expect(Object.keys(r.defaults).sort()).toEqual(expected)
    expect(r.values['content.bodySelector']).toBeUndefined()
    expect(r.values['search.results']).toBeUndefined()
  })

  test('a stored value outside the ceiling reads clamped, and one of the wrong type reads as the default', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'u1', ingestion: { 'crawl.maxPages': 99999, 'crawl.parallel': 'many' } })
    const r = await readIngestionSettings('u1')
    expect(r.values['crawl.maxPages']).toBe(500)
    expect(r.values['crawl.parallel']).toBe(1)
    expect(r.changed).toEqual(['crawl.maxPages'])
  })
})

describe('saveIngestionSettings', () => {
  test('put_stores_only_changed: only the keys sent, and nothing else of the spec', async () => {
    const r = await saveIngestionSettings('u1', { 'crawl.maxPages': 120, 'fetching.userAgent': 'Probe/1.0' })
    expect(r.ok).toBe(true)
    expect(stored('u1')).toEqual({ 'crawl.maxPages': 120, 'fetching.userAgent': 'Probe/1.0' })
    await saveIngestionSettings('u1', { 'summary.titles': 10 })
    expect(stored('u1')).toEqual({ 'crawl.maxPages': 120, 'fetching.userAgent': 'Probe/1.0', 'summary.titles': 10 })
  })

  test('put_default_removes_key: a value equal to the default removes the key (a list too)', async () => {
    await saveIngestionSettings('u1', { 'crawl.maxPages': 120, 'crawl.excludePaths': ['login'] })
    const def = ingestionDefaults()['crawl.excludePaths']
    await saveIngestionSettings('u1', { 'crawl.maxPages': 200, 'crawl.excludePaths': def })
    expect(stored('u1')).toEqual({})
    expect((await readIngestionSettings('u1')).changed).toEqual([])
  })

  test('refuses_out_of_range: every bad key named with its range, nothing written', async () => {
    await saveIngestionSettings('u1', { 'crawl.maxPages': 120 })
    const r = await saveIngestionSettings('u1', { 'crawl.maxPages': 501, 'crawl.parallel': 0, 'summary.titles': 10 })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.errors.map(e => e.key).sort()).toEqual(['crawl.maxPages', 'crawl.parallel'])
    expect(r.errors.find(e => e.key === 'crawl.maxPages')!.message).toBe('crawl.maxPages must be an integer from 1 to 500')
    expect(stored('u1')).toEqual({ 'crawl.maxPages': 120 })
  })

  test('user_only_keys_accepted: a user-only setting is saved', async () => {
    const r = await saveIngestionSettings('u1', { 'storage.userQuotaMb': 2048, 'detection.enabledDetectors': ['github'] })
    expect(r.ok).toBe(true)
    expect(stored('u1')).toEqual({ 'storage.userQuotaMb': 2048, 'detection.enabledDetectors': ['github'] })
  })

  test('resource_only_keys_refused: a resource-only key, a search key and an unknown key are refused', async () => {
    const r = await saveIngestionSettings('u1', { 'content.bodySelector': 'main', 'search.results': 5, 'nope.key': 1 })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(Object.fromEntries(r.errors.map(e => [e.key, e.code]))).toEqual({
      'content.bodySelector': 'resource_only', 'search.results': 'wrong_scope', 'nope.key': 'unknown_key',
    })
    expect(h.db.rows('tradecraftUserSettings')).toEqual([])
  })

  test('keeps the switch, the search settings and a stored key the spec does not know', async () => {
    h.db.seed('tradecraftUserSettings', {
      userId: 'u1', v2Enabled: true, search: { 'search.results': 5 }, ingestion: { 'future.key': 7 },
    })
    await saveIngestionSettings('u1', { 'crawl.maxPages': 9 })
    const row = h.db.rows('tradecraftUserSettings', { userId: 'u1' })[0]
    expect(row.v2Enabled).toBe(true)
    expect(row.search).toEqual({ 'search.results': 5 })
    expect(row.ingestion).toEqual({ 'future.key': 7, 'crawl.maxPages': 9 })
  })

  test('takes the account row lock before it reads, inside one transaction', async () => {
    await saveIngestionSettings('u1', { 'crawl.maxPages': 9 })
    expect(h.db.raw.map(r => r.sql)).toEqual(['SELECT pg_advisory_xact_lock(hashtext($1))'])
    expect(h.db.raw[0].values).toEqual(['tradecraft_user_settings:u1'])
    const lockAt = h.db.calls.indexOf('$raw')
    expect(lockAt).toBeLessThan(h.db.calls.indexOf('tradecraftUserSettings.findUnique'))
  })

  test('an empty object changes nothing and is not an error', async () => {
    const r = await saveIngestionSettings('u1', {})
    expect(r.ok).toBe(true)
    expect(stored('u1')).toEqual({})
  })
})

describe('resetIngestionSettings', () => {
  test('reset_section: only that section goes back to its defaults', async () => {
    await saveIngestionSettings('u1', { 'crawl.maxPages': 9, 'crawl.parallel': 4, 'summary.titles': 10 })
    const r = await resetIngestionSettings('u1', 'crawl')
    expect(r.ok).toBe(true)
    expect(stored('u1')).toEqual({ 'summary.titles': 10 })
  })

  test('reset_all: every value goes back to its default', async () => {
    await saveIngestionSettings('u1', { 'crawl.maxPages': 9, 'summary.titles': 10 })
    await resetIngestionSettings('u1', 'all')
    expect(stored('u1')).toEqual({})
    expect((await readIngestionSettings('u1')).values['crawl.maxPages']).toBe(200)
  })

  test('an unknown section, a resource-only section or a search section is refused', async () => {
    for (const section of ['nope', 'siteType', 'content', 'search', '']) {
      expect((await resetIngestionSettings('u1', section)).ok).toBe(false)
    }
  })

  test('the sections a person may reset are the ingestion sections that hold a user setting', () => {
    expect(INGESTION_SECTIONS).toEqual(['fetching', 'detection', 'knownTypes', 'crawl', 'storage', 'summary', 'refreshing', 'focus'])
  })
})

test('isolated (AC-04): one account saving or resetting never changes another account', async () => {
  await saveIngestionSettings('u2', { 'crawl.maxPages': 77 })
  await saveIngestionSettings('u1', { 'crawl.maxPages': 9, 'summary.titles': 10 })
  await resetIngestionSettings('u1', 'all')
  expect(stored('u2')).toEqual({ 'crawl.maxPages': 77 })
  expect((await readIngestionSettings('u2')).values['crawl.maxPages']).toBe(77)
  expect((await readIngestionSettings('u1')).values['crawl.maxPages']).toBe(200)
})

describe('focus recipes (§4.8 "My focus recipes", T5.5)', () => {
  const add = (userId: string, recipe: Record<string, unknown>) => editRecipes(userId, { add: recipe })
  const storedRecipes = (userId: string) => (h.db.rows('tradecraftUserSettings', { userId })[0]?.recipes ?? []) as Record<string, unknown>[]

  test('an account starts with none; an added recipe is listed with its id', async () => {
    expect(await readRecipes('u1')).toEqual([])
    const r = await add('u1', { name: '  SQLi payloads ', topics: ['sql_injection'], kinds: ['payloads', 'bypasses'] })
    expect(r).toMatchObject({ ok: true, recipes: [{ name: 'SQLi payloads', topics: ['sql_injection'], kinds: ['payloads', 'bypasses'] }] })
    const [recipe] = await readRecipes('u1')
    expect(recipe.id).toMatch(/^[A-Za-z0-9_-]{8,64}$/)
    expect(storedRecipes('u1')).toEqual([recipe])
  })

  test('recipes_cap_50: the 50th recipe is saved, the 51st refused with nothing written', async () => {
    for (let i = 0; i < 50; i++) expect((await add('u1', { name: `R${i}`, kinds: ['poc'] })).ok).toBe(true)
    const r = await add('u1', { name: 'One too many', kinds: ['poc'] })
    expect(r).toMatchObject({ ok: false, status: 409, code: 'recipe_cap' })
    expect(storedRecipes('u1')).toHaveLength(50)
  })

  test('recipe_topics_validated: topics and kinds from the fixed lists, a name of 1-60 characters, something chosen', async () => {
    for (const [why, recipe, field] of [
      ['an unknown topic', { name: 'x', topics: ['sqli'] }, 'topics'],
      ['an unknown kind', { name: 'x', kinds: ['tool'] }, 'kinds'],
      ['no name', { name: '  ', kinds: ['poc'] }, 'name'],
      ['a long name', { name: 'n'.repeat(61), kinds: ['poc'] }, 'name'],
      ['a control character', { name: 'a\nb', kinds: ['poc'] }, 'name'],
      ['nothing chosen', { name: 'Empty' }, 'topics'],
      ['an unknown key', { name: 'x', kinds: ['poc'], skip: 'news' }, 'recipe'],
    ] as const) {
      expect(await add('u1', recipe as Record<string, unknown>), why).toMatchObject({ ok: false, status: 400, field })
    }
    expect(await add('u1', { name: 'n'.repeat(60), kinds: ['poc'] })).toMatchObject({ ok: true })
    expect(storedRecipes('u1')).toHaveLength(1)
  })

  test('user_skill_topics_allowed and foreign_skill_refused: only the owner\'s own skills', async () => {
    h.db.seed('userAttackSkill', { id: 'mine', userId: 'u1', name: 'Mine' })
    h.db.seed('userAttackSkill', { id: 'theirs', userId: 'u2', name: 'Theirs' })
    expect(await add('u1', { name: 'Mine', topics: ['user_skill:mine'] })).toMatchObject({ ok: true })
    expect(await add('u1', { name: 'Theirs', topics: ['user_skill:theirs'] })).toMatchObject({ ok: false, status: 400, code: 'foreign_skill', field: 'topics' })
    expect(storedRecipes('u1').map(r => r.name)).toEqual(['Mine'])
  })

  test('a name is unique per account (case and spaces aside); another account may reuse it', async () => {
    await add('u1', { name: 'Web', kinds: ['poc'] })
    expect(await add('u1', { name: ' web ', kinds: ['payloads'] })).toMatchObject({ ok: false, status: 409, code: 'recipe_name_taken' })
    expect(await add('u2', { name: 'Web', kinds: ['payloads'] })).toMatchObject({ ok: true })
  })

  test('rename and delete by id; an unknown id is a 404; the other recipes stay', async () => {
    await add('u1', { name: 'A', kinds: ['poc'] })
    await add('u1', { name: 'B', kinds: ['writeups'] })
    const [a, b] = await readRecipes('u1')
    expect(await editRecipes('u1', { rename: { id: a.id, name: 'A2' } })).toMatchObject({ ok: true, recipes: [{ id: a.id, name: 'A2' }, { id: b.id, name: 'B' }] })
    expect(await editRecipes('u1', { rename: { id: a.id, name: 'b' } })).toMatchObject({ ok: false, code: 'recipe_name_taken' })
    expect(await editRecipes('u1', { rename: { id: 'nope', name: 'C' } })).toMatchObject({ ok: false, status: 404, code: 'recipe_not_found' })
    expect(await editRecipes('u1', { delete: a.id })).toMatchObject({ ok: true, recipes: [{ id: b.id }] })
    expect(await editRecipes('u1', { delete: a.id })).toMatchObject({ ok: false, status: 404 })
    expect(await editRecipes('u2', { delete: b.id })).toMatchObject({ ok: false, status: 404 })
    expect(storedRecipes('u1').map(r => r.name)).toEqual(['B'])
  })

  test('exactly one of add, rename, delete', async () => {
    for (const body of [{}, { add: { name: 'x', kinds: ['poc'] }, delete: 'x' }, { replace: [] }, { delete: 7 }, { rename: { id: 'x' } }]) {
      expect(await editRecipes('u1', body), JSON.stringify(body)).toMatchObject({ ok: false, status: 400 })
    }
  })

  test('a malformed stored list reads as the valid recipes it holds; the ingestion values stay', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'u1', ingestion: { 'crawl.maxPages': 9 }, recipes: [{ id: 'ok1', name: 'Kept', topics: ['xss'], kinds: [] }, 'junk', { name: 'no id' }] })
    expect(await readRecipes('u1')).toEqual([{ id: 'ok1', name: 'Kept', topics: ['xss'], kinds: [] }])
    await add('u1', { name: 'New', kinds: ['poc'] })
    expect(stored('u1')).toEqual({ 'crawl.maxPages': 9 })
    expect(storedRecipes('u1').map(r => r.name)).toEqual(['Kept', 'New'])
  })
})

describe('the search settings (Configure search, Q11, T7.2)', () => {
  const row = () => h.db.rows('tradecraftUserSettings', { userId: 'u1' })[0]

  test('search_section_ranges: every search setting of the spec, user level, defaults as Q11; out of range refused', async () => {
    const view = await readSearchSettings('u1')
    expect(Object.keys(view.values).sort()).toEqual(SETTINGS.filter(s => s.scope === 'search').map(s => s.key).sort())
    expect(view.defaults).toEqual(searchDefaults())
    expect(view.values).toMatchObject({
      'librarian.use': 'agent', 'librarian.maxModelCalls': 5, 'librarian.maxPages': 4, 'librarian.timeLimitSec': 30,
      'librarian.questionsPerRun': 10, 'search.results': 8, 'search.useSession': true, 'search.strictness': 'balanced',
      'reading.charsPerRead': 12000, 'prompt.resourceList': 'auto', 'prompt.coverageMap': true, 'hints.enabled': true,
    })
    expect(view.values).not.toHaveProperty('hints.perRun')
    const bad = await saveSearchSettings('u1', { 'librarian.maxModelCalls': 1, 'search.results': 21 })
    expect(bad.ok).toBe(false)
    expect(!bad.ok && bad.errors.map(e => e.key)).toEqual(['librarian.maxModelCalls', 'search.results'])
    expect(row()).toBeUndefined()
  })

  test('saves only what changed, keeps the ingestion values and the switch; a default removes its key', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'u1', v2Enabled: true, ingestion: { 'crawl.maxPages': 9 }, search: { 'search.results': 4 } })
    const r = await saveSearchSettings('u1', { 'search.results': 12, 'librarian.questionsPerRun': 10 })
    expect(r.ok && r.view.changed).toEqual(['search.results'])
    expect(row()).toMatchObject({ v2Enabled: true, ingestion: { 'crawl.maxPages': 9 }, search: { 'search.results': 12 } })
  })

  test('a removed setting, stored or sent, is ignored and dropped at the next save, never an error', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'u1', v2Enabled: true, search: { 'hints.perRun': 2, 'search.results': 4 } })
    const view = await readSearchSettings('u1')
    expect(view.values).not.toHaveProperty('hints.perRun')
    expect(view.changed).toEqual(['search.results'])
    const r = await saveSearchSettings('u1', { 'hints.perRun': 6, 'hints.enabled': false })
    expect(r.ok && r.view.changed.sort()).toEqual(['hints.enabled', 'search.results'])
    expect(row().search).toEqual({ 'search.results': 4, 'hints.enabled': false })
  })

  test('synonyms_cap_200 and their shape: one {term, expansions} per pair, as the agent reads them', async () => {
    expect(MAX_USER_SYNONYMS).toBe(200)
    const many = Array.from({ length: 201 }, (_, i) => ({ term: `t${i}`, expansion: `e${i}` }))
    expect(validateSynonyms(many.slice(0, 200)).ok).toBe(true)
    expect(validateSynonyms(many).ok).toBe(false)
    const r = await saveSearchSettings('u1', { synonyms: [{ term: 'PATT', expansion: 'PayloadsAllTheThings' }] })
    expect(r.ok && r.view.synonyms).toEqual([{ term: 'PATT', expansion: 'PayloadsAllTheThings' }])
    expect(row().synonyms).toEqual([{ term: 'PATT', expansions: ['PayloadsAllTheThings'] }])
    expect((await readSearchSettings('u1')).synonyms).toEqual([{ term: 'PATT', expansion: 'PayloadsAllTheThings' }])
  })

  test('reset leaves the synonyms and the keys the spec does not know; under the account row lock', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'u1', search: { 'search.results': 12, 'future.key': 1 }, synonyms: [{ term: 'a', expansions: ['b'] }] })
    await resetSearchSettings('u1')
    expect(row().search).toEqual({ 'future.key': 1 })
    expect(row().synonyms).toEqual([{ term: 'a', expansions: ['b'] }])
    expect(h.db.raw[0].values).toEqual(['tradecraft_user_settings:u1'])
  })

  test('isolated (AC-04): one account\'s search settings never reach another\'s', async () => {
    await saveSearchSettings('u1', { 'search.results': 3 })
    expect((await readSearchSettings('u2')).values['search.results']).toBe(8)
  })
})
