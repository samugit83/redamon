/**
 * The settings spec is the contract every later card reads (phase 1 "Settings"): its
 * entries must be well formed, its ranges inside the ceilings, and it must never grow a
 * cache setting or a user-level login.
 *
 * @vitest-environment node
 */
import { describe, expect, test } from 'vitest'
import {
  SECTIONS, SETTINGS, SETTINGS_CONSTANTS, SITE_TYPE_KEYS, settingDef, specDefaults, validateOverrides, validateUserSettings,
  isValidValue, type SettingDef,
} from './settingsSpec'

const NUMERIC = (s: SettingDef) => s.type === 'int' || s.type === 'number'

describe('settingsSpec: every entry well formed', () => {
  test('keys are unique and dotted', () => {
    const keys = SETTINGS.map(s => s.key)
    expect(new Set(keys).size).toBe(keys.length)
    for (const k of keys) expect(k).toMatch(/^[a-z][A-Za-z]*(\.[a-z][A-Za-z0-9]*)+$/)
  })

  test('section, scope, level and type are known; the section belongs to the same scope', () => {
    const sections = new Map(SECTIONS.map(s => [s.id, s]))
    for (const s of SETTINGS) {
      expect(sections.has(s.section), s.key).toBe(true)
      expect(sections.get(s.section)!.scope, s.key).toBe(s.scope)
      expect(['user', 'both', 'resource'], s.key).toContain(s.level)
      expect(['int', 'number', 'bool', 'enum', 'string', 'list'], s.key).toContain(s.type)
      expect(s.label.length, s.key).toBeGreaterThan(0)
      expect(s.help.length, s.key).toBeGreaterThan(0)
    }
  })

  test('each type carries the fields it needs and its default is a valid value', () => {
    for (const s of SETTINGS) {
      if (NUMERIC(s)) {
        expect([s.min, s.max, s.ceiling].every(n => typeof n === 'number'), s.key).toBe(true)
        expect(s.unit, s.key).toBeTruthy()
      }
      if (s.type === 'enum') expect(s.values!.length, s.key).toBeGreaterThan(1)
      if (s.type === 'string') expect(s.maxLength, s.key).toBeGreaterThan(0)
      if (s.type === 'list') expect(s.maxItems! > 0 && s.maxLength! > 0, s.key).toBe(true)
      if (s.listMode) expect(['list', 'string'], s.key).toContain(s.type)
      expect(isValidValue(s, s.default), `${s.key} default`).toBe(true)
    }
  })

  test('ranges inside ceilings', () => {
    for (const s of SETTINGS.filter(NUMERIC)) {
      expect(s.min! <= (s.default as number) && (s.default as number) <= s.max! && s.max! <= s.ceiling!, s.key).toBe(true)
    }
  })

  test('appliesTo names only short site types', () => {
    const types = new Set(Object.values(SITE_TYPE_KEYS))
    for (const s of [...SETTINGS, ...SECTIONS]) for (const t of s.appliesTo ?? []) expect(types.has(t), `${'key' in s ? s.key : s.id}: ${t}`).toBe(true)
    expect(Object.keys(SITE_TYPE_KEYS).sort()).toEqual(['agentic-crawl', 'cve-poc-db', 'gitbook', 'github-repo', 'mkdocs-wiki', 'pdf', 'sphinx-docs'])
  })

  test('the key names later cards use exist', () => {
    const fixed = [
      'fetching.requestTimeoutSec', 'fetching.browserMaxChars', 'crawl.strategy', 'crawl.maxPages', 'knownTypes.realTitles',
      'knownTypes.maxTitleFetches', 'knownTypes.maxMapEntries.website', 'storage.defaultMode', 'storage.incremental',
      'summary.defaultModel', 'refreshing.onFailure', 'focus.tagEveryPage', 'focus.maxContentChecks', 'librarian.use',
      'search.results', 'search.useSession', 'search.strictness', 'reading.charsPerRead', 'prompt.resourceList',
      'prompt.coverageMap', 'hints.enabled', 'hints.perRun',
    ]
    for (const k of fixed) expect(settingDef(k), k).toBeDefined()
    expect(settingDef('crawl.strategy')!.values).toEqual(['llm', 'auto', 'rules'])
    expect(settingDef('refreshing.onFailure')!.values).toEqual(['keep', 'replace'])
    expect(settingDef('focus.tagEveryPage')!.values).toEqual(['rules_model', 'rules'])
    expect(settingDef('librarian.use')!.values).toEqual(['agent', 'search_only'])
    expect(settingDef('prompt.resourceList')!.values).toEqual(['auto', 'full', 'one_line'])
    expect(settingDef('summary.defaultModel')!.level).toBe('user')
  })
})

describe('settingsSpec: the feature document defaults', () => {
  test('crawl.maxPages defaults to 200 (§4.4, today 30)', () => {
    expect(settingDef('crawl.maxPages')!.default).toBe(200)
    expect(settingDef('crawl.maxPages')!.ceiling).toBe(500)
  })

  test('storage.defaultMode defaults to live (OQ-9)', () => {
    expect(settingDef('storage.defaultMode')!.default).toBe('live')
  })

  test('crawl strategy defaults to LLM-guided (OQ-1) and the browser cut to 40,000 with the EX-2 ceiling', () => {
    expect(settingDef('crawl.strategy')!.default).toBe('llm')
    expect(settingDef('fetching.browserMaxChars')).toMatchObject({ default: 40000, min: 10000, max: 500000, ceiling: 1000000 })
  })

  test('the user storage quota is 1 GB under a 10 GB ceiling (OQ-2)', () => {
    expect(settingDef('storage.userQuotaMb')).toMatchObject({ default: 1024, ceiling: 10240, level: 'user' })
    expect(SETTINGS_CONSTANTS.userStoredBytesCeiling).toBe(10 * 1024 ** 3)
    expect(SETTINGS_CONSTANTS.instanceStoredBytesCeiling).toBe(20 * 1024 ** 3)
  })

  test('no_cache_setting: no key or label names a cache or a lifetime (R-084)', () => {
    for (const s of SETTINGS) {
      expect(`${s.key} ${s.label}`, s.key).not.toMatch(/cache|ttl/i)
    }
  })

  test('no_credentials_at_user_level: no cookie, header, password or token setting anywhere (R-071)', () => {
    for (const s of SETTINGS) {
      expect(`${s.key} ${s.label}`, s.key).not.toMatch(/cookie|header|password|credential|secret|authorization|githubtoken/i)
    }
  })

  test('search settings are user only (Q11)', () => {
    for (const s of SETTINGS.filter(x => x.scope === 'search')) expect(s.level, s.key).toBe('user')
  })

  test('specDefaults holds every key of its scope and nothing else', () => {
    const ingestion = specDefaults('ingestion')
    expect(Object.keys(ingestion).sort()).toEqual(SETTINGS.filter(s => s.scope === 'ingestion').map(s => s.key).sort())
    expect(ingestion['crawl.excludePaths']).toContain('page/*')
    ;(ingestion['crawl.excludePaths'] as string[]).push('mutated')
    expect(settingDef('crawl.excludePaths')!.default).not.toContain('mutated')
  })
})

describe('validateUserSettings', () => {
  test('accepts user and both keys of its scope', () => {
    const r = validateUserSettings('ingestion', { 'crawl.maxPages': 300, 'storage.defaultMode': 'stored', 'detection.enabledDetectors': ['github'] })
    expect(r).toEqual({ ok: true, value: { 'crawl.maxPages': 300, 'storage.defaultMode': 'stored', 'detection.enabledDetectors': ['github'] } })
  })

  test('refuses an out-of-range value, naming the key and its range', () => {
    const r = validateUserSettings('ingestion', { 'crawl.maxPages': 501 })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors).toEqual([{ key: 'crawl.maxPages', code: 'bad_value', message: 'crawl.maxPages must be an integer from 1 to 500' }])
  })

  test('refuses a resource-only key, a key of the other scope, an unknown key and a wrong type', () => {
    const r = validateUserSettings('ingestion', {
      'type.github.branch': 'main', 'search.results': 5, 'crawl.cacheTtl': 1, 'crawl.requireTitle': 'yes', 'crawl.maxPages': 2.5,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(Object.fromEntries(r.errors.map(e => [e.key, e.code]))).toEqual({
        'type.github.branch': 'resource_only', 'search.results': 'wrong_scope', 'crawl.cacheTtl': 'unknown_key',
        'crawl.requireTitle': 'bad_value', 'crawl.maxPages': 'bad_value',
      })
    }
  })

  test('a list item outside the allowed values is refused', () => {
    expect(validateUserSettings('ingestion', { 'detection.enabledDetectors': ['github', 'wordpress'] }).ok).toBe(false)
  })

  test('the search scope accepts its own keys', () => {
    expect(validateUserSettings('search', { 'search.results': 3, 'hints.perRun': 0, 'librarian.use': 'search_only' }).ok).toBe(true)
    expect(validateUserSettings('search', { 'crawl.maxPages': 10 }).ok).toBe(false)
  })

  test('refuses something that is not an object', () => {
    for (const bad of [null, [], 'x', 3]) expect(validateUserSettings('ingestion', bad).ok).toBe(false)
  })
})

describe('validateOverrides', () => {
  test('every user-only key is refused on a resource (R-133)', () => {
    const userOnly = SETTINGS.filter(s => s.level === 'user')
    expect(userOnly.length).toBeGreaterThan(5)
    for (const s of userOnly) {
      const r = validateOverrides({ [s.key]: s.default })
      expect(r.ok, s.key).toBe(false)
      if (!r.ok) expect(r.errors[0].code, s.key).toBe('user_only')
    }
  })

  test('both and resource keys are accepted; a list-mode key carries its mode', () => {
    const r = validateOverrides({
      'crawl.maxPages': 50,
      'type.github.includeFolders': ['SQL Injection/'],
      'crawl.excludePaths': { mode: 'add', items: ['/drafts/'] },
      'summary.extraInstructions': { mode: 'replace', text: 'List the CVE ids.' },
    })
    expect(r).toEqual({
      ok: true,
      value: {
        'crawl.maxPages': 50,
        'type.github.includeFolders': ['SQL Injection/'],
        'crawl.excludePaths': { mode: 'add', items: ['/drafts/'] },
        'summary.extraInstructions': { mode: 'replace', text: 'List the CVE ids.' },
      },
    })
  })

  test('a list-mode key without its mode, or with extra fields, is refused', () => {
    for (const bad of [['/x/'], { items: ['/x/'] }, { mode: 'merge', items: ['/x/'] }, { mode: 'add', items: ['/x/'], extra: 1 }]) {
      expect(validateOverrides({ 'crawl.includePaths': bad }).ok, JSON.stringify(bad)).toBe(false)
    }
  })
})

describe('constants', () => {
  test('the fixed values of the plan (§5, Q11, Q12)', () => {
    expect(SETTINGS_CONSTANTS).toMatchObject({
      jobsPerAgent: 2, jobLeaseSec: 60, jobLeaseRenewSec: 20, dbPoolSize: 5, maxResourcesPerUser: 200,
      maxQueuedJobsPerUser: 200, purgeBatchRows: 5000, checkUrlDeadlineSec: 60, focusPreviewDeadlineSec: 120,
      readNowDeadlineSec: 45, webappDeadlineMarginSec: 15, searchWordings: 6, resultsPerWording: 20, mergedCandidates: 40,
      librarianSectionChars: 3000, librarianSecondTries: 1, librarianAnswerMaxChars: 6000, coverageMapMaxTopics: 20,
      fullSummaryMaxResources: 10, pagesPerHint: 3, cardPassMaxPages: 500, folderDescriptionCalls: 10, maxRedirects: 5,
      sitemapMaxBytes: 10 * 1024 * 1024, sitemapMaxDepth: 2, sitemapMaxChildren: 20,
    })
  })
})
