/**
 * The fields a person may write on a 2.0 resource.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { defaultStorageMode, forcedStorageMode, parseResourceFields, recommendedStorageMode, typeOptionsOf } from './fields'

const CREATE = { name: 'Wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' }

describe('parseResourceFields', () => {
  test('create needs a name, a URL and a model', () => {
    expect(parseResourceFields(CREATE, 'create')).toEqual({ ok: true, value: { name: 'Wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' } })
    for (const key of ['name', 'url', 'llmModel'] as const) {
      const body: Record<string, unknown> = { ...CREATE }
      delete body[key]
      expect(parseResourceFields(body, 'create')).toMatchObject({ ok: false, error: { field: key } })
    }
  })

  test('update takes only what it is given', () => {
    expect(parseResourceFields({ enabled: false }, 'update')).toEqual({ ok: true, value: { enabled: false } })
  })

  test('url_checked: the address check and the login-in-URL refusal', () => {
    expect(parseResourceFields({ url: 'http://127.0.0.1/' }, 'update')).toMatchObject({ ok: false, error: { field: 'url', code: 'bad_url', error: 'private address blocked' } })
    expect(parseResourceFields({ url: 'https://u:p@wiki.example.test/' }, 'update')).toMatchObject({ ok: false, error: { code: 'userinfo_refused' } })
    expect(parseResourceFields({ url: `https://wiki.example.test/${'a'.repeat(2100)}` }, 'update')).toMatchObject({ ok: false, error: { field: 'url' } })
  })

  test('a loop model is refused, a model is trimmed', () => {
    expect(parseResourceFields({ llmModel: 'loop/mcp' }, 'update')).toMatchObject({ ok: false, error: { code: 'loop_model_not_allowed' } })
    expect(parseResourceFields({ llmModel: '  gpt-4o ' }, 'update')).toEqual({ ok: true, value: { llmModel: 'gpt-4o' } })
  })

  test('a masked GitHub token keeps the stored one; an empty one clears it', () => {
    expect(parseResourceFields({ githubTokenOverride: '••••••••1234' }, 'update')).toEqual({ ok: true, value: {} })
    expect(parseResourceFields({ githubTokenOverride: 'set' }, 'update')).toEqual({ ok: true, value: {} })
    expect(parseResourceFields({ githubTokenOverride: '' }, 'update')).toEqual({ ok: true, value: { githubTokenOverride: '' } })
    expect(parseResourceFields({ githubTokenOverride: 'ghp_new' }, 'update')).toEqual({ ok: true, value: { githubTokenOverride: 'ghp_new' } })
  })

  test('storage, type, login removal, focus', () => {
    expect(parseResourceFields({ storageMode: 'stored', forcedType: 'pdf' }, 'update')).toEqual({ ok: true, value: { storageMode: 'stored', forcedType: 'pdf' } })
    expect(parseResourceFields({ storageMode: 'cached' }, 'update').ok).toBe(false)
    expect(parseResourceFields({ forcedType: 'wordpress' }, 'update').ok).toBe(false)
    expect(parseResourceFields({ credentials: null }, 'update')).toEqual({ ok: true, value: { credentials: null } })
    expect(parseResourceFields({ credentials: { cookie: 'x' } }, 'update')).toMatchObject({ ok: false, error: { field: 'credentials' } })
    expect(parseResourceFields({ focus: { mode: 'focused' } }, 'update')).toMatchObject({ ok: true, value: { focus: { mode: 'focused', strictness: 'balanced' } } })
    expect(parseResourceFields({ focus: { mode: 'focused', keep: 'k'.repeat(1001) } }, 'update')).toMatchObject({ ok: false, error: { field: 'focus.keep', code: 'bad_focus' } })
    expect(parseResourceFields({ focus: {} }, 'update')).toEqual({ ok: true, value: { focus: {} } })
  })

  test('keys the server owns are ignored, never written', () => {
    const parsed = parseResourceFields({
      ...CREATE, userId: 'other', user: { connect: { id: 'other' } }, activeJobId: 'j', sitemap: {}, generation: 9,
      typeOptions: { 'type.github.branch': 'x' }, summary: 'mine', summarySource: 'manual', settingsHash: 'f'.repeat(16),
    }, 'create')
    expect(parsed).toEqual({ ok: true, value: { name: 'Wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' } })
  })
})

describe('slug_rules (R-137, §6.4)', () => {
  test('a Resource ID is lowercase letters, digits and dashes from a letter or digit on', () => {
    for (const ok of ['hacktricks', 'my-blog-2', '0day', 'a']) {
      expect(parseResourceFields({ ...CREATE, slug: ok }, 'create')).toEqual({ ok: true, value: { ...CREATE, slug: ok } })
    }
    for (const bad of ['HackTricks', '-lead', 'with space', 'under_score', 'é', '', 'x'.repeat(201), 7]) {
      expect(parseResourceFields({ ...CREATE, slug: bad }, 'create'), String(bad)).toMatchObject({ ok: false, error: { field: 'slug', code: 'bad_slug' } })
    }
  })
})

describe('overrides (§6.1)', () => {
  test('both and resource keys are saved; list keys carry their mode', () => {
    const overrides = {
      'crawl.maxPages': 50, 'type.github.branch': 'dev', 'content.bodySelector': 'main',
      'crawl.excludePaths': { mode: 'replace', items: ['tag/'] }, 'summary.extraInstructions': { mode: 'add', text: 'List the classes.' },
    }
    expect(parseResourceFields({ overrides }, 'update')).toEqual({ ok: true, value: { overrides } })
  })

  test('user_only_refused: a user-only setting is never a resource override (R-133)', () => {
    for (const key of ['storage.userQuotaMb', 'storage.defaultMode', 'detection.enabledDetectors', 'summary.defaultModel', 'focus.alwaysSkip']) {
      expect(parseResourceFields({ overrides: { [key]: 1 } }, 'update'), key).toMatchObject({ ok: false, error: { field: `overrides.${key}`, code: 'user_only' } })
    }
  })

  test('a value out of range, a list without its mode, an unknown key: 400 naming the key', () => {
    expect(parseResourceFields({ overrides: { 'crawl.maxPages': 501 } }, 'update')).toMatchObject({
      ok: false, error: { field: 'overrides.crawl.maxPages', code: 'bad_value', error: 'crawl.maxPages must be an integer from 1 to 500' },
    })
    expect(parseResourceFields({ overrides: { 'crawl.excludePaths': ['tag/'] } }, 'update')).toMatchObject({ ok: false, error: { code: 'bad_mode' } })
    expect(parseResourceFields({ overrides: { 'nope': 1 } }, 'update')).toMatchObject({ ok: false, error: { code: 'unknown_key' } })
    expect(parseResourceFields({ overrides: [] }, 'update')).toMatchObject({ ok: false, error: { field: 'overrides' } })
  })

  test('typeOptionsOf keeps the type.* keys', () => {
    expect(typeOptionsOf({ 'type.cve.pathPatterns': ['{year}/{cve}.md'], 'crawl.maxPages': 9 })).toEqual({ 'type.cve.pathPatterns': ['{year}/{cve}.md'] })
  })
})

describe('presetKey (OQ-6)', () => {
  test('a known preset at creation; ignored on an edit; an unknown one refused', () => {
    expect(parseResourceFields({ ...CREATE, presetKey: 'hacktricks' }, 'create')).toEqual({ ok: true, value: { ...CREATE, presetKey: 'hacktricks' } })
    expect(parseResourceFields({ presetKey: 'hacktricks' }, 'update')).toEqual({ ok: true, value: {} })
    expect(parseResourceFields({ ...CREATE, presetKey: 'nope' }, 'create')).toMatchObject({ ok: false, error: { code: 'bad_preset' } })
  })
})

describe('forced_modes (R-082, R-142)', () => {
  test('a PDF is always Stored, a CVE database always Live, any other type is the person\'s choice', () => {
    expect(forcedStorageMode('pdf')).toBe('stored')
    expect(forcedStorageMode('cve-poc-db')).toBe('live')
    for (const t of ['', 'mkdocs-wiki', 'sphinx-docs', 'gitbook', 'github-repo', 'agentic-crawl']) expect(forcedStorageMode(t)).toBeNull()
  })
})

describe('the recommended mode per type (§4.5)', () => {
  test.each([
    ['agentic-crawl', null, 'stored'], ['github-repo', null, 'stored'], ['pdf', null, 'stored'], ['cve-poc-db', null, 'live'],
    ['mkdocs-wiki', null, 'live'], ['mkdocs-wiki', true, 'stored'], ['gitbook', false, 'live'], ['sphinx-docs', true, 'stored'], ['', null, 'live'],
  ] as const)('%s (fits the limits: %s) → %s', (type, fits, mode) => {
    expect(recommendedStorageMode(type, fits)).toBe(mode)
  })

  test("the account's default as a mode a row can hold", () => {
    expect(defaultStorageMode('recommended', 'github-repo')).toBe('stored')
    expect(defaultStorageMode('stored', '')).toBe('stored')
    expect(defaultStorageMode('live', 'agentic-crawl')).toBe('live')
    expect(defaultStorageMode('nonsense', 'agentic-crawl')).toBe('live')
  })
})

