/**
 * The fields a person may write on a 2.0 resource.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  applyCredentials, changedLoginFields, defaultStorageMode, forcedStorageMode, hasCredentials, parseResourceFields,
  recommendedStorageMode, typeOptionsOf,
} from './fields'

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
    expect(parseResourceFields({ credentials: { cookie: 'x' } }, 'update')).toMatchObject({ ok: true, value: { credentials: { cookie: { value: 'x' } } } })
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


describe('credentials (§6.6, T6.5, D-55)', () => {
  const parse = (credentials: unknown, mode: 'create' | 'update' = 'update') => parseResourceFields({ ...(mode === 'create' ? CREATE : {}), credentials }, mode)
  const STORED = {
    cookie: 'session=fake-session', headers: [{ name: 'X-Api-Key', value: 'fake-key-123' }], basic_auth: { username: 'bob', password: 'fake-pass' },
  }

  test('credentials: a cookie, headers and basic authentication are taken; null removes the login', () => {
    const login = { cookie: 'session=fake-session', headers: [{ name: 'X-Api-Key', value: 'k1' }], basic_auth: { username: 'bob', password: 'p:w' } }
    expect(parse(login)).toEqual({
      ok: true,
      value: { credentials: { cookie: { value: 'session=fake-session' }, headers: [{ name: 'X-Api-Key', value: { value: 'k1' } }], basicAuth: { username: 'bob', password: { value: 'p:w' } } } },
    })
    expect(parse(login, 'create')).toMatchObject({ ok: true, value: { credentials: { cookie: { value: 'session=fake-session' } } } })
    expect(parse(null)).toEqual({ ok: true, value: { credentials: null } })
    expect(parse(null, 'create')).toEqual({ ok: true, value: { name: 'Wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' } })
    expect(parse({ basic_auth: null })).toEqual({ ok: true, value: { credentials: { basicAuth: null } } })
  })

  test.each([
    ['not an object', 'cookie=1', 'credentials'],
    ['an unknown key', { cookies: 'a=1' }, 'credentials'],
    ['a cookie over 8 KB', { cookie: 'c'.repeat(8001) }, 'credentials.cookie'],
    ['a cookie with CR', { cookie: 'a=1\rX: y' }, 'credentials.cookie'],
    ['a cookie with LF', { cookie: 'a=1\nSet-Cookie: x' }, 'credentials.cookie'],
    ['a cookie with NUL', { cookie: 'a=1\u0000' }, 'credentials.cookie'],
    ['headers not a list', { headers: { 'X-A': '1' } }, 'credentials.headers'],
    ['21 headers', { headers: Array.from({ length: 21 }, (_, i) => ({ name: `X-H${i}`, value: 'v' })) }, 'credentials.headers'],
    ['a header name that is no HTTP token', { headers: [{ name: 'X Api', value: 'v' }] }, 'credentials.headers[0].name'],
    ['a header name with a colon', { headers: [{ name: 'X-A:', value: 'v' }] }, 'credentials.headers[0].name'],
    ['an empty header name', { headers: [{ name: '', value: 'v' }] }, 'credentials.headers[0].name'],
    ['a header value with LF', { headers: [{ name: 'X-A', value: 'v\nHost: evil' }] }, 'credentials.headers[0].value'],
    ['a header value with NUL', { headers: [{ name: 'X-A', value: 'v\u0000' }] }, 'credentials.headers[0].value'],
    ['a header value over 4 KB', { headers: [{ name: 'X-A', value: 'v'.repeat(4097) }] }, 'credentials.headers[0].value'],
    ['a header named twice', { headers: [{ name: 'X-A', value: '1' }, { name: 'x-a', value: '2' }] }, 'credentials.headers[1].name'],
    ['a basic username with a colon', { basic_auth: { username: 'bo:b', password: 'p' } }, 'credentials.basic_auth.username'],
    ['an empty basic username', { basic_auth: { username: '', password: 'p' } }, 'credentials.basic_auth.username'],
    ['a basic username with CR', { basic_auth: { username: 'bob\r', password: 'p' } }, 'credentials.basic_auth.username'],
    ['a basic password with LF', { basic_auth: { username: 'bob', password: 'p\n' } }, 'credentials.basic_auth.password'],
    ['a basic password not text', { basic_auth: { username: 'bob', password: 5 } }, 'credentials.basic_auth.password'],
  ])('refused: %s', (_why, credentials, field) => {
    expect(parse(credentials)).toMatchObject({ ok: false, error: { field, code: 'bad_credentials' } })
  })

  test.each(['Host', 'content-length', 'Transfer-Encoding', 'CONNECTION', 'Cookie', 'authorization'])('forbidden header name: %s', (name) => {
    expect(parse({ headers: [{ name, value: 'v' }] })).toMatchObject({ ok: false, error: { field: 'credentials.headers[0].name', code: 'bad_credentials' } })
  })

  test('"set" keeps the stored value; a new value replaces it; an empty one clears it', () => {
    const keepAll = parse({ cookie: 'set', headers: [{ name: 'x-api-key', value: 'set' }], basic_auth: { username: 'bob', password: 'set' } })
    expect(keepAll.ok).toBe(true)
    if (!keepAll.ok) return
    // A header is matched by its name whatever its case; it keeps the spelling the form sent.
    expect(applyCredentials(STORED, keepAll.value.credentials!)).toEqual({ ok: true, value: { ...STORED, headers: [{ name: 'x-api-key', value: 'fake-key-123' }] } })
    const changed = parse({ cookie: 'session=fake-new', headers: [], basic_auth: { username: 'alice', password: 'set' } })
    if (!changed.ok) throw new Error('parse')
    expect(applyCredentials(STORED, changed.value.credentials!)).toEqual({
      ok: true, value: { cookie: 'session=fake-new', headers: [], basic_auth: { username: 'alice', password: 'fake-pass' } },
    })
    const cleared = parse({ cookie: '' })
    if (!cleared.ok) throw new Error('parse')
    expect(applyCredentials(STORED, cleared.value.credentials!)).toEqual({ ok: true, value: { ...STORED, cookie: '' } })
  })

  test('absent parts are kept as stored', () => {
    const onlyCookie = parse({ cookie: 'session=fake-2' })
    if (!onlyCookie.ok) throw new Error('parse')
    expect(applyCredentials(STORED, onlyCookie.value.credentials!)).toEqual({ ok: true, value: { ...STORED, cookie: 'session=fake-2' } })
  })

  test('"set" with nothing stored to keep: refused for a header and a password; a cookie stays empty', () => {
    const header = parse({ headers: [{ name: 'X-New', value: 'set' }] })
    if (!header.ok) throw new Error('parse')
    expect(applyCredentials({}, header.value.credentials!)).toMatchObject({ ok: false, error: { field: 'credentials.headers[0].value', code: 'bad_credentials' } })
    const password = parse({ basic_auth: { username: 'bob', password: 'set' } })
    if (!password.ok) throw new Error('parse')
    expect(applyCredentials({}, password.value.credentials!)).toMatchObject({ ok: false, error: { field: 'credentials.basic_auth.password' } })
    const cookie = parse({ cookie: 'set' })
    if (!cookie.ok) throw new Error('parse')
    expect(applyCredentials({}, cookie.value.credentials!)).toEqual({ ok: true, value: {} })
  })

  test('has_login_recomputed: a login is any of the three; nothing set stores {}', () => {
    expect(hasCredentials({})).toBe(false)
    expect(hasCredentials({ cookie: '', headers: [], basic_auth: null })).toBe(false)
    expect(hasCredentials({ cookie: 'a=1', headers: [], basic_auth: null })).toBe(true)
    expect(hasCredentials({ cookie: '', headers: [{ name: 'X-A', value: '1' }], basic_auth: null })).toBe(true)
    expect(hasCredentials({ cookie: '', headers: [], basic_auth: { username: 'bob', password: '' } })).toBe(true)
    const emptied = parse({ cookie: '', headers: [], basic_auth: null })
    if (!emptied.ok) throw new Error('parse')
    expect(applyCredentials(STORED, emptied.value.credentials!)).toEqual({ ok: true, value: {} })
  })

  test('changedLoginFields names what changed, never a value', () => {
    const after = { cookie: 'session=fake-new', headers: [{ name: 'X-Api-Key', value: 'fake-key-123' }, { name: 'X-Team', value: 'fake-t' }], basic_auth: { username: 'bob', password: 'fake-pass-2' } }
    expect(changedLoginFields(STORED, after)).toEqual(['cookie', 'header:X-Team', 'basic_auth.password'])
    expect(changedLoginFields(STORED, {})).toEqual(['cookie', 'header:X-Api-Key', 'basic_auth.username', 'basic_auth.password'])
    expect(changedLoginFields(STORED, STORED)).toEqual([])
    expect(JSON.stringify(changedLoginFields(STORED, after))).not.toMatch(/fake/)
  })
})
