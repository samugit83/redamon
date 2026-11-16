/**
 * The fields a person may write on a 2.0 resource.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { forcedStorageMode, parseResourceFields } from './fields'

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
    expect(parseResourceFields({ focus: { mode: 'focused' } }, 'update')).toMatchObject({ ok: false, error: { field: 'focus' } })
  })

  test('keys the server owns are ignored, never written', () => {
    const parsed = parseResourceFields({ ...CREATE, slug: 'evil', userId: 'other', user: { connect: { id: 'other' } }, activeJobId: 'j', sitemap: {}, generation: 9 }, 'create')
    expect(parsed).toEqual({ ok: true, value: { name: 'Wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' } })
  })
})

describe('forced_modes (R-082, R-142)', () => {
  test('a PDF is always Stored, a CVE database always Live, any other type is the person\'s choice', () => {
    expect(forcedStorageMode('pdf')).toBe('stored')
    expect(forcedStorageMode('cve-poc-db')).toBe('live')
    for (const t of ['', 'mkdocs-wiki', 'sphinx-docs', 'gitbook', 'github-repo', 'agentic-crawl']) expect(forcedStorageMode(t)).toBeNull()
  })
})
