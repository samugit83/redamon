/**
 * Root's instance LLM provider routes (step 6.11, GV-15): /api/admin/llm-providers (GET, POST),
 * /[providerId] (PUT, DELETE) and /policy (PUT).
 *
 * - With RBAC_GOVERNANCE_ENABLED off none exists (404), before the session or anything is read.
 * - `instance:settings` is Root-only: the confirmed Root reads, and writes with its password; an
 *   admin or an unconfirmed Root is 403 `root_only`; a write is same-origin JSON.
 * - A provider key is never returned unmasked, never logged and never in an audit row's before or
 *   after; a masked value sent back keeps the stored one; a new endpoint needs the key typed again.
 * - Chat kinds only; an assignment names a set that exists; each write commits with its audit row.
 * - Until the schema holds the tables (the real store), a write answers 503 instance_providers_not_ready.
 *
 * The store, the Root rule, the audit writer and the database are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/llm-providers/route.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import type { InstanceLlmProviderRecord } from '@/lib/instanceProviders/rows'

const KEY = 'sk-INSTANCE-SECRET-abcd1234'
const AWS_SECRET = 'aws-SECRET-value-9876'
const HEADER_SECRET = 'header-SECRET-5555'
const SECRETS = [KEY, AWS_SECRET, HEADER_SECRET]

const h = vi.hoisted(() => ({
  session: { userId: 'root-1', role: 'admin' } as { userId: string; role: string } | null,
  standing: 'confirmed' as 'confirmed' | 'unconfirmed' | 'none',
  passwordOk: true,
  providers: new Map<string, unknown>(),
  assignments: [] as { setId: string; providerId: string }[],
  byo: false,
  storedSets: ['set-red'] as string[],
  realStore: false,
}))
const audits: Array<Record<string, unknown>> = []
const store = vi.hoisted(() => ({
  readInstanceProviders: vi.fn(async () => [...h.providers.values()]),
  readInstanceProvider: vi.fn(async (id: string) => h.providers.get(id) ?? null),
  readProviderAssignments: vi.fn(async (ids?: string[]) => h.assignments.filter((a) => !ids || ids.includes(a.providerId))),
  readByoLlmForbidden: vi.fn(async () => h.byo),
  createInstanceProvider: vi.fn(),
  updateInstanceProvider: vi.fn(),
  deleteInstanceProvider: vi.fn(),
  writeByoLlmForbidden: vi.fn(async (_tx: unknown, v: boolean) => { h.byo = v }),
}))

vi.mock('@/lib/instanceProviders/store', async (orig) => {
  const actual = (await orig()) as Record<string, unknown>
  return Object.fromEntries(Object.keys(actual).map((k) => [k, k in store
    ? (...a: unknown[]) => (h.realStore ? (actual[k] as (...x: unknown[]) => unknown)(...a) : (store as Record<string, (...x: unknown[]) => unknown>)[k](...a))
    : actual[k]]))
})
vi.mock('@/lib/session', async () => {
  const { NextResponse: R } = await import('next/server')
  return { requireSession: async () => h.session ?? R.json({ error: 'Unauthorized' }, { status: 401 }) }
})
vi.mock('@/lib/authz/rootPowers', async () => {
  const { NextResponse: R } = await import('next/server')
  const rootOnlyRefusal = (standing: string, error: string) => R.json({ error, code: 'root_only', standing }, { status: 403 })
  return {
    rootStanding: async () => h.standing,
    rootOnlyRefusal,
    requireRootPower: async (_r: unknown, _s: unknown, password: unknown) => {
      if (h.standing !== 'confirmed') return rootOnlyRefusal(h.standing, 'Only Root')
      return h.passwordOk && password === 'root-pass' ? null : R.json({ error: 'password', code: 'step_up_required' }, { status: 403 })
    },
  }
})
vi.mock('@/lib/authz/permissionAdmin', () => ({
  lockPermissions: vi.fn(async () => {}),
  personAuditEntry: async (_r: unknown, s: { userId: string }, entry: Record<string, unknown>) => ({ actorId: s.userId, ...entry, source: 'api' }),
}))
vi.mock('@/lib/audit', () => ({ writeAuditTx: vi.fn(async (_tx: unknown, entry: Record<string, unknown>) => { audits.push(entry) }) }))
vi.mock('@/lib/prisma', () => {
  const tx = {
    permissionSet: { findMany: async ({ where }: { where: { id: { in: string[] } } }) => where.id.in.filter((id) => h.storedSets.includes(id)).map((id) => ({ id })) },
  }
  return {
    default: {
      $transaction: async (fn: (t: unknown) => unknown) => fn(tx),
      permissionSet: { findMany: async () => [{ id: 'set-red', name: 'Red team', kind: 'member' }, { id: 'set-x', name: 'Ops', kind: 'admin' }] },
    },
  }
})

import { setFlagsForTests } from '@/lib/authz/flags'
import { GET, POST } from './route'
import { PUT, DELETE } from './[providerId]/route'
import { PUT as PUT_POLICY } from './policy/route'

function provider(over: Partial<InstanceLlmProviderRecord> = {}): InstanceLlmProviderRecord {
  return {
    id: 'inst-1', providerType: 'openai', name: 'Shared OpenAI', apiKey: KEY, baseUrl: '', modelIdentifier: '',
    defaultHeaders: { 'X-Api-Key': HEADER_SECRET }, timeout: 120, temperature: 0, maxTokens: 16384, sslVerify: true,
    reasoningEnabled: false, reasoningEffort: 'high', awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '',
    awsBearerToken: '', createdAt: new Date(0), updatedAt: new Date(0), createdById: 'root-1', updatedById: null, ...over,
  }
}

const URL_BASE = 'http://redamon.test/api/admin/llm-providers'
function req(path: string, method: string, body?: unknown, origin = 'http://redamon.test') {
  return new NextRequest(`${URL_BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', host: 'redamon.test', origin },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (providerId: string) => ({ params: Promise.resolve({ providerId }) })
const NEW = { providerType: 'openai', name: 'Shared OpenAI', apiKey: KEY, setIds: ['set-red', 'builtin:recon-operator'], stepUpPassword: 'root-pass' }
const noSecret = (value: unknown) => { for (const s of SECRETS) expect(JSON.stringify(value)).not.toContain(s) }

let logs: string[]
beforeEach(() => {
  h.session = { userId: 'root-1', role: 'admin' }
  h.standing = 'confirmed'
  h.passwordOk = true
  h.providers = new Map([['inst-1', provider()]])
  h.assignments = [{ setId: 'set-red', providerId: 'inst-1' }]
  h.byo = false
  h.storedSets = ['set-red']
  h.realStore = false
  audits.length = 0
  for (const fn of Object.values(store)) fn.mockClear()
  store.createInstanceProvider.mockImplementation(async (_tx: unknown, w: { data: object }) => provider({ ...w.data, id: 'inst-new' }))
  store.updateInstanceProvider.mockImplementation(async (_tx: unknown, id: string, w: { data: object }) => ({ provider: provider({ ...w.data, id }), setIdsBefore: [] }))
  store.deleteInstanceProvider.mockImplementation(async () => ['set-red'])
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  logs = []
  for (const level of ['log', 'info', 'warn', 'error'] as const) {
    vi.spyOn(console, level).mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')) })
  }
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
  noSecret(logs)
})

describe('switch off: the routes do not exist', () => {
  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('404 for every route, nothing read or written (%s)', async (_n, flags) => {
    setFlagsForTests(flags)
    const answers = [
      await GET(),
      await POST(req('', 'POST', NEW)),
      await PUT(req('/inst-1', 'PUT', { name: 'x', stepUpPassword: 'root-pass' }), params('inst-1')),
      await DELETE(req('/inst-1', 'DELETE', { stepUpPassword: 'root-pass' }), params('inst-1')),
      await PUT_POLICY(req('/policy', 'PUT', { byoLlmForbidden: true, stepUpPassword: 'root-pass' })),
    ]
    expect(answers.map((r) => r.status)).toEqual([404, 404, 404, 404, 404])
    for (const fn of Object.values(store)) expect(fn).not.toHaveBeenCalled()
    expect(audits).toEqual([])
  })
})

describe('the confirmed Root only', () => {
  test('no session: 401', async () => {
    h.session = null
    expect((await GET()).status).toBe(401)
    expect((await POST(req('', 'POST', NEW))).status).toBe(401)
  })

  test.each(['none', 'unconfirmed'] as const)('an account that is not the confirmed Root (%s): 403 root_only, nothing read or written', async (standing) => {
    h.standing = standing
    for (const res of [await GET(), await POST(req('', 'POST', NEW)), await PUT(req('/inst-1', 'PUT', { name: 'x', stepUpPassword: 'root-pass' }), params('inst-1'))]) {
      expect(res.status).toBe(403)
      expect((await res.json()).code).toBe('root_only')
    }
    expect(store.readInstanceProviders).not.toHaveBeenCalled()
    expect(store.createInstanceProvider).not.toHaveBeenCalled()
  })

  test('a write without Root\'s password is refused, nothing written', async () => {
    const res = await POST(req('', 'POST', { ...NEW, stepUpPassword: 'wrong' }))
    expect(res.status).toBe(403)
    expect(store.createInstanceProvider).not.toHaveBeenCalled()
  })

  test('a cross-origin write is refused before the password is checked', async () => {
    const res = await POST(req('', 'POST', NEW, 'http://evil.test'))
    expect(res.status).toBe(403)
    expect(store.createInstanceProvider).not.toHaveBeenCalled()
  })
})

describe('provider key never returned unmasked', () => {
  test('GET: every secret masked, the sets, the selectable sets and the policy', async () => {
    h.providers.set('inst-2', provider({ id: 'inst-2', providerType: 'bedrock', apiKey: '', defaultHeaders: {}, awsAccessKeyId: 'AKIAEXAMPLE0001', awsSecretKey: AWS_SECRET }))
    const res = await GET()
    expect(res.status).toBe(200)
    const body = await res.json()
    noSecret(body)
    expect(body.providers[0]).toMatchObject({ id: 'inst-1', apiKey: '••••••••1234', setIds: ['set-red'] })
    expect(body.providers[0].defaultHeaders['X-Api-Key']).toBe('••••••••5555')
    expect(body.providers[1]).toMatchObject({ awsSecretKey: '••••••••9876', awsAccessKeyId: '••••••••0001' })
    expect(body.sets.map((s: { id: string }) => s.id)).toEqual(expect.arrayContaining(['builtin:default-member', 'builtin:full-admin', 'set-red', 'set-x']))
    expect(body.byoLlmForbidden).toBe(false)
  })

  test('POST answers the new provider masked; its audit row holds no secret', async () => {
    const res = await POST(req('', 'POST', NEW))
    expect(res.status).toBe(201)
    const body = await res.json()
    noSecret(body)
    expect(body.setIds).toEqual(['builtin:recon-operator', 'set-red'])
    expect(store.createInstanceProvider).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      setIds: ['builtin:recon-operator', 'set-red'], actorId: 'root-1',
      data: expect.objectContaining({ providerType: 'openai', apiKey: KEY }),
    }))
    expect(audits).toEqual([expect.objectContaining({
      action: 'instance.llm_provider_created', targetId: 'inst-new', permission: 'instance:settings',
      after: { name: 'Shared OpenAI', providerType: 'openai', modelIdentifier: '', setIds: ['builtin:recon-operator', 'set-red'] },
    })])
    noSecret(audits)
  })

  test('PUT with the masked key and header keeps the stored ones; the audit row says a secret changed, never which value', async () => {
    const res = await PUT(req('/inst-1', 'PUT', {
      name: 'Renamed', apiKey: '••••••••1234', defaultHeaders: { 'X-Api-Key': '••••••••5555' }, setIds: ['builtin:full-admin'], stepUpPassword: 'root-pass',
    }), params('inst-1'))
    expect(res.status).toBe(200)
    noSecret(await res.json())
    const write = store.updateInstanceProvider.mock.calls[0][2] as { data: InstanceLlmProviderRecord; setIds: string[] }
    expect(write.data.apiKey).toBe(KEY)
    expect(write.data.defaultHeaders).toEqual({ 'X-Api-Key': HEADER_SECRET })
    expect(write.setIds).toEqual(['builtin:full-admin'])
    expect(audits[0]).toMatchObject({
      action: 'instance.llm_provider_updated',
      before: { name: 'Shared OpenAI', setIds: ['set-red'] },
      after: { name: 'Renamed', setIds: ['builtin:full-admin'], secretsChanged: false, endpointChanged: false },
    })
    noSecret(audits)
  })

  test('PUT with a new key: secretsChanged, the value nowhere but the store', async () => {
    await PUT(req('/inst-1', 'PUT', { apiKey: 'sk-NEW-KEY-7777', stepUpPassword: 'root-pass' }), params('inst-1'))
    expect((store.updateInstanceProvider.mock.calls[0][2] as { data: { apiKey: string } }).data.apiKey).toBe('sk-NEW-KEY-7777')
    expect(audits[0]).toMatchObject({ after: { secretsChanged: true } })
    expect(JSON.stringify(audits)).not.toContain('sk-NEW-KEY-7777')
    expect(logs.join('\n')).not.toContain('sk-NEW-KEY-7777')
  })

  test('PUT that sends no setIds keeps the assignments', async () => {
    await PUT(req('/inst-1', 'PUT', { name: 'Renamed', stepUpPassword: 'root-pass' }), params('inst-1'))
    expect((store.updateInstanceProvider.mock.calls[0][2] as { setIds: string[] }).setIds).toEqual(['set-red'])
  })

  test('a new endpoint or kind with the stored key kept is refused: the key must be typed again (HD-24)', async () => {
    h.providers.set('inst-1', provider({ providerType: 'openai_compatible', baseUrl: 'https://llm.example.com/v1', modelIdentifier: 'm' }))
    const res = await PUT(req('/inst-1', 'PUT', { baseUrl: 'https://other.example.com/v1', stepUpPassword: 'root-pass' }), params('inst-1'))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('secret_reentry_required')
    const kind = await PUT(req('/inst-1', 'PUT', { providerType: 'anthropic', stepUpPassword: 'root-pass' }), params('inst-1'))
    expect(kind.status).toBe(400)
    expect(store.updateInstanceProvider).not.toHaveBeenCalled()
  })

  test('DELETE removes the provider and its sets, audited without a secret', async () => {
    const res = await DELETE(req('/inst-1', 'DELETE', { stepUpPassword: 'root-pass' }), params('inst-1'))
    expect(res.status).toBe(200)
    expect(store.deleteInstanceProvider).toHaveBeenCalledWith(expect.anything(), 'inst-1')
    expect(audits[0]).toMatchObject({ action: 'instance.llm_provider_deleted', before: { setIds: ['set-red'] } })
    noSecret(audits)
  })

  test('an unknown provider: 404', async () => {
    expect((await PUT(req('/gone', 'PUT', { name: 'x', stepUpPassword: 'root-pass' }), params('gone'))).status).toBe(404)
    expect((await DELETE(req('/gone', 'DELETE', { stepUpPassword: 'root-pass' }), params('gone'))).status).toBe(404)
  })
})

describe('what a provider may be', () => {
  test.each([
    ['a Jev kind', { providerType: 'jev' }, 'non_chat_provider'],
    ['a Jev OpenRouter kind', { providerType: 'jev_openrouter' }, 'non_chat_provider'],
    ['an unknown kind', { providerType: 'instance' }, 'invalid_provider_type'],
    ['no name', { name: '  ' }, 'invalid_name'],
    ['no key', { apiKey: '' }, 'key_required'],
    ['an OpenAI-compatible without its endpoint', { providerType: 'openai_compatible', apiKey: '' }, 'invalid_field'],
    ['a cloud metadata endpoint', { providerType: 'openai_compatible', baseUrl: 'http://169.254.169.254/v1', modelIdentifier: 'm' }, 'invalid_base_url'],
    ['a set list that is not one', { setIds: 'set-red' }, 'invalid_set_ids'],
    ['a set that does not exist', { setIds: ['set-gone'] }, 'unknown_set'],
    ['a built-in set that does not exist', { setIds: ['builtin:nope'] }, 'unknown_set'],
    ['a bad temperature', { temperature: 9 }, 'invalid_field'],
  ])('%s → 400 %s, nothing written', async (_n, over, code) => {
    const res = await POST(req('', 'POST', { ...NEW, ...over }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe(code)
    expect(store.createInstanceProvider).not.toHaveBeenCalled()
    expect(audits).toEqual([])
  })

  test('a Bedrock provider takes its AWS credentials; an OpenAI-compatible one its endpoint and model', async () => {
    expect((await POST(req('', 'POST', { ...NEW, providerType: 'bedrock', apiKey: '', awsBearerToken: 'bedrock-token', awsRegion: 'eu-west-1' }))).status).toBe(201)
    expect((store.createInstanceProvider.mock.calls[0][1] as { data: object }).data).toMatchObject({ awsBearerToken: 'bedrock-token', awsRegion: 'eu-west-1', apiKey: '' })
    expect((await POST(req('', 'POST', { ...NEW, providerType: 'openai_compatible', apiKey: '', baseUrl: 'https://llm.example.com/v1', modelIdentifier: 'qwen' }))).status).toBe(201)
  })
})

describe('the policy', () => {
  test('byoLlmForbidden changes with Root\'s password and is audited; the same value writes nothing', async () => {
    const res = await PUT_POLICY(req('/policy', 'PUT', { byoLlmForbidden: true, stepUpPassword: 'root-pass' }))
    expect(res.status).toBe(200)
    expect(h.byo).toBe(true)
    expect(audits).toEqual([expect.objectContaining({ action: 'instance.llm_policy_changed', before: { byoLlmForbidden: false }, after: { byoLlmForbidden: true } })])
    await PUT_POLICY(req('/policy', 'PUT', { byoLlmForbidden: true, stepUpPassword: 'root-pass' }))
    expect(audits).toHaveLength(1)
    expect((await PUT_POLICY(req('/policy', 'PUT', { byoLlmForbidden: 'yes', stepUpPassword: 'root-pass' }))).status).toBe(400)
  })
})

describe('before the provider tables exist', () => {
  test('a write answers 503 instance_providers_not_ready and leaves no audit row', async () => {
    h.realStore = true
    const res = await POST(req('', 'POST', NEW))
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('instance_providers_not_ready')
    expect(audits).toEqual([])
    const view = await (await GET()).json()
    expect(view.providers).toEqual([])
  })
})

void NextResponse
