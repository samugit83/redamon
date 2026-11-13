/**
 * GET /api/projects/[id]/owner-catalog (step 5.7, SH-26): the project owner's catalogs for a
 * collaborator's project form, by name and presence only: the owner's LLM providers and Jev
 * configurations (id, name, type, whether a key is stored), attack skills (id, name, quarantined),
 * tradecraft resources (id, name, enabled), MCP servers (name, tools, default phases) and which API
 * keys are set. Never a value: no API key, token, password, base URL, header, endpoint, stdio command
 * or skill text reaches any caller, the owner included (the rows below hold one of each, the doubles
 * return whole rows whatever the select asks, and every answer is searched for them).
 *
 * `recon:read` on the project (R): the owner, a Read share with or without Raw data, an overseer; a
 * project the caller cannot see answers 404. `?models=1` adds the model options of the owner's chat
 * providers (the agent's /models, as /api/models lists them for one's own providers), for the
 * controls only the owner and a co-owner change: level M, else the 403 naming the level. With
 * RBAC_SHARING_ENABLED off the route does not exist (404 before anything is read, DV-30).
 *
 * Real guard, can() and projectAccess(); the session, Prisma and the agent are doubles
 * (sharedReads.ts, agentFetch).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), shares: new Map(), policy: { enabled: true } as unknown, models: {} as Record<string, unknown>, refused: vi.fn(),
  agent: vi.fn(),
}))
vi.mock('@/lib/session', () => ({ getAuthzIdentity: (...a: unknown[]) => h.identity(...a), mayActAs: async () => false }))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedReads')).sharedReadPrisma(h as never) }))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => h.agent(...a),
}))

import { GET } from './route'
import { AgentUnreachableError } from '@/lib/agentFetch'
import { setFlagsForTests } from '@/lib/authz/flags'
import {
  COLLABORATOR, OVERSEER, OWNER, RAW_COLLABORATOR, SHARED_PROJECT, STRANGER,
  clearCaches, endSharedReads, resetSharedReads, setFlags, signInAs,
} from '@/lib/authz/__testing__/sharedReads'
import { principal } from '@/lib/authz/__testing__/routePermissionCases'
import { OWNER_KEY_FIELDS } from '@/lib/ownerCatalog'

/** Every secret the rows below hold matches this; no answer may. */
const FAKE = /rbac-fake/

const CREATED = (n: number) => new Date(Date.UTC(2026, 10, 1, 0, n))

// The owner's provider rows, whole: a key in each auth column, an endpoint, a header.
const PROVIDERS = [
  { id: 'prov-openai', userId: OWNER, providerType: 'openai', name: 'Team OpenAI', apiKey: 'sk-rbac-fake-openai', baseUrl: '', modelIdentifier: '',
    defaultHeaders: {}, awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', createdAt: CREATED(1) },
  { id: 'prov-local', userId: OWNER, providerType: 'openai_compatible', name: 'Lab Ollama', apiKey: '', baseUrl: 'http://rbac-fake-base.internal:11434/v1',
    modelIdentifier: 'llama3.1', defaultHeaders: { 'X-Api-Key': 'rbac-fake-header' }, awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '',
    awsBearerToken: '', createdAt: CREATED(2) },
  { id: 'prov-bedrock', userId: OWNER, providerType: 'bedrock', name: 'AWS', apiKey: '', baseUrl: '', modelIdentifier: '', defaultHeaders: {},
    awsRegion: 'eu-west-1', awsAccessKeyId: 'AKIA-rbac-fake-id', awsSecretKey: 'rbac-fake-aws-secret', awsBearerToken: '', createdAt: CREATED(3) },
  { id: 'prov-jev', userId: OWNER, providerType: 'jev', name: 'TypeSafe AI (Jev)', apiKey: 'rbac-fake-jev-token', baseUrl: 'https://api.typesafe.ai',
    modelIdentifier: 'jev-1.13.0', defaultHeaders: {}, awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', createdAt: CREATED(4) },
  { id: 'prov-jev-or', userId: OWNER, providerType: 'jev_openrouter', name: 'OpenRouter (Jev)', apiKey: '', baseUrl: 'https://openrouter.ai/api/v1',
    modelIdentifier: 'typesafe/jev-1.13', defaultHeaders: {}, awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', createdAt: CREATED(5) },
]
// The collaborator's own rows: a catalog that showed any of these read the caller's account.
const CALLER_PROVIDER = { ...PROVIDERS[0], id: 'prov-bob', userId: COLLABORATOR, name: 'Bob OpenAI', apiKey: 'sk-rbac-fake-bob' }

const SKILLS = [
  { id: 'skill-new', userId: OWNER, name: 'GraphQL batching', description: 'rbac-fake-description', content: 'rbac-fake-skill-content',
    quarantinedAt: null, quarantineReason: null, createdAt: CREATED(9) },
  { id: 'skill-old', userId: OWNER, name: 'Legacy SSO bypass', description: null, content: 'rbac-fake-skill-content-2',
    quarantinedAt: new Date('2026-11-05T00:00:00Z'), quarantineReason: 'rbac-fake-quarantine-reason', createdAt: CREATED(8) },
]
const RESOURCES = [
  { id: 'tc-1', userId: OWNER, name: 'HackTricks', slug: 'hacktricks', url: 'https://rbac-fake-tradecraft.test/wiki', enabled: true,
    githubTokenOverride: 'ghp_rbac-fake-override', summary: 'rbac-fake-summary', sitemap: { a: 'rbac-fake-sitemap' }, createdAt: CREATED(1) },
  { id: 'tc-2', userId: OWNER, name: 'Internal PoCs', slug: 'internal-pocs', url: 'https://rbac-fake-pocs.internal/', enabled: false,
    githubTokenOverride: '', summary: '', sitemap: {}, createdAt: CREATED(2) },
]
// Every key the settings route masks, set on the owner's row except three, plus the instance tunnel credentials.
const UNSET_KEYS = new Set(['shodanApiKey', 'pdcpApiKey', 'trufflehogGitToken'])
const OWNER_SETTINGS: Record<string, unknown> = {
  userId: OWNER,
  ...Object.fromEntries(OWNER_KEY_FIELDS.map((f) => [f, UNSET_KEYS.has(f) ? '' : `rbac-fake-${f}`])),
  ngrokAuthtoken: 'rbac-fake-ngrok', chiselAuth: 'rbac-fake-chisel', chiselServerUrl: 'https://rbac-fake-chisel.test',
  githubEnterpriseHost: 'ghe.rbac-fake.test',
  mcpServers: [
    {
      id: 'intel', name: 'Intel MCP', description: 'rbac-fake-mcp-description', enabled: true, transport: 'streamable_http',
      url: 'https://rbac-fake-mcp.test/mcp?token=rbac-fake-url-token', headers: { Authorization: 'Bearer rbac-fake-header-token' },
      auth: { type: 'bearer', token: 'rbac-fake-bearer' }, default_phases: ['informational'], tags: ['rbac-fake-tag'],
      tools: [
        { name: 'intel_lookup', purpose: 'rbac-fake-purpose', when_to_use: 'rbac-fake-when', args_format: 'rbac-fake-args',
          description: 'rbac-fake-tool-description', default_phases: ['informational', 'exploitation'] },
        { name: 'intel_whois', purpose: 'p', when_to_use: 'w', args_format: 'a', description: 'd' },
      ],
    },
    {
      id: 'local-tools', name: 'Local tools', enabled: false, transport: 'stdio', command: '/opt/rbac-fake-cmd',
      args: ['--token', 'rbac-fake-arg'], env: { API_KEY: 'rbac-fake-env' }, cwd: '/rbac-fake-cwd', default_phases: [], tools: [],
    },
  ],
}
const CALLER_SETTINGS = { ...OWNER_SETTINGS, userId: COLLABORATOR, tavilyApiKey: 'rbac-fake-bob-tavily', mcpServers: [{ id: 'bob-srv', name: 'Bob server', tools: [] }] }

// The agent's model listing for the owner's chat providers.
const AGENT_MODELS = {
  'OpenAI (Team OpenAI)': [{ id: 'gpt-5', name: 'GPT-5', context_length: 400000, description: 'OpenAI' }],
  Custom: [{ id: 'custom/prov-local', name: 'Lab Ollama', context_length: null, description: 'Custom' }],
  'AWS Bedrock (AWS)': [],
}

const EXPECTED_CATALOG = {
  providers: [
    { id: 'prov-openai', name: 'Team OpenAI', type: 'openai', hasKey: true },
    { id: 'prov-local', name: 'Lab Ollama', type: 'openai_compatible', hasKey: false },
    { id: 'prov-bedrock', name: 'AWS', type: 'bedrock', hasKey: true },
  ],
  jevProviders: [
    { id: 'prov-jev', name: 'TypeSafe AI (Jev)', type: 'jev', hasKey: true },
    { id: 'prov-jev-or', name: 'OpenRouter (Jev)', type: 'jev_openrouter', hasKey: false },
  ],
  attackSkills: [
    { id: 'skill-new', name: 'GraphQL batching', quarantined: false },
    { id: 'skill-old', name: 'Legacy SSO bypass', quarantined: true },
  ],
  tradecraftResources: [
    { id: 'tc-1', name: 'HackTricks', enabled: true },
    { id: 'tc-2', name: 'Internal PoCs', enabled: false },
  ],
  mcpServers: [
    {
      id: 'intel', name: 'Intel MCP', enabled: true, default_phases: ['informational'],
      tools: [
        { name: 'intel_lookup', default_phases: ['informational', 'exploitation'] },
        { name: 'intel_whois', default_phases: [] },
      ],
    },
    { id: 'local-tools', name: 'Local tools', enabled: false, default_phases: [], tools: [] },
  ],
  keys: Object.fromEntries(OWNER_KEY_FIELDS.map((f) => [f, !UNSET_KEYS.has(f)])),
}

type FindArgs = { where: { userId: string }; select?: Record<string, unknown>; orderBy?: unknown }
const byOwner = <T extends { userId: string }>(rows: T[]) => vi.fn(async ({ where }: FindArgs) => rows.filter((r) => r.userId === where.userId))
const providerFind = byOwner([...PROVIDERS, CALLER_PROVIDER])
const skillFind = byOwner(SKILLS)
const resourceFind = byOwner(RESOURCES)
const settingsFind = vi.fn(async ({ where }: FindArgs) =>
  [OWNER_SETTINGS, CALLER_SETTINGS].find((s) => s.userId === where.userId) ?? null)

const CO_OWNER = 'erin'
const EDITOR = 'frank'

function signInAsMember(id: string): void {
  const p = principal(id)
  h.identity.mockResolvedValue({ session: { userId: p.id, role: p.role }, principal: p, actingAs: null })
}

/** Write sharing in force (the switch and Root's policy), with a Manage share and a write share without it. */
async function writeSharingInForce(): Promise<void> {
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  await clearCaches()
  h.policy = { enabled: true, maxLevel: 'write' }
  const write = { access: 'write', rawData: false, expiresAt: null, user: { status: 'active' }, runScans: false, useAgent: false, exploit: false }
  h.shares.set(`${SHARED_PROJECT}|${CO_OWNER}`, { ...write, manage: true })
  h.shares.set(`${SHARED_PROJECT}|${EDITOR}`, { ...write, manage: false })
}

const get = (query = '', id = SHARED_PROJECT) =>
  GET(new NextRequest(`http://localhost:3000/api/projects/${id}/owner-catalog${query}`), { params: Promise.resolve({ id }) })

const ownCatalogReads = () => [providerFind, skillFind, resourceFind, settingsFind].reduce((n, f) => n + f.mock.calls.length, 0)

beforeEach(async () => {
  await resetSharedReads(h as never)
  h.agent.mockReset()
  h.agent.mockResolvedValue(new Response(JSON.stringify(AGENT_MODELS), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  for (const f of [providerFind, skillFind, resourceFind, settingsFind]) f.mockClear()
  h.models.userLlmProvider = { findMany: providerFind }
  h.models.userAttackSkill = { findMany: skillFind }
  h.models.userTradecraftResource = { findMany: resourceFind }
  h.models.userSettings = { findUnique: settingsFind }
})
afterEach(async () => {
  await endSharedReads()
  vi.restoreAllMocks()
})

describe('GET /api/projects/[id]/owner-catalog with RBAC_SHARING_ENABLED off: the route does not exist (DV-30)', () => {
  test.each([
    ['every switch off', { identity: false, permissions: false, sharing: false }],
    ['identity + permissions on, sharing off', { identity: true, permissions: true, sharing: false }],
  ])('%s: 404 for the owner, a share holder, an overseer and no session; nothing read', async (_what, flags) => {
    await setFlags(flags)
    for (const who of [OWNER, COLLABORATOR, OVERSEER, null]) {
      if (who) signInAs(h as never, who)
      else h.identity.mockResolvedValue(null)
      const res = await get('?models=1')
      expect([who, res.status, await res.json()]).toEqual([who, 404, { error: 'Not found' }])
    }
    expect(h.identity).not.toHaveBeenCalled()
    expect(ownCatalogReads()).toBe(0)
    expect(h.agent).not.toHaveBeenCalled()
    expect(h.refused).not.toHaveBeenCalled()
  })
})

describe('GET /api/projects/[id]/owner-catalog: who reads it', () => {
  test('no session: 401, nothing read', async () => {
    h.identity.mockResolvedValue(null)
    expect((await get()).status).toBe(401)
    expect(ownCatalogReads()).toBe(0)
  })

  test('a stranger, and a project that does not exist: 404, the owner catalog never read', async () => {
    signInAs(h as never, STRANGER)
    expect((await get()).status).toBe(404)
    signInAs(h as never, OWNER)
    expect((await get('', 'P-missing')).status).toBe(404)
    expect(ownCatalogReads()).toBe(0)
  })

  test("the owner: 200 with the owner's catalog", async () => {
    signInAs(h as never, OWNER)
    const res = await get()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual(EXPECTED_CATALOG)
    expect(h.agent).not.toHaveBeenCalled()
  })

  test.each([
    ['a Read share without Raw data', COLLABORATOR],
    ['a Read share with Raw data', RAW_COLLABORATOR],
    ['an overseer (an admin reading by oversight)', OVERSEER],
  ])("%s: 200 with the owner's catalog, read from the owner's rows, never the caller's", async (_what, who) => {
    signInAs(h as never, who)
    const res = await get()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual(EXPECTED_CATALOG)
    for (const f of [providerFind, skillFind, resourceFind, settingsFind]) {
      expect(f.mock.calls.map(([a]) => (a as FindArgs).where)).toEqual([{ userId: OWNER }])
    }
    expect(h.refused).not.toHaveBeenCalled()
  })

  test('a co-owner (Read + Write with Manage) and a write share without Manage read it too', async () => {
    await writeSharingInForce()
    for (const who of [CO_OWNER, EDITOR]) {
      signInAsMember(who)
      const res = await get()
      expect([who, res.status]).toEqual([who, 200])
      expect(await res.json()).toEqual(EXPECTED_CATALOG)
    }
  })
})

describe('GET /api/projects/[id]/owner-catalog: no secret for any caller', () => {
  test('the reads name no endpoint, header, skill text or tradecraft token column', async () => {
    signInAs(h as never, COLLABORATOR)
    await get()
    const select = (f: { mock: { calls: unknown[][] } }) => (f.mock.calls[0][0] as FindArgs).select ?? {}
    for (const col of ['baseUrl', 'defaultHeaders', 'modelIdentifier']) expect(select(providerFind)).not.toHaveProperty(col)
    for (const col of ['content', 'description', 'quarantineReason']) expect(select(skillFind)).not.toHaveProperty(col)
    for (const col of ['url', 'githubTokenOverride', 'summary', 'sitemap']) expect(select(resourceFind)).not.toHaveProperty(col)
    const settingsSelect = (settingsFind.mock.calls[0][0] as FindArgs).select ?? {}
    for (const col of ['ngrokAuthtoken', 'chiselAuth', 'chiselServerUrl', 'githubEnterpriseHost', 'featureModels']) {
      expect(settingsSelect).not.toHaveProperty(col)
    }
  })

  test.each([
    ['the owner', OWNER, ''],
    ['the owner, with the model options', OWNER, '?models=1'],
    ['a Read share', COLLABORATOR, ''],
    ['a Read share with Raw data', RAW_COLLABORATOR, ''],
    ['an overseer', OVERSEER, ''],
  ])('%s: the answer holds no key, token, password, endpoint, header, command or skill text', async (_what, who, query) => {
    signInAs(h as never, who)
    const res = await get(query)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toMatch(FAKE)
    for (const value of ['sk-', 'AKIA', 'ghp_', 'Bearer', 'http://', 'https://']) expect(text).not.toContain(value)
  })

  test('a co-owner with the model options: no secret either', async () => {
    await writeSharingInForce()
    signInAsMember(CO_OWNER)
    const res = await get('?models=1')
    expect(res.status).toBe(200)
    expect(await res.text()).not.toMatch(FAKE)
  })
})

describe('GET /api/projects/[id]/owner-catalog?models=1: the owner\'s model options, level M', () => {
  test("the owner: the agent lists the owner's chat providers (never a Jev row, never the caller's), the answer adds `models`", async () => {
    signInAs(h as never, OWNER)
    const res = await get('?models=1')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ...EXPECTED_CATALOG, models: AGENT_MODELS })
    expect(h.agent).toHaveBeenCalledTimes(1)
    const [path, init] = h.agent.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/models')
    expect(init.method).toBe('POST')
    const sent = JSON.parse(String(init.body)) as { providers: Array<{ id: string; userId: string }> }
    expect(sent.providers.map((p) => p.id)).toEqual(['prov-openai', 'prov-local', 'prov-bedrock'])
  })

  test('a co-owner (Manage) gets them; a write share without Manage gets the 403 naming level M, the agent not asked', async () => {
    await writeSharingInForce()
    signInAsMember(CO_OWNER)
    const allowed = await get('?models=1')
    expect(allowed.status).toBe(200)
    expect((await allowed.json()).models).toEqual(AGENT_MODELS)
    h.agent.mockClear()
    signInAsMember(EDITOR)
    const refused = await get('?models=1')
    expect(refused.status).toBe(403)
    expect(await refused.json()).toEqual(expect.objectContaining({ code: 'forbidden', permission: 'recon:read', level: 'M' }))
    expect(h.agent).not.toHaveBeenCalled()
  })

  test.each([
    ['a Read share', COLLABORATOR],
    ['a Read share with Raw data', RAW_COLLABORATOR],
    ['an overseer', OVERSEER],
  ])('%s: 403 naming level M, neither the agent nor the catalog asked', async (_what, who) => {
    signInAs(h as never, who)
    const res = await get('?models=1')
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual(expect.objectContaining({ code: 'forbidden', permission: 'recon:read', level: 'M' }))
    expect(h.agent).not.toHaveBeenCalled()
    expect(ownCatalogReads()).toBe(0)
  })

  test('the agent answers with extra fields: only id, name, context length and description reach the browser', async () => {
    signInAs(h as never, OWNER)
    h.agent.mockResolvedValueOnce(new Response(JSON.stringify({
      'OpenAI (Team OpenAI)': [{ id: 'gpt-5', name: 'GPT-5', context_length: 400000, description: 'OpenAI', api_key: 'sk-rbac-fake-echo' }],
      Broken: 'rbac-fake-not-a-list',
      Mixed: [null, 'rbac-fake-string', { name: 'no id' }, { id: 'ok', name: 'Ok' }],
    }), { status: 200 }))
    const res = await get('?models=1')
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.models).toEqual({
      'OpenAI (Team OpenAI)': [{ id: 'gpt-5', name: 'GPT-5', context_length: 400000, description: 'OpenAI' }],
      Mixed: [{ id: 'ok', name: 'Ok', context_length: null, description: '' }],
    })
    expect(JSON.stringify(body)).not.toMatch(FAKE)
  })

  test('the agent unreachable: a coded 503, nothing of the owner in it', async () => {
    signInAs(h as never, OWNER)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agent.mockRejectedValueOnce(new AgentUnreachableError(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })))
    const res = await get('?models=1')
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual(expect.objectContaining({ code: 'agent_unreachable' }))
    expect(JSON.stringify(body)).not.toMatch(FAKE)
  })

  test('the agent failing: the coded upstream error, never its text', async () => {
    signInAs(h as never, OWNER)
    h.agent.mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'provider rejected sk-rbac-fake-openai' }), { status: 500 }))
    const res = await get('?models=1')
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual(expect.objectContaining({ code: 'agent_error', upstreamStatus: 500 }))
    expect(JSON.stringify(body)).not.toMatch(FAKE)
  })

  test('the agent answering something that is not a model list: a coded 502', async () => {
    signInAs(h as never, OWNER)
    h.agent.mockResolvedValueOnce(new Response(JSON.stringify(['rbac-fake']), { status: 200 }))
    const res = await get('?models=1')
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual(expect.objectContaining({ code: 'invalid_response' }))
  })
})

describe('GET /api/projects/[id]/owner-catalog: stored values the catalog must survive', () => {
  test('no settings row, no rows at all: empty lists and every key unset', async () => {
    signInAs(h as never, OWNER)
    h.models.userLlmProvider = { findMany: vi.fn(async () => []) }
    h.models.userAttackSkill = { findMany: vi.fn(async () => []) }
    h.models.userTradecraftResource = { findMany: vi.fn(async () => []) }
    h.models.userSettings = { findUnique: vi.fn(async () => null) }
    const res = await get()
    expect(await res.json()).toEqual({
      providers: [], jevProviders: [], attackSkills: [], tradecraftResources: [], mcpServers: [],
      keys: Object.fromEntries(OWNER_KEY_FIELDS.map((f) => [f, false])),
    })
  })

  test('MCP servers that are not a list, or entries that are not servers: skipped, never echoed', async () => {
    signInAs(h as never, OWNER)
    for (const mcpServers of [{ id: 'rbac-fake-object' }, 'rbac-fake-string', null]) {
      h.models.userSettings = { findUnique: vi.fn(async () => ({ ...OWNER_SETTINGS, mcpServers })) }
      expect((await (await get()).json()).mcpServers).toEqual([])
    }
    h.models.userSettings = { findUnique: vi.fn(async () => ({ ...OWNER_SETTINGS, mcpServers: [
      null, 'rbac-fake-entry', ['rbac-fake'], { name: 'no id', url: 'https://rbac-fake.test' },
      { id: 'srv', tools: 'rbac-fake-tools', default_phases: ['informational', 'rbac-fake-phase', 7] },
      { id: 'srv2', name: 42, tools: [null, { purpose: 'rbac-fake' }, { name: 'ok_tool', default_phases: 'rbac-fake' }] },
    ] })) }
    const body = await (await get()).json()
    expect(body.mcpServers).toEqual([
      { id: 'srv', name: 'srv', enabled: true, default_phases: ['informational'], tools: [] },
      { id: 'srv2', name: 'srv2', enabled: true, default_phases: [], tools: [{ name: 'ok_tool', default_phases: [] }] },
    ])
    expect(JSON.stringify(body)).not.toMatch(FAKE)
  })

  test('a failed read: the coded 500 of the route, never the error text', async () => {
    signInAs(h as never, OWNER)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.models.userSettings = { findUnique: vi.fn(async () => { throw Object.assign(new Error('rbac-fake db text'), { code: 'P1001' }) }) }
    const res = await get()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: "Could not read the project owner's catalogs", code: 'P1001' })
  })
})
