/**
 * Instance LLM providers (step 6.11, GV-15, OQ-42): who may use one, what the agent receives, and the
 * twin rules the agent applies (agentic/llm_builder.py, agentic/tests/test_instance_providers.py).
 *
 * The provider store and the account loader are doubles; the capability resolution (assigned sets,
 * the instance default, Default member for an account never assigned, admin profiles, a disabled
 * account) is the real one.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/instanceProviders/instanceProviders.test.ts
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import type { InstanceLlmProviderRecord, PermissionSetProviderRow } from './rows'

type SetRow = { id: string; kind: string; name: string; permissions: string[] }
const h = vi.hoisted(() => ({
  providers: [] as InstanceLlmProviderRecord[],
  assignments: [] as PermissionSetProviderRow[],
  byoForbidden: false,
  readFails: false,
  principals: new Map<string, Record<string, unknown>>(),
  sets: new Map<string, SetRow>(),
  root: null as null | { rootUserId: string; rootConfirmedAt: Date | null },
}))
const store = vi.hoisted(() => ({
  readInstanceProviders: vi.fn(async (ids?: readonly string[]) =>
    h.providers.filter((p) => ids === undefined || ids.includes(p.id))),
  readProviderAssignments: vi.fn(async () => {
    if (h.readFails) throw Object.assign(new Error('db down'), { code: 'P1001' })
    return h.assignments
  }),
  readByoLlmForbidden: vi.fn(async () => h.byoForbidden),
}))
const loadPrincipal = vi.fn(async (id: string) => h.principals.get(id) ?? null)

vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: { findUnique: async () => (h.root ? { ...h.root, rootAssignedBy: 'host', defaultMemberSetId: null } : null) },
    user: { findUnique: async ({ where }: { where: { id: string } }) => (h.principals.has(where.id) ? { email: `${where.id}@example.com`, role: 'admin' } : null) },
    permissionSet: {
      findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
        where.id.in.flatMap((id) => (h.sets.has(id) ? [{ ...h.sets.get(id)! }] : [])),
    },
  },
}))
vi.mock('./store', () => store)
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  loadPrincipal: (id: string) => loadPrincipal(id),
}))

import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { agentProviderList, entitledInstanceProviders, entitledProviderSummaries, ownProvidersWithheld } from './entitlement'
import { instanceModelGroups } from './models'
import {
  INSTANCE_MODEL_PREFIX, INSTANCE_PROVIDER_KINDS, INSTANCE_ROW_TYPE, agentRowOf, isInstanceProviderKind, listingRowOf,
  splitInstanceModel,
} from './rows'

const KEY = 'sk-INSTANCE-CANARY-1234'
const RED: SetRow = { id: 'set-red', kind: 'member', name: 'Red team', permissions: ['project:create', 'self:llm_providers'] }
const BLUE: SetRow = { id: 'set-blue', kind: 'member', name: 'Blue team', permissions: ['project:create'] }

function provider(id: string, over: Partial<InstanceLlmProviderRecord> = {}): InstanceLlmProviderRecord {
  return {
    id, providerType: 'openai', name: `Shared ${id}`, apiKey: KEY, baseUrl: '', modelIdentifier: '',
    defaultHeaders: { 'X-Api-Key': 'header-secret' }, timeout: 120, temperature: 0, maxTokens: 16384, sslVerify: true,
    reasoningEnabled: false, reasoningEffort: 'high', awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '',
    awsBearerToken: '', createdAt: new Date(0), updatedAt: new Date(0), createdById: 'root-1', updatedById: null, ...over,
  }
}

function account(id: string, over: Record<string, unknown> = {}) {
  return {
    id, email: `${id}@example.com`, name: id, role: 'standard', status: 'active', sessionVersion: 0,
    mustChangePassword: false, adminProfileId: null, hasPassword: true, createdAt: new Date(0), lastLoginAt: null,
    legacyGrants: [], permissionSets: [], permissionOverrides: [], ...over,
  }
}

const GOVERNANCE_ON = { identity: true, permissions: true, governance: true }
const OWN = [{ id: 'own-1', providerType: 'anthropic', apiKey: 'sk-own', userId: 'alice' }]

beforeEach(() => {
  h.providers = [provider('inst-a'), provider('inst-b', { providerType: 'anthropic' }), provider('inst-c')]
  h.assignments = [{ setId: RED.id, providerId: 'inst-a' }, { setId: 'builtin:recon-operator', providerId: 'inst-b' }]
  h.byoForbidden = false
  h.readFails = false
  h.root = null
  h.sets = new Map([[RED.id, RED], [BLUE.id, BLUE]])
  h.principals = new Map(Object.entries({
    alice: account('alice', { permissionSets: [RED.id] }),
    bob: account('bob', { permissionSets: ['builtin:recon-operator', BLUE.id] }),
    carol: account('carol'),
    dave: account('dave', { status: 'disabled', permissionSets: [RED.id] }),
    analyst: account('analyst', { permissionSets: ['builtin:read-only-analyst'] }),
    admin: account('admin', { role: 'admin', adminProfileId: 'builtin:full-admin' }),
    root: account('root', { role: 'admin' }),
  }))
  for (const fn of Object.values(store)) fn.mockClear()
  loadPrincipal.mockClear()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  setFlagsForTests(GOVERNANCE_ON)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

const ids = (rows: { id: string }[]) => rows.map((r) => r.id)

describe('assigned only through sets', () => {
  test('a provider is offered to the holders of a set it is assigned to, and to nobody else', async () => {
    expect(ids(await entitledInstanceProviders('alice'))).toEqual(['inst-a'])
    expect(ids(await entitledInstanceProviders('bob'))).toEqual(['inst-b'])
    // Never assigned: the instance default (none here), so Default member, which no provider names.
    expect(await entitledInstanceProviders('carol')).toEqual([])
    // inst-c is assigned to no set: nobody, an admin included.
    expect(await entitledInstanceProviders('admin')).toEqual([])
  })

  test('the set a person resolves to counts: Default member, an admin profile', async () => {
    h.assignments = [{ setId: 'builtin:default-member', providerId: 'inst-c' }, { setId: 'builtin:full-admin', providerId: 'inst-a' }]
    expect(ids(await entitledInstanceProviders('carol'))).toEqual(['inst-c'])
    expect(ids(await entitledInstanceProviders('admin'))).toEqual(['inst-a', 'inst-c'])
    expect(await entitledInstanceProviders('alice')).toEqual([])
  })

  test('a disabled or gone account holds no set, so no provider', async () => {
    expect(await entitledInstanceProviders('dave')).toEqual([])
    expect(await entitledInstanceProviders('nobody')).toEqual([])
  })

  test('two sets naming the same provider offer it once', async () => {
    h.assignments.push({ setId: BLUE.id, providerId: 'inst-b' })
    expect(ids(await entitledInstanceProviders('bob'))).toEqual(['inst-b'])
    expect(store.readInstanceProviders).toHaveBeenCalledWith(['inst-b'])
  })

  test('no assignment at all: a member, an admin and an account never assigned get none', async () => {
    h.assignments = []
    for (const id of ['alice', 'admin', 'carol']) expect(await entitledInstanceProviders(id)).toEqual([])
  })

  test('a provider of a non-chat or unknown kind is never offered', async () => {
    h.providers = [provider('inst-a', { providerType: 'jev' }), provider('inst-b', { providerType: 'jev_openrouter' })]
    h.assignments = [{ setId: RED.id, providerId: 'inst-a' }, { setId: RED.id, providerId: 'inst-b' }]
    expect(await entitledInstanceProviders('alice')).toEqual([])
  })

  test('a failed read throws, never reads as "no provider"', async () => {
    h.readFails = true
    await expect(entitledInstanceProviders('alice')).rejects.toThrow('db down')
  })

  test('what a person sees of them: names and kinds, no key, endpoint or header', async () => {
    const summaries = await entitledProviderSummaries('alice')
    expect(summaries).toEqual([{ id: 'inst-a', name: 'Shared inst-a', providerType: 'openai' }])
    expect(JSON.stringify(summaries)).not.toContain(KEY)
  })
})

describe('the agent list', () => {
  test("owner's entitlements used on a shared project: the list is the owner's, whoever runs", async () => {
    // The agent fetches the project owner's list for every run of the project (C1). Bob holds the
    // recon-operator set and could use inst-b on his own projects, but on Alice's project the list is
    // Alice's: inst-a, never inst-b.
    const ownerList = await agentProviderList('alice', OWN)
    expect(ownerList.map((r) => (r as { id: string }).id)).toEqual(['own-1', 'inst-a'])
    const collaboratorList = await agentProviderList('bob', [])
    expect(collaboratorList.map((r) => (r as { id: string }).id)).toEqual(['inst-b'])
  })

  test('an instance row is marked, carries its key for the agent alone, and names the owner', async () => {
    const [row] = await agentProviderList('alice', [])
    expect(row).toMatchObject({ id: 'inst-a', providerType: INSTANCE_ROW_TYPE, instanceProviderType: 'openai', apiKey: KEY, userId: 'alice' })
    expect(row).not.toHaveProperty('createdById')
  })

  test('switch off → not offered or resolved: the own rows untouched, nothing read', async () => {
    for (const flags of [{}, { identity: true, permissions: true }]) {
      setFlagsForTests(flags)
      expect(await agentProviderList('alice', OWN)).toEqual(OWN)
      expect(await entitledInstanceProviders('alice')).toEqual([])
      expect(await ownProvidersWithheld('analyst')).toBe(false)
    }
    expect(store.readProviderAssignments).not.toHaveBeenCalled()
    expect(store.readByoLlmForbidden).not.toHaveBeenCalled()
    expect(loadPrincipal).not.toHaveBeenCalled()
  })

  test('byoLlmForbidden withholds the own rows of an account lacking self:llm_providers, and only those', async () => {
    h.byoForbidden = true
    h.assignments.push({ setId: 'builtin:read-only-analyst', providerId: 'inst-c' })
    expect(await ownProvidersWithheld('analyst')).toBe(true)
    expect((await agentProviderList('analyst', [{ id: 'own-x', providerType: 'openai' }])).map((r) => (r as { id: string }).id)).toEqual(['inst-c'])
    // Alice's Red team set holds self:llm_providers: her own rows stay.
    expect(await ownProvidersWithheld('alice')).toBe(false)
    expect((await agentProviderList('alice', OWN)).map((r) => (r as { id: string }).id)).toEqual(['own-1', 'inst-a'])
    h.byoForbidden = false
    expect(await ownProvidersWithheld('analyst')).toBe(false)
  })
})

describe('the model listing', () => {
  test('ids become instance/<providerId>/<model>; the loop group and loop ids are dropped', async () => {
    const listOne = vi.fn(async (rows: Record<string, unknown>[]) => ({
      [`X (${rows[0].name})`]: [{ id: rows[0].providerType === 'openai_compatible' ? `custom/${rows[0].id}` : 'gpt-5', name: 'model' }, { id: 'loop/mcp', name: 'loop' }],
      'Agent in the Loop': [{ id: 'loop/mcp', name: 'Agent in the Loop' }],
    }))
    const groups = await instanceModelGroups(
      [provider('inst-a'), provider('inst-v', { providerType: 'openai_compatible', name: 'vLLM' })], listOne)
    expect(groups).toEqual({
      'Instance: Shared inst-a': [{ id: 'instance/inst-a/gpt-5', name: 'model' }],
      'Instance: vLLM': [{ id: 'instance/inst-v/custom/inst-v', name: 'model' }],
    })
    // Each provider is listed alone, as a user row of its own kind.
    expect(listOne.mock.calls.map((c) => c[0].map((r) => [r.id, r.providerType]))).toEqual([[['inst-a', 'openai']], [['inst-v', 'openai_compatible']]])
  })

  test('two providers with the same name keep apart', async () => {
    const groups = await instanceModelGroups([provider('a', { name: 'Same' }), provider('b', { name: 'Same' })],
      async () => ({ G: [{ id: 'gpt-5' }] }))
    expect(Object.keys(groups)).toEqual(['Instance: Same', 'Instance: Same (b)'])
  })

  test('listingRowOf and agentRowOf never add the audit columns', () => {
    for (const row of [listingRowOf(provider('a')), agentRowOf(provider('a'), 'u')]) {
      expect(row).not.toHaveProperty('createdAt')
      expect(row).not.toHaveProperty('updatedById')
    }
  })
})

describe('model ids and the agent twin', () => {
  test('split', () => {
    expect(splitInstanceModel('instance/p1/gpt-5')).toEqual({ providerId: 'p1', model: 'gpt-5' })
    expect(splitInstanceModel('instance/p1/custom/p1')).toEqual({ providerId: 'p1', model: 'custom/p1' })
    for (const bad of ['instance/', 'instance/p1', 'instance/p1/', 'instance//gpt-5', 'gpt-5', 'custom/p1', null, 3]) {
      expect(splitInstanceModel(bad)).toBeNull()
    }
  })

  test('the kinds are chat kinds only', () => {
    expect(isInstanceProviderKind('openai_compatible')).toBe(true)
    for (const bad of ['jev', 'jev_openrouter', 'instance', 'bedrock_custom', '', undefined]) expect(isInstanceProviderKind(bad)).toBe(false)
  })

  test('the marker, the prefix and the keyed kinds match agentic/llm_builder.py', () => {
    const py = readFileSync(path.resolve(__dirname, '../../../../agentic/llm_builder.py'), 'utf8')
    expect(py).toContain(`INSTANCE_ROW_TYPE = "${INSTANCE_ROW_TYPE}"`)
    expect(py).toContain(`INSTANCE_MODEL_PREFIX = "${INSTANCE_MODEL_PREFIX}"`)
    const keyed = /_INSTANCE_KEYED_KINDS = \{([^}]*)\}/.exec(py)?.[1] ?? ''
    const pyKinds = [...keyed.matchAll(/"([a-z_]+)":/g)].map((m) => m[1])
    expect([...pyKinds, 'openai_compatible'].sort()).toEqual([...INSTANCE_PROVIDER_KINDS].sort())
  })
})

// Fix of the 6.11 review, finding 6: the Root branch of the capability resolution holds no set, so
// "through a set" never reached Root. Decision: Root (confirmed or chosen automatically) uses every
// instance provider, assigned or not: it holds every permission that is not a Root power, and using a
// provider is none; it is also who manages them.
describe('Root', () => {
  test.each([
    ['the confirmed Root', new Date(0)],
    ['a Root chosen automatically', null],
  ])('%s is offered every instance provider, assigned or not', async (_name, confirmedAt) => {
    h.root = { rootUserId: 'root', rootConfirmedAt: confirmedAt }
    expect(ids(await entitledInstanceProviders('root'))).toEqual(['inst-a', 'inst-b', 'inst-c'])
    h.assignments = []
    expect(ids(await entitledInstanceProviders('root'))).toEqual(['inst-a', 'inst-b', 'inst-c'])
  })

  test('only chat kinds, as for everyone; another admin still only through a set', async () => {
    h.root = { rootUserId: 'root', rootConfirmedAt: new Date(0) }
    h.providers.push(provider('inst-jev', { providerType: 'jev' }))
    expect(ids(await entitledInstanceProviders('root'))).toEqual(['inst-a', 'inst-b', 'inst-c'])
    expect(await entitledInstanceProviders('admin')).toEqual([])
  })

  test('switch off: Root too is offered none, and nothing is read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.root = { rootUserId: 'root', rootConfirmedAt: new Date(0) }
    expect(await entitledInstanceProviders('root')).toEqual([])
    expect(store.readInstanceProviders).not.toHaveBeenCalled()
  })
})
