/**
 * The webapp-side LLM features on a project spend the owner's credentials (step 5.6, C1; SH-32,
 * GV-12): report narratives, RoE parse, the command whisperer, the multi-mute suggestion and
 * text-to-cypher each send the agent the project owner's id and run on the owner's feature model (a
 * `custom/<providerId>` model resolves only against its owner's providers). A collaborator reaches
 * them only with Use AI agent (which counts only with the owner's consent) and each spend writes a
 * `credits.used` row naming them before the agent is called. The owner's use writes nothing.
 *
 * The guard is doubled with the context each person's access gives and applies the permission's own
 * level as the real guard does (`meetsLevel`); everything past it runs as the route does, the agent
 * behind `agentFetch` doubled.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

type Person = 'owner' | 'editorA' | 'editor' | 'coowner' | 'coownerA'

const h = vi.hoisted(() => ({
  person: 'owner' as Person,
  models: {} as Record<string, Record<string, string>>,
  audit: [] as Array<Record<string, unknown>>,
  agentFetch: vi.fn(),
  reportCreate: vi.fn(),
}))

const WRITE = { rawData: true, runScans: false, exploit: false, manage: false }
const ACCESS: Record<Person, Record<string, unknown>> = {
  owner: { level: 'owner', toggles: { rawData: true }, via: 'owner' },
  // A write share with Use AI agent, as projectAccess() answers it while the owner consents.
  editorA: { level: 'write', toggles: { ...WRITE, useAgent: true }, via: 'share' },
  // The same share without the consent (or without the toggle): Use AI agent reads false.
  editor: { level: 'write', toggles: { ...WRITE, useAgent: false }, via: 'share' },
  coowner: { level: 'write', toggles: { ...WRITE, useAgent: false, manage: true }, via: 'share' },
  coownerA: { level: 'write', toggles: { ...WRITE, useAgent: true, manage: true }, via: 'share' },
}
const userOf = (p: Person) => (p === 'owner' ? 'owner-1' : `${p}-1`)

vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  const { meetsLevel } = await import('@/lib/authz/projectAccess')
  const { PERMISSIONS } = await import('@/lib/authz/permissions')
  return {
    ...real,
    requirePermission: async (_request: Request, permission: keyof typeof PERMISSIONS, opts: { projectId?: string | null } = {}) => {
      const id = userOf(h.person)
      const access = opts.projectId ? { project: { id: opts.projectId, userId: 'owner-1' }, ...ACCESS[h.person] } : null
      const level = PERMISSIONS[permission].level
      if (access && level && !meetsLevel(access as never, level)) return real.forbiddenResponse(permission)
      return {
        session: { userId: id, role: 'standard' }, principal: { id, role: 'standard' }, actingAs: null,
        effective: { userId: id }, permission, capabilities: {}, access,
      }
    },
  }
})
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: userOf(h.person) }) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: async ({ where }: { where: { userId: string } }) =>
        (h.models[where.userId] ? { featureModels: h.models[where.userId] } : null),
    },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { h.audit.push(data); return data } },
    report: { create: (...a: unknown[]) => h.reportCreate(...a) },
  },
}))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error { cause_: unknown = null }
  return { agentFetch: (...a: unknown[]) => h.agentFetch(...a), AgentUnreachableError }
})
vi.mock('@/lib/report/reportData', () => ({
  gatherReportData: async () => {
    const empty = new Proxy({}, { get: () => [] })
    return {
      project: { name: 'Proj', targetDomain: 'example.com' }, metrics: { riskScore: 1, riskLabel: 'low' },
      graphOverview: empty, attackSurface: empty, vulnerabilities: { findings: [] },
      cveIntelligence: { cveChains: [], exploits: [], githubSecrets: [] }, attackChains: { chains: [], exploitSuccesses: [] },
      remediations: [], trufflehog: { findings: [] }, secrets: {}, jsRecon: { findings: [] }, supplyChain: { findings: [] },
      graphqlScan: { findings: [] }, vhostSni: { findings: [] }, tlsx: { findings: [], topIssuers: [] },
      webCachePoison: { findings: [] }, aiSurface: { findings: [], attackFindings: [] }, otx: { pulses: [] },
    }
  },
}))
vi.mock('@/lib/report/reportTemplate', () => ({ generateReportHtml: () => '<html></html>' }))
vi.mock('fs', async (orig) => ({ ...(await orig<typeof import('fs')>()), writeFileSync: vi.fn(), mkdirSync: vi.fn(), existsSync: () => true }))
vi.mock('@/lib/roe/review', async (orig) => ({
  ...(await orig<typeof import('@/lib/roe/review')>()),
  buildReplaceReview: async () => ({ changes: [], rejected: [], ignored: [], kept: [], implausible: false, modelChangeCount: 0 }),
}))
vi.mock('@/lib/roe/actor', () => ({ actingAdminId: async () => null }))
vi.mock('@/lib/activationLock', async (orig) => ({ ...(await orig<typeof import('@/lib/activationLock')>()), activationBusy: async () => false }))
vi.mock('@/lib/multiMute', async (orig) => ({ ...(await orig<typeof import('@/lib/multiMute')>()), exemptPairs: async () => [] }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { REGISTRY_DIGEST } from '@/lib/reconSettings/registryDigest.generated'
import { POST as reportsPost } from './projects/[id]/reports/route'
import { POST as roeParsePost } from './roe/parse/route'
import { POST as whispererPost } from './agent/command-whisperer/route'
import { POST as suggestPost } from './triage/multi-mute/suggest/route'
import { POST as textToCypherPost } from './agent/text-to-cypher/route'

const OWNER_MODEL = 'custom/prov-owner-1/llama'

const json = (url: string, body: unknown) => new NextRequest(url, {
  method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://x' }, body: JSON.stringify(body),
})

interface Feature {
  name: string
  featureId: string
  path: string
  /** Its permission is below Use AI agent, so the route asks W+A of a non-owner itself. */
  belowUseAgent: boolean
  /** The collaborator who reaches it with Use AI agent (RoE parse needs Manage as well). */
  allowed: Person
  /** The collaborators who reach the permission but not Use AI agent. */
  refused: Person[]
  call: () => Promise<Response>
  agentAnswer: () => Record<string, unknown>
}

const FEATURES: Feature[] = [
  {
    name: 'report narratives', featureId: 'report_narratives', path: '/api/report/summarize', belowUseAgent: true, allowed: 'editorA', refused: ['editor', 'coowner'],
    call: () => reportsPost(new NextRequest('http://x/api/projects/P1/reports', { method: 'POST' }), { params: Promise.resolve({ id: 'P1' }) }),
    agentAnswer: () => ({ executiveSummary: 'ok', model_used: OWNER_MODEL }),
  },
  {
    name: 'RoE parse', featureId: 'roe_parse', path: '/roe/parse', belowUseAgent: true, allowed: 'coownerA', refused: ['coowner'],
    call: () => {
      const form = new FormData()
      form.append('file', new File(['Scope: example.com only'], 'roe.txt', { type: 'text/plain' }))
      form.append('projectId', 'P1')
      return roeParsePost(new NextRequest('http://x/api/roe/parse', { method: 'POST', body: form }))
    },
    agentAnswer: () => ({ fields: {}, unknownKeys: [], registryDigest: REGISTRY_DIGEST, model_used: OWNER_MODEL }),
  },
  {
    name: 'command whisperer', featureId: 'command_whisperer', path: '/command-whisperer', belowUseAgent: false, allowed: 'editorA', refused: ['editor', 'coowner'],
    call: () => whispererPost(json('http://x/api/agent/command-whisperer', { prompt: 'list files', project_id: 'P1' })),
    agentAnswer: () => ({ command: 'ls', model_used: OWNER_MODEL }),
  },
  {
    name: 'multi-mute suggestion', featureId: 'multi_mute', path: '/graph/multi-mute/suggest', belowUseAgent: true, allowed: 'editorA', refused: ['editor', 'coowner'],
    call: () => suggestPost(json('http://x/api/triage/multi-mute/suggest', { projectId: 'P1', nodeId: 'finding-1' })),
    agentAnswer: () => ({ groups: [], model_used: OWNER_MODEL, multi_mute: 1 }),
  },
  {
    name: 'text-to-cypher', featureId: 'text_to_cypher', path: '/text-to-cypher', belowUseAgent: false, allowed: 'editorA', refused: ['editor', 'coowner'],
    call: () => textToCypherPost(json('http://x/api/agent/text-to-cypher', { question: 'hosts?', project_id: 'P1', user_id: 'someone-else' })),
    agentAnswer: () => ({ cypher: 'MATCH (n) RETURN n' }),
  },
]

const sent = () => JSON.parse((h.agentFetch.mock.calls[0][1] as RequestInit).body as string) as Record<string, unknown>
const spends = () => h.audit.filter((r) => r.action === 'credits.used')

beforeEach(() => {
  h.person = 'owner'
  h.audit = []
  // Each person has their own models; only the owner's may be used on the owner's project.
  h.models = {
    'owner-1': { report_narratives: OWNER_MODEL, roe_parse: OWNER_MODEL, command_whisperer: OWNER_MODEL, multi_mute: OWNER_MODEL },
    'editorA-1': { report_narratives: 'gpt-own', roe_parse: 'gpt-own', command_whisperer: 'gpt-own', multi_mute: 'gpt-own' },
  }
  h.reportCreate.mockReset().mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'r1', ...data }))
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

function answerWith(f: Feature) {
  h.agentFetch.mockReset().mockImplementation(async () => new Response(JSON.stringify(f.agentAnswer()), { status: 200 }))
}

describe.each(FEATURES)('$name', (f) => {
  test("each LLM feature uses the owner's user_id and the owner's feature model, for a collaborator too", async () => {
    answerWith(f)
    h.person = f.allowed
    const res = await f.call()
    expect(res.status).toBeLessThan(300)
    expect(h.agentFetch.mock.calls[0][0]).toBe(f.path)
    expect(sent().user_id).toBe('owner-1')
    // a custom/ model of the owner resolves: the owner's id travels with the owner's model.
    if (f.featureId !== 'text_to_cypher') expect(sent().model).toBe(OWNER_MODEL)
  })

  test('spend attributed to the actor: one credits.used row naming the collaborator, before the agent call', async () => {
    answerWith(f)
    h.person = f.allowed
    let rowsAtCall = -1
    h.agentFetch.mockImplementationOnce(async () => {
      rowsAtCall = spends().length
      return new Response(JSON.stringify(f.agentAnswer()), { status: 200 })
    })
    await f.call()
    expect(rowsAtCall).toBe(1)
    const actor = userOf(f.allowed)
    expect(spends()).toEqual([expect.objectContaining({
      actorId: actor, projectId: 'P1', targetId: 'P1', after: { feature: f.featureId, actor },
    })])
  })

  test("the owner's own use: the owner's model, no credits.used row", async () => {
    answerWith(f)
    const res = await f.call()
    expect(res.status).toBeLessThan(300)
    expect(sent().user_id).toBe('owner-1')
    expect(spends()).toEqual([])
  })

  test('each needs useAgent for a collaborator: without it nothing is spent or recorded', async () => {
    answerWith(f)
    for (const person of f.refused) {
      h.person = person
      const res = await f.call()
      if (f.featureId === 'report_narratives') {
        // A report itself is W: it is generated, without narratives, and nothing is spent.
        expect(res.status).toBe(201)
        expect((await res.json()).narrativesSkipped).toBe('use_agent_required')
      } else {
        expect(res.status).toBe(403)
        const body = await res.json()
        expect(body.code).toBe('forbidden')
        if (f.belowUseAgent) expect(body.level).toBe('W+A')
      }
    }
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(spends()).toEqual([])
  })

  test('no credits.used row, no spend', async () => {
    answerWith(f)
    h.person = f.allowed
    const prisma = (await import('@/lib/prisma')).default as unknown as { auditLog: { create: unknown } }
    const create = prisma.auditLog.create
    prisma.auditLog.create = async () => { throw new Error('audit table down') }
    vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const res = await f.call()
      expect(res.status).toBe(503)
      expect((await res.json()).code).toBe('spend_not_recorded')
      expect(h.agentFetch).not.toHaveBeenCalled()
    } finally {
      prisma.auditLog.create = create
    }
  })
})

describe('report narratives at W', () => {
  test("a collaborator with Use AI agent whose owner chose no model gets a report without narratives (the picker is the owner's)", async () => {
    answerWith(FEATURES[0])
    h.person = 'editorA'
    delete h.models['owner-1'].report_narratives
    const res = await FEATURES[0].call()
    expect(res.status).toBe(201)
    expect((await res.json()).narrativesSkipped).toBe('owner_model_required')
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(spends()).toEqual([])
  })

  test("the owner without a model is still asked to choose one (unchanged)", async () => {
    delete h.models['owner-1'].report_narratives
    const res = await FEATURES[0].call()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('model_required')
  })
})

describe('RoE parse for a project being created', () => {
  test("is the caller's own: the caller's model and id, no credits.used row", async () => {
    h.agentFetch.mockReset().mockImplementation(async () => new Response(JSON.stringify({
      fields: {}, unknownKeys: [], registryDigest: REGISTRY_DIGEST, model_used: 'gpt-own',
    }), { status: 200 }))
    h.person = 'editorA'
    const form = new FormData()
    form.append('file', new File(['Scope: example.com only'], 'roe.txt', { type: 'text/plain' }))
    const res = await roeParsePost(new NextRequest('http://x/api/roe/parse', { method: 'POST', body: form }))
    expect(res.status).toBe(200)
    expect(sent()).toMatchObject({ user_id: 'editorA-1', model: 'gpt-own' })
    expect(spends()).toEqual([])
  })
})
