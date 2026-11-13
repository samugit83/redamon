/**
 * `sdk.llm.invoke` on a project shared with the token's user (step 5.10, C1; the plugin part of step
 * 5.6): the call spends the project owner's model choice and keys (the agent gets the owner's id and
 * model), only while the person's access holds Use AI agent (which counts only with the owner's
 * consent), and writes its `credits.used` row first, attributed to the person (no row, no call). The
 * plugin's daily cap and the usage stay the person's. The owner's own calls write no row.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  agentCalls: [] as { path: string; body: Record<string, unknown> }[],
  charges: [] as string[],
  usage: [] as unknown[][],
  audits: [] as Record<string, unknown>[],
  auditFails: false,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/agentFetch', () => ({
  AgentUnreachableError: class extends Error {},
  agentFetch: async (path: string, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body))
    h.agentCalls.push({ path, body })
    return Response.json({ content: 'ok', model_used: body.model, usage: { input_tokens: 1, output_tokens: 1 } })
  },
}))
vi.mock('./llmBudget', () => ({
  chargeLlmCall: vi.fn(async (pluginId: string, userId: string) => {
    h.charges.push(`${pluginId}:${userId}`)
    return { allowed: true, count: h.charges.length, cap: 100, key: 'llm:2026-11-13' }
  }),
  recordLlmUsage: vi.fn(async (...a: unknown[]) => void h.usage.push(a)),
}))
vi.mock('@/lib/audit', async (orig) => ({
  ...(await orig<typeof import('@/lib/audit')>()),
  writeAuditTx: vi.fn(async (_tx: unknown, entry: Record<string, unknown>) => {
    if (h.auditFails) throw new Error('audit table down')
    h.audits.push(entry)
  }),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => {
  const actual = await orig<typeof import('@/lib/authz/projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_PROJECT, BOB, CALL_SECRET, answer, gatewayRequest, seedWorld, token, type TokenInput } from './__testing__/gatewayHarness'
import { projectAccess, type ProjectAccess, type ProjectAccessToggles } from '@/lib/authz/projectAccess'
import { POST as llmInvoke } from '@/app/api/plugin-gateway/v1/llm/invoke/route'

const OWNER_MODEL = 'openai/owner-model'
const BOB_MODEL = 'anthropic/bob-model'
const policy = vi.mocked(projectAccess)
const editor = (toggles: Partial<ProjectAccessToggles> = {}): ProjectAccess =>
  Object.freeze({
    project: Object.freeze({ id: ALICE_PROJECT, userId: ALICE }),
    level: 'write',
    toggles: Object.freeze({ rawData: true, ...toggles }),
    via: 'share',
  }) as ProjectAccess

let db: FakePrisma
const BOB_TOKEN: TokenInput = { sub: BOB, prj: ALICE_PROJECT, ses: undefined, conv: undefined }
const hello = { messages: [{ role: 'user', content: 'Hello' }] }
const invoke = async (over: TokenInput) => answer(await llmInvoke(gatewayRequest('llm/invoke', hello, { token: await token(over) })))

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  db.seed('userSettings', [
    { userId: ALICE, featureModels: { 'plugin:echo': OWNER_MODEL } },
    { userId: BOB, featureModels: { 'plugin:echo': BOB_MODEL } },
  ])
  h.agentCalls = []
  h.charges = []
  h.usage = []
  h.audits = []
  h.auditFails = false
  policy.mockReset()
  policy.mockResolvedValue(editor({ useAgent: true }))
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe("a collaborator's call", () => {
  test("spends the owner's model and keys: the agent gets the owner's id and model, never the collaborator's", async () => {
    expect((await invoke(BOB_TOKEN)).status).toBe(200)
    expect(h.agentCalls).toEqual([
      { path: '/plugins/llm/invoke', body: { user_id: ALICE, plugin_id: 'echo', model: OWNER_MODEL, messages: hello.messages } },
    ])
  })

  test('writes one credits.used row before the call, naming the person, the project and the plugin feature', async () => {
    await invoke(BOB_TOKEN)
    expect(h.audits).toEqual([
      expect.objectContaining({
        action: 'credits.used',
        actorId: BOB,
        projectId: ALICE_PROJECT,
        permission: 'plugins:use',
        targetType: 'project',
        targetId: ALICE_PROJECT,
        after: { feature: 'plugin_llm', actor: BOB },
      }),
    ])
  })

  test("the plugin's daily cap and the usage stay the person's", async () => {
    await invoke(BOB_TOKEN)
    expect(h.charges).toEqual([`echo:${BOB}`])
    expect(h.usage[0].slice(0, 2)).toEqual(['echo', BOB])
  })

  test('no row, no call: 503 spend_not_recorded and the agent never asked', async () => {
    h.auditFails = true
    expect(await invoke(BOB_TOKEN)).toEqual({
      status: 503,
      body: { error: expect.stringMatching(/could not be recorded, so nothing was spent/), code: 'spend_not_recorded' },
    })
    expect(h.agentCalls).toEqual([])
  })

  test('the owner chose no model: 409 owner_model_required, though the collaborator chose one', async () => {
    await db.userSettings.update({ where: { userId: ALICE }, data: { featureModels: {} } })
    expect(await invoke(BOB_TOKEN)).toMatchObject({ status: 409, body: { code: 'owner_model_required', featureId: 'plugin:echo' } })
    expect(h.agentCalls).toEqual([])
    expect(h.audits).toEqual([])
  })

  test('without Use AI agent (no consent, or the toggle off): 404, nothing spent or recorded', async () => {
    policy.mockResolvedValue(editor({ useAgent: false }))
    expect(await invoke(BOB_TOKEN)).toMatchObject({ status: 404, body: { code: 'not_found' } })
    expect(h.agentCalls).toEqual([])
    expect(h.charges).toEqual([])
    expect(h.audits).toEqual([])
  })
})

describe("the owner's call", () => {
  test('spends their own model and writes no credits.used row', async () => {
    const actual = await vi.importActual<typeof import('@/lib/authz/projectAccess')>('@/lib/authz/projectAccess')
    policy.mockImplementation(actual.projectAccess)
    expect((await invoke({ ses: undefined, conv: undefined })).status).toBe(200)
    expect(h.agentCalls[0].body).toMatchObject({ user_id: ALICE, model: OWNER_MODEL })
    expect(h.audits).toEqual([])
    expect(h.charges).toEqual([`echo:${ALICE}`])
  })
})
