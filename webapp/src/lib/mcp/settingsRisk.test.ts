/**
 * The MCP settings writers on a shared project (step 5.1b; SH-08, SH-28, OQ-23): update_recon_settings,
 * apply_recon_preset and update_project_scope judge a collaborator's change exactly as the project PUT
 * does (`classifyChange` → `settingsRefusal`, the same text), and refuse it before anything is written.
 * Recording an engagement authorization stays the owner's on both tools that record one.
 *
 * Today every one of these tools asks the owner's level (4.10: a token reaches a shared project's
 * write tools only once Phase 5 lowers their level, step 5.2b), so the classification is inert: the
 * first block proves it. The others "lift" the level the tool asks to the one 5.2b gives it (W for the
 * settings and the preset, M for the scope) through the real `mcpProjectAccess`, as a collaborator's
 * token will then reach them, and prove the per-key judgment that will stand behind it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  share: null as unknown,
  liftTo: null as string | null,
  row: {} as Record<string, unknown>,
  projectUpdateMany: vi.fn(),
  authCreate: vi.fn(),
  audit: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      findUnique: async () => ({ ...h.row }),
      updateMany: (...a: unknown[]) => h.projectUpdateMany(...a),
    },
    engagementAuthorization: {
      create: (...a: unknown[]) => h.authCreate(...a),
      findFirst: async () => null,
    },
    fireteamSettingsAudit: { createMany: async () => ({ count: 0 }) },
    jobQueue: { findMany: async () => [] },
    projectAuthProfile: { findUnique: async () => null },
    scanSchedule: { findMany: async () => [], updateMany: async () => ({ count: 0 }) },
    userSettings: { findUnique: async () => null },
    userLlmProvider: { count: async () => 0, findMany: async () => [] },
    userProjectPreset: { findFirst: async () => null },
    recordingSession: { findFirst: async () => null, update: async () => ({}) },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/authz/projectAccess', async () => {
  const actual = await vi.importActual<typeof import('@/lib/authz/projectAccess')>('@/lib/authz/projectAccess')
  return {
    ...actual,
    projectAccess: async ({ userId }: { userId: string }) =>
      (userId === 'owner' ? { project: { id: 'p1', userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' } : h.share),
  }
})
vi.mock('@/lib/mcpAuth', async () => {
  const actual = await vi.importActual<typeof import('@/lib/mcpAuth')>('@/lib/mcpAuth')
  return {
    ...actual,
    mcpProjectAccess: (token: never, projectId: unknown, needed: never = 'O' as never) =>
      actual.mcpProjectAccess(token, projectId, (h.liftTo ?? needed) as never),
  }
})
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: async () => null, describeScanWriters: async () => null }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/reconPresets/server', async () => {
  const actual = await vi.importActual<typeof import('@/lib/reconPresets/server')>('@/lib/reconPresets/server')
  return { ...actual, fetchBackendDefaults: async () => ({}) }
})
vi.mock('@/lib/graphSeedDomains', async orig => ({
  ...(await orig<typeof import('@/lib/graphSeedDomains')>()),
  seedProjectDomains: async () => true,
}))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
}))
vi.mock('@/lib/ipHostnamePolicy', () => ({ markOutOfPolicy: async () => true }))
vi.mock('@/lib/activationLock', async orig => ({
  ...(await orig<typeof import('@/lib/activationLock')>()),
  activationBusy: async () => false,
}))

import { McpLevelDenied, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { classifyChange, settingsRefusal } from '@/lib/authz/settingsRisk'
import { extractPresetSettings } from '@/lib/project-preset-utils'
import { validateDomainBatch } from '@/lib/domainBatch'
import { updateReconSettings } from './writeTools'
import { applyReconPreset } from './presetTools'
import { updateProjectScope } from './scopeTools'
import { attachEngagementAuthorization } from './engagementTools'
import type { McpContext } from './tools'
import type { ProjectAccess } from '@/lib/authz/projectAccess'

const SCOPES: McpScope[] = ['recon:read', 'recon:settings', 'preset:apply', 'project:rescope', 'engagement:authorize']
const ctx = (userId = 'collab'): McpContext => ({
  token: {
    tokenId: 't1', userId, tokenPrefix: 'rdmn_mcp_aaaaaaaa', name: 'agent', scopes: SCOPES,
    ...(userId === 'owner' ? {} : { sharedProjects: { allowlist: [] } }),
  } as McpContext['token'],
})

const P = { id: 'p1', userId: 'owner' }
const run = { runScans: false, useAgent: false, exploit: false }
const EDITOR = { project: P, level: 'write', toggles: { rawData: true, ...run, manage: false }, via: 'share' }
const CO_OWNER = { project: P, level: 'write', toggles: { rawData: true, ...run, manage: true }, via: 'share' }
const AT = new Date('2026-11-13T08:00:00.000Z')
const AUTH = { documentSha256: 'a'.repeat(64), documentKind: 'hackerone_program', issuedAt: '2026-01-01T00:00:00.000Z' }

/** The settings row: defaults plus the columns the cases change. */
const settingsRow = (over: Record<string, unknown> = {}) => ({
  ...extractPresetSettings({}),
  loadedPreset: null, ipMode: false, domainBatchMode: false, ipHostnameMode: 'ip_only',
  agentRequireToolConfirmation: true, jsReconValidateKeys: false, naabuRateLimit: 100,
  httpxCustomHeaders: ['X-Api-Key: rbac-fake-header-0002'],
  roeTimeWindowEnabled: false, roeTimeWindowDays: ['mon'],
  userId: 'owner', updatedAt: AT,
  ...over,
})

const batchRow = (hosts: string[]) => ({
  domainBatchMode: true, domainBatchHosts: hosts, domainBatchGroups: validateDomainBatch(hosts).groups,
  engagementKind: 'internal', ipMode: false, targetGuardrailEnabled: false, roeExcludedHosts: [],
  githubTargetOrg: '', githubTargetRepos: '', gvmScanTargets: 'both',
  supplyChainOrgName: '', supplyChainRepoUrl: '', supplyChainRepoRef: '', supplyChainRepoScope: '',
  userId: 'owner', updatedAt: AT,
})

async function refusalOf(p: Promise<unknown>): Promise<McpToolError> {
  const err = await p.then(() => null, (e: unknown) => e)
  expect(err).toBeInstanceOf(McpToolError)
  return err as McpToolError
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.share = EDITOR
  h.liftTo = null
  h.row = settingsRow()
  h.projectUpdateMany.mockResolvedValue({ count: 1 })
  h.authCreate.mockResolvedValue({ id: 'auth1', recordedAt: AT })
  h.audit.mockResolvedValue(undefined)
  h.fetch.mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) })
  vi.stubGlobal('fetch', h.fetch)
})

describe('today: every settings writer is the owner\'s (inert until step 5.2b)', () => {
  test('a write share with Manage reaches none of them; nothing is read for a decision or written', async () => {
    h.share = CO_OWNER
    await expect(updateReconSettings(ctx(), 'p1', { naabuRateLimit: 7 })).rejects.toBeInstanceOf(McpLevelDenied)
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'secret-hunter' })).rejects.toBeInstanceOf(McpLevelDenied)
    await expect(updateProjectScope(ctx(), { projectId: 'p1', changes: { githubTargetOrg: 'acme' } })).rejects.toBeInstanceOf(McpLevelDenied)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test("the owner's token writes a loosened gate and a secret as before", async () => {
    const out = await updateReconSettings(ctx('owner'), 'p1', { agentRequireToolConfirmation: false, naabuRateLimit: 7 })
    expect(out.changed).toEqual(['agentRequireToolConfirmation', 'naabuRateLimit'])
    expect(h.projectUpdateMany).toHaveBeenCalledTimes(1)
  })
})

describe('update_recon_settings, at the level 5.2b gives it (W)', () => {
  beforeEach(() => { h.liftTo = 'W' })

  test('an editor\'s ordinary change writes', async () => {
    await updateReconSettings(ctx(), 'p1', { naabuRateLimit: 7 })
    expect(h.projectUpdateMany.mock.calls[0][0].data).toEqual({ naabuRateLimit: 7 })
  })

  test('MCP write classified the same way: the PUT\'s refusal, word for word, and nothing written', async () => {
    const cases: Array<[ProjectAccess, Record<string, unknown>]> = [
      [EDITOR as unknown as ProjectAccess, { agentRequireToolConfirmation: false, naabuRateLimit: 7 }],
      [EDITOR as unknown as ProjectAccess, { jsReconValidateKeys: true }],
      [CO_OWNER as unknown as ProjectAccess, { agentRequireToolConfirmation: false }],
      [CO_OWNER as unknown as ProjectAccess, { httpxCustomHeaders: [] }],
      [EDITOR as unknown as ProjectAccess, { roeGlobalMaxRps: 5 }],
    ]
    for (const [who, change] of cases) {
      h.share = who
      __resetRateLimiter()
      const err = await refusalOf(updateReconSettings(ctx(), 'p1', change))
      const put = settingsRefusal(classifyChange(settingsRow(), change, who), 'project:settings')!
      expect(err.message, JSON.stringify(change)).toBe(put.error)
      expect(err.code).toBe('level_denied')
      expect(err.audit).toEqual({ refusedKeys: put.refused.map(r => r.key), needs: put.needs })
    }
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('an editor cannot loosen the dangerous-tool confirmation, named with its level', async () => {
    const err = await refusalOf(updateReconSettings(ctx(), 'p1', { agentRequireToolConfirmation: false }))
    expect(err.message).toMatch(/agentRequireToolConfirmation needs Manage and Exploitation & shells/)
    expect(err.message).toMatch(/\(project:settings\)/)
  })

  test('the window switch is read with the change: a scanning day added while it is on needs the owner', async () => {
    h.share = CO_OWNER
    h.row = settingsRow({ roeTimeWindowEnabled: true })
    const err = await refusalOf(updateReconSettings(ctx(), 'p1', { roeTimeWindowDays: ['mon', 'sun'] }))
    expect(err.message).toMatch(/roeTimeWindowDays needs the project's owner/)
    h.row = settingsRow()
    __resetRateLimiter()
    await expect(updateReconSettings(ctx(), 'p1', { roeTimeWindowDays: ['mon', 'sun'] })).resolves.toBeTruthy()
  })
})

describe('apply_recon_preset, at the level 5.2b gives it (W)', () => {
  beforeEach(() => { h.liftTo = 'W' })

  test('a preset that loosens a gate is refused at W, a dry run included, and nothing is written', async () => {
    for (const dryRun of [true, false]) {
      __resetRateLimiter()
      const err = await refusalOf(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'secret-hunter', dryRun }))
      expect(err.message).toMatch(/jsReconValidateKeys needs Manage/)
      expect(err.message).toMatch(/\(preset:apply\)/)
    }
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test("a preset that resets the owner's secret header list needs the owner", async () => {
    h.share = CO_OWNER
    const err = await refusalOf(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'secret-hunter' }))
    expect(err.message).toMatch(/httpxCustomHeaders needs the project's owner/)
  })

  test('a co-owner applies it when it leaves the secrets as stored', async () => {
    h.share = CO_OWNER
    h.row = settingsRow({ httpxCustomHeaders: extractPresetSettings({}).httpxCustomHeaders })
    const out = await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'secret-hunter' })
    expect(out.written).toBe(true)
  })
})

describe('update_project_scope, at the level 5.2b gives it (M)', () => {
  beforeEach(() => {
    h.liftTo = 'M'
    h.share = CO_OWNER
    h.row = batchRow(['a.example.com', 'b.example.com'])
  })

  test('a co-owner narrows the batch; adding a host needs the owner', async () => {
    await updateProjectScope(ctx(), { projectId: 'p1', changes: { domainBatchHosts: ['a.example.com'] } })
    expect(h.projectUpdateMany).toHaveBeenCalledTimes(1)
    __resetRateLimiter()
    h.projectUpdateMany.mockClear()
    const err = await refusalOf(updateProjectScope(ctx(), { projectId: 'p1', changes: { domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.com'] } }))
    expect(err.message).toMatch(/domainBatchHosts needs the project's owner \(widens the scope: adds c\.example\.com\)/)
    expect(err.message).toMatch(/\(project:rescope\)/)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('recording an authorization with it stays the owner\'s, whatever the level', async () => {
    await expect(updateProjectScope(ctx(), { projectId: 'p1', changes: { domainBatchHosts: ['a.example.com'] }, authorization: AUTH }))
      .rejects.toBeInstanceOf(McpLevelDenied)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
    expect(h.authCreate).not.toHaveBeenCalled()
  })
})

describe('attach_engagement_authorization stays the owner\'s', () => {
  test('a co-owner\'s token is refused at the level; the owner records it', async () => {
    h.share = CO_OWNER
    h.liftTo = 'M'
    await expect(attachEngagementAuthorization(ctx(), 'p1', AUTH)).rejects.toBeInstanceOf(McpLevelDenied)
    expect(h.authCreate).not.toHaveBeenCalled()
    await attachEngagementAuthorization(ctx('owner'), 'p1', AUTH)
    expect(h.authCreate).toHaveBeenCalledTimes(1)
  })
})
