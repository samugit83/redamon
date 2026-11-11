/**
 * The recon preset tools.
 *
 * What can go wrong here is not a wrong value but a wrong DOOR: another user's
 * preset read through a guessed id, a built-in rewritten, an apply that lands
 * while the in-app agent is reading settings, or a write that silently loses a
 * concurrent one. Each test below pins one of those.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  presetFindFirst: vi.fn(),
  presetFindMany: vi.fn(),
  presetCount: vi.fn(),
  presetCreate: vi.fn(),
  presetUpdateMany: vi.fn(),
  presetDeleteMany: vi.fn(),
  projectFind: vi.fn(),
  projectUpdateMany: vi.fn(),
  fireteamAudit: vi.fn(),
  jobs: vi.fn(),
  schedules: vi.fn(),
  userSettings: vi.fn(),
  live: vi.fn(),
  defaults: vi.fn(),
  audit: vi.fn(),
  renameBadges: vi.fn(),
  clearBadges: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    userProjectPreset: {
      findFirst: (...a: unknown[]) => h.presetFindFirst(...a),
      findMany: (...a: unknown[]) => h.presetFindMany(...a),
      count: (...a: unknown[]) => h.presetCount(...a),
      create: (...a: unknown[]) => h.presetCreate(...a),
      updateMany: (...a: unknown[]) => h.presetUpdateMany(...a),
      deleteMany: (...a: unknown[]) => h.presetDeleteMany(...a),
    },
    project: {
      findUnique: (...a: unknown[]) => h.projectFind(...a),
      updateMany: (...a: unknown[]) => h.projectUpdateMany(...a),
    },
    fireteamSettingsAudit: { createMany: (...a: unknown[]) => h.fireteamAudit(...a) },
    jobQueue: { findMany: (...a: unknown[]) => h.jobs(...a) },
    scanSchedule: { findMany: (...a: unknown[]) => h.schedules(...a) },
    userSettings: { findUnique: (...a: unknown[]) => h.userSettings(...a) },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/reconPresets/badges', () => ({
  renamePresetBadges: (...a: unknown[]) => h.renameBadges(...a),
  clearPresetBadges: (...a: unknown[]) => h.clearBadges(...a),
}))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: (...a: unknown[]) => h.live(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/reconPresets/server', async () => {
  const actual = await vi.importActual<typeof import('@/lib/reconPresets/server')>('@/lib/reconPresets/server')
  return { ...actual, fetchBackendDefaults: () => h.defaults() }
})

import { McpScopeError, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { DefaultsUnavailable, MAX_USER_PRESETS } from '@/lib/reconPresets/server'
import { extractPresetSettings } from '@/lib/project-preset-utils'
import {
  applyReconPreset,
  createReconPreset,
  deleteReconPreset,
  listReconPresets,
  updateReconPreset,
} from './presetTools'
import type { McpContext } from './tools'

const ALL: McpScope[] = ['recon:read', 'preset:write', 'preset:apply']
const ctx = (scopes: McpScope[] = ALL): McpContext => ({
  token: { tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa', name: 'agent', scopes },
})

const PRESET_AT = new Date('2026-09-29T09:00:00.000Z')
const PROJECT_AT = new Date('2026-09-29T08:00:00.000Z')

const userPreset = (over: Record<string, unknown> = {}) => ({
  id: 'up1', name: 'My preset', description: '', settings: { katanaDepth: 3, naabuEnabled: false },
  updatedAt: PRESET_AT, createdVia: 'ui', updatedVia: 'ui', lastWriterTokenPrefix: null,
  ...over,
})

/** A project row at its defaults, with the fields apply reads beside them. */
const projectRow = (over: Record<string, unknown> = {}) => ({
  ...extractPresetSettings({}),
  loadedPreset: null, ipMode: false, domainBatchMode: false,
  updatedAt: PROJECT_AT,
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.presetFindFirst.mockResolvedValue(userPreset())
  h.presetFindMany.mockResolvedValue([])
  h.presetCount.mockResolvedValue(0)
  h.presetCreate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({
    id: 'new1', name: data.name, updatedAt: PRESET_AT,
  }))
  h.presetUpdateMany.mockResolvedValue({ count: 1 })
  h.presetDeleteMany.mockResolvedValue({ count: 1 })
  h.renameBadges.mockResolvedValue(0)
  h.clearBadges.mockResolvedValue(0)
  h.projectFind.mockImplementation(async (args: { select?: Record<string, unknown> }) =>
    args.select && Object.keys(args.select).length === 2 && 'userId' in args.select
      ? { id: 'p1', userId: 'owner' }
      : projectRow())
  h.projectUpdateMany.mockResolvedValue({ count: 1 })
  h.jobs.mockResolvedValue([])
  h.schedules.mockResolvedValue([])
  h.userSettings.mockResolvedValue(null)
  h.live.mockResolvedValue(null)
  h.defaults.mockResolvedValue({})
  h.audit.mockResolvedValue(undefined)
})

// --- scopes -----------------------------------------------------------------------------------

describe('each tool enforces its own scope', () => {
  test('recon:read is enough to list', async () => {
    await expect(listReconPresets(ctx(['recon:read']))).resolves.toBeTruthy()
    await expect(listReconPresets(ctx(['preset:write']))).rejects.toBeInstanceOf(McpScopeError)
  })

  test('create, update and delete need preset:write; apply needs preset:apply', async () => {
    const readOnly = ctx(['recon:read', 'preset:apply'])
    await expect(createReconPreset(readOnly, { name: 'x', fromPresetId: 'stealth-recon' })).rejects.toThrow(/preset:write/)
    await expect(updateReconPreset(readOnly, { presetId: 'up1', name: 'y' })).rejects.toThrow(/preset:write/)
    await expect(deleteReconPreset(readOnly, { presetId: 'up1' })).rejects.toThrow(/preset:write/)
    await expect(applyReconPreset(ctx(['recon:read', 'preset:write']), { projectId: 'p1', presetId: 'stealth-recon' }))
      .rejects.toThrow(/preset:apply/)
  })
})

// --- list -------------------------------------------------------------------------------------

describe('list_recon_presets', () => {
  test('lists the built-ins and the user\'s own presets, scoped to the user', async () => {
    h.presetFindMany.mockResolvedValue([userPreset({ updatedVia: 'mcp', lastWriterTokenPrefix: 'rdmn_mcp_aaaaaaaa' })])
    const r = await listReconPresets(ctx()) as { builtin: { id: string }[]; user: Record<string, unknown>[] }
    expect(r.builtin.length).toBeGreaterThan(20)
    expect(r.user[0]).toMatchObject({ id: 'up1', source: 'user', keyCount: 2, updatedVia: 'mcp' })
    expect(h.presetFindMany.mock.calls[0][0].where).toEqual({ userId: 'owner' })
  })

  test('a database failure says unavailable, never an empty list', async () => {
    h.presetFindMany.mockRejectedValue(new Error('db down'))
    const r = await listReconPresets(ctx()) as { builtin: unknown[]; user: unknown }
    expect(r.builtin.length).toBeGreaterThan(20)
    expect(r.user).toMatchObject({ status: 'unavailable' })
  })

  test('the list carries no values and no applicability, and the notes say apply replaces', async () => {
    const r = await listReconPresets(ctx())
    const text = JSON.stringify(r)
    expect(text).not.toContain('"parameters"')
    expect(text).not.toContain('applicability')
    expect(text).not.toContain('stealthCritical')
    expect((r as { notes: string[] }).notes.join(' ')).toMatch(/apply_recon_preset.*REPLACES/)
  })

  test('includeSettings returns a preset\'s values, projected, and only with a presetId', async () => {
    h.presetFindFirst.mockResolvedValue(userPreset({ settings: { katanaDepth: 3, targetDomain: 'x.example.com' } }))
    const r = await listReconPresets(ctx(), { presetId: 'up1', includeSettings: true }) as { preset: { settings: unknown } }
    expect(r.preset.settings).toEqual({ katanaDepth: 3 })
    await expect(listReconPresets(ctx(), { includeSettings: true })).rejects.toMatchObject({ code: 'bad_args' })
  })

  test('a built-in by id returns its full description', async () => {
    const r = await listReconPresets(ctx(), { presetId: 'stealth-recon' }) as { preset: { fullDescription: string } }
    expect(r.preset.fullDescription.length).toBeGreaterThan(200)
  })

  test('another user\'s preset reads exactly like a missing one', async () => {
    h.presetFindFirst.mockResolvedValue(null)
    const foreign = await listReconPresets(ctx(), { presetId: 'theirs' }).catch(e => e)
    const missing = await listReconPresets(ctx(), { presetId: 'nope' }).catch(e => e)
    expect(foreign.code).toBe('not_found')
    expect(foreign.message.replace('theirs', 'X')).toBe(missing.message.replace('nope', 'X'))
    expect(h.presetFindFirst.mock.calls[0][0].where).toEqual({ id: 'theirs', userId: 'owner' })
  })
})

// --- create -----------------------------------------------------------------------------------

describe('create_recon_preset', () => {
  test('copies a built-in, with provenance and the writing token recorded', async () => {
    const r = await createReconPreset(ctx(), { name: '  Stealthy  ', fromPresetId: 'stealth-recon' })
    expect(r.presetId).toBe('new1')
    const data = h.presetCreate.mock.calls[0][0].data
    expect(data).toMatchObject({
      userId: 'owner', name: 'Stealthy', createdVia: 'mcp', updatedVia: 'mcp',
      lastWriterTokenPrefix: 'rdmn_mcp_aaaaaaaa',
    })
    expect(data.settings.reconPresetId).toBe('stealth-recon')
  })

  test('exactly one source', async () => {
    await expect(createReconPreset(ctx(), { name: 'x' })).rejects.toMatchObject({ code: 'bad_args' })
    await expect(createReconPreset(ctx(), { name: 'x', settings: { katanaDepth: 2 }, fromPresetId: 'stealth-recon' }))
      .rejects.toMatchObject({ code: 'bad_args' })
  })

  test('settings are validated like a project write, naming the key', async () => {
    await expect(createReconPreset(ctx(), { name: 'x', settings: { targetDomain: 'x.example.com' } }))
      .rejects.toMatchObject({ code: 'setting_rejected', audit: { rejectedKey: 'targetDomain' } })
    expect(h.presetCreate).not.toHaveBeenCalled()
  })

  test('a duplicate name, ignoring case, is preset_exists with the existing id', async () => {
    h.presetFindMany.mockResolvedValue([{ id: 'up1', name: 'My Preset' }])
    await expect(createReconPreset(ctx(), { name: 'my preset', settings: { katanaDepth: 2 } }))
      .rejects.toMatchObject({ code: 'preset_exists', audit: { existingPresetId: 'up1' } })
  })

  test('the per-user limit is enforced', async () => {
    h.presetCount.mockResolvedValue(MAX_USER_PRESETS)
    await expect(createReconPreset(ctx(), { name: 'x', settings: { katanaDepth: 2 } }))
      .rejects.toMatchObject({ code: 'preset_limit' })
  })

  test('a capture from a project leaves out upload paths only that project may read', async () => {
    h.projectFind.mockImplementation(async (args: { select?: Record<string, unknown> }) =>
      args.select && 'userId' in args.select && Object.keys(args.select).length === 2
        ? { id: 'p1', userId: 'owner' }
        : { ...extractPresetSettings({}), ffufWordlist: '/app/recon/wordlists/p1/mine.txt' })
    const r = await createReconPreset(ctx(), { name: 'captured', fromProjectId: 'p1' })
    expect(r.notCaptured).toContain('ffufWordlist')
    expect(h.presetCreate.mock.calls[0][0].data.settings).not.toHaveProperty('ffufWordlist')
  })
})

// --- update and delete ------------------------------------------------------------------------

describe('update_recon_preset', () => {
  test('a built-in is immutable', async () => {
    await expect(updateReconPreset(ctx(), { presetId: 'stealth-recon', name: 'x' }))
      .rejects.toMatchObject({ code: 'builtin_immutable' })
  })

  test('merges, removes keys, and writes with a compare-and-swap', async () => {
    const r = await updateReconPreset(ctx(), { presetId: 'up1', settings: { katanaDepth: 4 }, removeKeys: ['naabuEnabled'] })
    const call = h.presetUpdateMany.mock.calls[0][0]
    expect(call.where).toEqual({ id: 'up1', userId: 'owner', updatedAt: PRESET_AT })
    expect(call.data.settings).toEqual({ katanaDepth: 4 })
    expect(call.data).toMatchObject({ updatedVia: 'mcp', lastWriterTokenPrefix: 'rdmn_mcp_aaaaaaaa' })
    expect(r.changedCount).toBe(2)
  })

  test('a call that changes nothing is refused', async () => {
    await expect(updateReconPreset(ctx(), { presetId: 'up1', settings: { katanaDepth: 3 } }))
      .rejects.toMatchObject({ code: 'bad_args' })
  })

  test('a rename onto another preset\'s name is preset_exists', async () => {
    h.presetFindMany.mockResolvedValue([{ id: 'up1', name: 'My preset' }, { id: 'up2', name: 'Taken' }])
    await expect(updateReconPreset(ctx(), { presetId: 'up1', name: 'taken' }))
      .rejects.toMatchObject({ code: 'preset_exists' })
  })

  test('a concurrent change is a conflict, not a retry', async () => {
    h.presetUpdateMany.mockResolvedValue({ count: 0 })
    await expect(updateReconPreset(ctx(), { presetId: 'up1', name: 'renamed' }))
      .rejects.toMatchObject({ code: 'conflict' })
    expect(h.presetUpdateMany).toHaveBeenCalledTimes(1)
    expect(h.renameBadges).not.toHaveBeenCalled()
  })

  test('C-10: a rename renames the badge of the projects that loaded it, and says how many', async () => {
    h.renameBadges.mockResolvedValue(3)
    const r = await updateReconPreset(ctx(), { presetId: 'up1', name: 'Renamed' })
    expect(h.renameBadges.mock.calls[0].slice(1)).toEqual(['owner', 'up1', 'Renamed'])
    expect(r).toMatchObject({ renamedFrom: 'My preset', badgesRenamed: 3 })
    expect(r.note).toMatch(/badge now shows the new name \(3 project\(s\)\)/)
    expect(h.audit.mock.calls[0][0].after.badgesRenamed).toBe(3)
  })

  test('C-10: a settings change moves no badge: they hold what loading it produced', async () => {
    const r = await updateReconPreset(ctx(), { presetId: 'up1', settings: { katanaDepth: 4 } })
    expect(h.renameBadges).not.toHaveBeenCalled()
    expect(r).not.toHaveProperty('badgesRenamed')
    expect(r.note).toMatch(/badge stays/)
  })

  test('the merged result is validated whole', async () => {
    await expect(updateReconPreset(ctx(), { presetId: 'up1', settings: { katanaDepth: 999 } }))
      .rejects.toMatchObject({ code: 'setting_rejected' })
  })
})

describe('delete_recon_preset', () => {
  test('a built-in cannot be deleted', async () => {
    await expect(deleteReconPreset(ctx(), { presetId: 'stealth-recon' })).rejects.toMatchObject({ code: 'builtin_immutable' })
  })

  test('the audit keeps what the preset held, which is the only undo', async () => {
    await deleteReconPreset(ctx(), { presetId: 'up1' })
    expect(h.presetDeleteMany.mock.calls[0][0].where).toEqual({ id: 'up1', userId: 'owner', updatedAt: PRESET_AT })
    const entry = h.audit.mock.calls[0][0]
    expect(entry.action).toBe('mcp.delete_recon_preset')
    expect(entry.before.settings).toEqual({ katanaDepth: 3, naabuEnabled: false })
  })

  test('C-10: the badge of every project that loaded it is cleared, and counted', async () => {
    h.clearBadges.mockResolvedValue(2)
    const r = await deleteReconPreset(ctx(), { presetId: 'up1' })
    expect(h.clearBadges.mock.calls[0].slice(1)).toEqual(['owner', 'up1'])
    expect(r).toMatchObject({ deleted: true, badgesCleared: 2 })
    expect(h.audit.mock.calls[0][0].after.badgesCleared).toBe(2)
  })

  test('a lost compare-and-swap reads back as conflict or not_found', async () => {
    h.presetDeleteMany.mockResolvedValue({ count: 0 })
    h.presetFindFirst.mockResolvedValueOnce(userPreset()).mockResolvedValueOnce({ id: 'up1' })
    await expect(deleteReconPreset(ctx(), { presetId: 'up1' })).rejects.toMatchObject({ code: 'conflict' })
    h.presetFindFirst.mockResolvedValueOnce(userPreset()).mockResolvedValueOnce(null)
    await expect(deleteReconPreset(ctx(), { presetId: 'up1' })).rejects.toMatchObject({ code: 'not_found' })
    expect(h.clearBadges).not.toHaveBeenCalled()
  })
})

// --- apply ------------------------------------------------------------------------------------

describe('apply_recon_preset', () => {
  test('it is refused while anything reads or writes the graph', async () => {
    for (const busy of ['an agent session is running', 'a triage run is in progress', 'a GVM vulnerability scan is running']) {
      h.live.mockResolvedValue(busy)
      await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' }))
        .rejects.toMatchObject({ code: 'busy' })
    }
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('C-8: a session the agent confirmed names the way out', async () => {
    h.live.mockResolvedValue('an agent session is running')
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' }))
      .rejects.toThrow(/stop the session in the RedAmon UI/)
  })

  test('C-8: a flag the agent could not confirm points at the agent, not at the operator', async () => {
    h.live.mockResolvedValue('an agent session is marked running and the agent could not be reached to confirm it')
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' }))
      .rejects.toThrow(/The agent did not answer; check that its container is up, then retry/)
  })

  test('unreadable defaults write nothing', async () => {
    h.defaults.mockRejectedValue(new DefaultsUnavailable('down'))
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' }))
      .rejects.toMatchObject({ code: 'defaults_unavailable' })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('dryRun reports and writes nothing', async () => {
    const r = await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon', dryRun: true })
    expect(r).toMatchObject({ dryRun: true, written: false })
    expect(r.changedCount).toBeGreaterThan(0)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('the write is a compare-and-swap carrying the badge, and a lost one is a conflict', async () => {
    await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' })
    const call = h.projectUpdateMany.mock.calls[0][0]
    expect(call.where).toEqual({ id: 'p1', updatedAt: PROJECT_AT })
    // C-10: which preset, so a rename or delete of a user preset can find it.
    expect(call.data.loadedPreset).toMatchObject({ name: 'Stealth Recon', presetId: 'stealth-recon', source: 'builtin' })
    expect(call.data.loadedPreset.fingerprint).toMatch(/^v2:/)
    expect(call.data).not.toHaveProperty('mcpKaliExecEnabled')
    expect(call.data).not.toHaveProperty('targetDomain')

    h.projectUpdateMany.mockResolvedValue({ count: 0 })
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' }))
      .rejects.toMatchObject({ code: 'conflict' })
  })

  test('an IP preset on a domain project warns, and does not touch the targeting', async () => {
    const ipPreset = 'internal-network'
    const r = await applyReconPreset(ctx(), { projectId: 'p1', presetId: ipPreset })
    expect(r.targetMismatch).toMatch(/NOT changed/)
    expect(h.projectUpdateMany.mock.calls[0][0].data).not.toHaveProperty('ipMode')
  })

  test('an IP preset relying on hostnames, on an ip_only IP project, says why it will find none (D-17)', async () => {
    h.projectFind.mockImplementation(async (args: { select?: Record<string, unknown> }) =>
      args.select && Object.keys(args.select).length === 2 && 'userId' in args.select
        ? { id: 'p1', userId: 'owner' }
        : projectRow({ ipMode: true, ipHostnameMode: 'ip_only' }))
    const r = await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'internal-network', dryRun: true }) as
      Record<string, unknown>
    expect(r.hostnameModeNote).toMatch(/Hostnames on target IPs is ip_only/)
    expect(r.hostnameModeNote).toMatch(/update_project_scope/)
    expect(r).not.toHaveProperty('targetMismatch')
    expect(h.projectFind.mock.calls.some(([a]) => a?.select?.ipHostnameMode === true)).toBe(true)
  })

  test('no note once the project records hostnames, nor for a preset that needs none', async () => {
    h.projectFind.mockImplementation(async (args: { select?: Record<string, unknown> }) =>
      args.select && Object.keys(args.select).length === 2 && 'userId' in args.select
        ? { id: 'p1', userId: 'owner' }
        : projectRow({ ipMode: true, ipHostnameMode: 'record_only' }))
    const recording = await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'large-network', dryRun: true })
    expect(recording).not.toHaveProperty('hostnameModeNote')
    const other = await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon', dryRun: true })
    expect(other).not.toHaveProperty('hostnameModeNote')
  })

  test('the presets named as relying on hostnames are real IP presets', async () => {
    const { IP_PRESETS_RELYING_ON_HOSTNAMES } = await import('./presetTools')
    const { getPresetById } = await import('@/lib/recon-presets')
    for (const id of IP_PRESETS_RELYING_ON_HOSTNAMES) expect(getPresetById(id)?.targetProfile, id).toBe('ip')
  })

  test('a fireteam change writes the fireteam audit', async () => {
    h.presetFindFirst.mockResolvedValue(userPreset({ settings: { fireteamMaxConcurrent: 2 } }))
    await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'up1' })
    const rows = h.fireteamAudit.mock.calls[0][0].data as { field: string; source: string }[]
    expect(rows.some(r => r.field === 'fireteamMaxConcurrent' && r.source === 'mcp')).toBe(true)
  })

  test('a user preset holding a value that no longer validates is refused, pointing at the fix', async () => {
    h.presetFindFirst.mockResolvedValue(userPreset({ settings: { katanaDepth: 999 } }))
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'up1' }))
      .rejects.toThrow(/update_recon_preset/)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('another user\'s preset cannot be applied', async () => {
    h.presetFindFirst.mockResolvedValue(null)
    await expect(applyReconPreset(ctx(), { projectId: 'p1', presetId: 'theirs' }))
      .rejects.toMatchObject({ code: 'not_found' })
  })

  test('it reports the queued scans the change parked', async () => {
    h.jobs.mockResolvedValue([{ id: 'j1', kind: 'full_recon', projectId: 'p1', payload: {}, settingsHash: 'old' }])
    const r = await applyReconPreset(ctx(), { projectId: 'p1', presetId: 'stealth-recon' }) as {
      queuedJobsNeedingReview: { count: number; jobIds: string[] }
    }
    expect(r.queuedJobsNeedingReview.jobIds).toEqual(['j1'])
  })
})
