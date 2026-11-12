/**
 * Node filters survive an export/import round trip, and arrive DISARMED.
 *
 * An operator's exemptions ("no rule may mute this again") must come along, or
 * the imported project re-mutes what they had unmuted. The rules come along too,
 * but never armed: a freshly imported project must not start muting what its
 * next scan finds before its new owner has looked at them.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { Prisma } from '@prisma/client'
import JSZip from 'jszip'

const mockProjectCreate = vi.fn()
const mockFilterCreate = vi.fn()
const mockExemptionCreateMany = vi.fn()
const mockPresetFindMany = vi.fn()
const mockPresetCreate = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: 'new-owner' }) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => mockProjectCreate(...a) },
    projectNodeFilter: { create: (...a: unknown[]) => mockFilterCreate(...a) },
    nodeFilterExemption: { createMany: (...a: unknown[]) => mockExemptionCreateMany(...a) },
    userMuteRulesPreset: {
      findMany: (...a: unknown[]) => mockPresetFindMany(...a),
      create: (...a: unknown[]) => mockPresetCreate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'
import { muteRulesFingerprint } from '@/lib/nodeFilters/presets'

const RULES = {
  version: 1,
  kinds: {
    'vuln.nuclei': {
      enabled: true, action: 'mute',
      rules: [{ id: 'k3f9a2', name: 'Informational templates', enabled: true,
                all: [{ field: 'severity', op: 'in', value: ['info'] }] }],
    },
  },
}

async function bundle(nodeFilter: unknown, exemptions: unknown, project: Record<string, unknown> = {},
                      muteRulesPresets: unknown = null) {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'Imported' }))
  zip.file('project.json', JSON.stringify({ id: 'old-project', userId: 'old-owner', name: 'Imported', ...project }))
  if (nodeFilter) zip.file('node-filters/node-filters.json', JSON.stringify(nodeFilter))
  if (exemptions) zip.file('node-filters/node-filter-exemptions.json', JSON.stringify(exemptions))
  if (muteRulesPresets) zip.file('presets/user_mute_rules_presets.json', JSON.stringify(muteRulesPresets))
  const buf = await zip.generateAsync({ type: 'uint8array' })
  const fd = new FormData()
  fd.set('file', new File([buf as BlobPart], 'export.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectCreate.mockResolvedValue({ id: 'new-project', name: 'Imported' })
  mockFilterCreate.mockResolvedValue({})
  mockExemptionCreateMany.mockImplementation(({ data }: { data: unknown[] }) => Promise.resolve({ count: data.length }))
  mockPresetFindMany.mockResolvedValue([])
  mockPresetCreate.mockResolvedValue({})
})

describe('importing node filters', () => {
  test('import_nested_relation_writes: project.json cannot write node filters or any other relation', async () => {
    // Prisma's create accepts nested relation writes. Passed through, a crafted
    // project.json would arm unvalidated rules, or plant a run that never goes
    // stale and blocks every scan of the project for good.
    await POST(await bundle(null, null, {
      nodeFilter: { create: { applyToScans: true, mode: 'denylist', rules: { version: 1, kinds: {} } } },
      nodeFilterRuns: { create: { status: 'running', heartbeatAt: '2099-01-01T00:00:00Z', target: 'current',
        versionId: '', revision: 1, mode: 'denylist', rules: {}, actorUserId: 'x' } },
      nodeFilterExemptions: { create: [{ label: 'IP', nodeKey: '192.0.2.10', createdBy: 'x' }] },
      triageRuns: { create: [{}] },
      notAColumn: 'x',
      targetDomain: 'example.com',
    }))
    const data = mockProjectCreate.mock.calls[0][0].data
    // The two batch columns are the import's own scope normalisation: a
    // non-batch project keeps no batch scope, and a bundle with no ownership
    // token gets its own. No relation key gets through.
    expect(data).toEqual({
      name: 'Imported', targetDomain: 'example.com', userId: 'new-owner',
      domainBatchGroups: Prisma.DbNull, domainBatchHosts: [],
      ownershipToken: expect.stringMatching(/^[0-9a-f-]{36}$/),
    })
  })

  test('the rules arrive disarmed, under the new owner', async () => {
    const res = await POST(await bundle({ mode: 'denylist', rules: RULES, revision: 7 }, null))
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(mockFilterCreate).toHaveBeenCalledWith({
      data: {
        projectId: 'new-project', mode: 'denylist', rules: RULES,
        applyToScans: false, updatedBy: 'new-owner',
      },
    })
    expect(body.stats.nodeFilters).toBe('imported (not applied to new scans)')
  })

  test('even a bundle claiming it was armed arrives disarmed', async () => {
    await POST(await bundle({ mode: 'allowlist', rules: RULES, applyToScans: true }, null))
    expect(mockFilterCreate.mock.calls[0][0].data.applyToScans).toBe(false)
  })

  test('the exemptions come along, finding labels only', async () => {
    const res = await POST(await bundle(null, [
      { label: 'Vulnerability', nodeKey: 'v1', createdAt: '2026-09-01T00:00:00Z' },
      { label: 'MalPackageFinding', nodeKey: 'f9' },
      { label: 'IP', nodeKey: '192.0.2.10' },
      { label: 'Secret', nodeKey: '' },
      'garbage',
    ]))
    expect(mockExemptionCreateMany).toHaveBeenCalledWith({
      data: [
        { projectId: 'new-project', label: 'Vulnerability', nodeKey: 'v1', createdBy: 'new-owner' },
        { projectId: 'new-project', label: 'MalPackageFinding', nodeKey: 'f9', createdBy: 'new-owner' },
      ],
      skipDuplicates: true,
    })
    expect((await res.json()).stats.nodeFilterExemptions).toBe(2)
  })

  test('rules this catalog cannot read are left out, and the import still succeeds', async () => {
    const bad = { version: 1, kinds: { 'vuln.retired_kind': { enabled: true, action: 'mute', rules: [] } } }
    const res = await POST(await bundle({ mode: 'denylist', rules: bad }, null))
    expect(res.status).toBe(200)
    expect(mockFilterCreate).not.toHaveBeenCalled()
    expect((await res.json()).stats.nodeFilters).toMatch(/^skipped: unknown kind/)
  })

  test('a bundle from before node filters imports as it always did', async () => {
    const res = await POST(await bundle(null, null))
    expect(res.status).toBe(200)
    expect(mockFilterCreate).not.toHaveBeenCalled()
    expect(mockExemptionCreateMany).not.toHaveBeenCalled()
  })
})

describe('importing the loaded preset and the Mute Rules presets', () => {
  const OTHER_RULES = {
    version: 1,
    kinds: { 'secret': { enabled: true, action: 'mute', rules: [
      { id: 'b7c8d9', name: 'jsluice secrets', enabled: true, all: [{ field: 'source', op: 'in', value: ['jsluice'] }] },
    ] } },
  }

  test('the badge record comes along with the archive\'s fingerprint, not a recomputed one', async () => {
    // Recomputing from the imported rules would badge rules edited after the load.
    const loadedPreset = { name: 'Quiet perimeter', fingerprint: 'abc123' }
    await POST(await bundle({ mode: 'denylist', rules: RULES, loadedPreset }, null))
    expect(mockFilterCreate.mock.calls[0][0].data.loadedPreset).toEqual(loadedPreset)
  })

  test('a malformed badge record is dropped, and the rules still import', async () => {
    await POST(await bundle({ mode: 'denylist', rules: RULES, loadedPreset: { name: 'x'.repeat(500), fingerprint: 'f' } }, null))
    const data = mockFilterCreate.mock.calls[0][0].data
    expect(data).not.toHaveProperty('loadedPreset')
    expect(data.rules).toEqual(RULES)
  })

  test('the presets arrive under the importing user, never the exporter', async () => {
    const res = await POST(await bundle(null, null, {}, [
      { name: 'Quiet perimeter', description: 'why', mode: 'denylist', rules: RULES, userId: 'old-owner', id: 'old-id' },
    ]))
    expect(mockPresetCreate).toHaveBeenCalledTimes(1)
    expect(mockPresetCreate.mock.calls[0][0].data).toEqual({
      userId: 'new-owner', name: 'Quiet perimeter', description: 'why', mode: 'denylist', rules: RULES,
    })
    expect((await res.json()).stats.muteRulesPresets).toBe(1)
  })

  test('a preset this catalog cannot run, or without a name, is skipped and counted', async () => {
    const bad = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute',
      rules: [{ id: 'k3f9a2', name: 'x', enabled: true, all: [{ field: 'no_such_field', op: 'in', value: ['a'] }] }] } } }
    const res = await POST(await bundle(null, null, {}, [
      { name: 'Broken', mode: 'denylist', rules: bad },
      { name: '   ', mode: 'denylist', rules: RULES },
      { name: 'Good', mode: 'denylist', rules: RULES },
    ]))
    expect(mockPresetCreate).toHaveBeenCalledTimes(1)
    expect(mockPresetCreate.mock.calls[0][0].data.name).toBe('Good')
    const { stats } = await res.json()
    expect(stats.muteRulesPresets).toBe(1)
    expect(stats.muteRulesPresetsSkipped).toBe(2)
  })

  test('import_preset_twice: a preset the user already has, same name and rules, is not duplicated', async () => {
    mockPresetFindMany.mockResolvedValue([{ name: 'Quiet perimeter', mode: 'denylist', rules: RULES }])
    await POST(await bundle(null, null, {}, [
      { name: 'Quiet perimeter', mode: 'denylist', rules: RULES },
      { name: 'Quiet perimeter', mode: 'denylist', rules: OTHER_RULES },
      { name: 'Quiet perimeter', mode: 'allowlist', rules: RULES },
    ]))
    // Same name but different rules, or a different mode, is a different preset.
    const made = mockPresetCreate.mock.calls.map(c => [c[0].data.mode, muteRulesFingerprint(c[0].data.mode, c[0].data.rules)])
    expect(made).toEqual([
      ['denylist', muteRulesFingerprint('denylist', OTHER_RULES)],
      ['allowlist', muteRulesFingerprint('allowlist', RULES)],
    ])
  })

  test('the same preset twice in one archive is created once', async () => {
    await POST(await bundle(null, null, {}, [
      { name: 'Quiet perimeter', mode: 'denylist', rules: RULES },
      { name: 'Quiet perimeter', mode: 'denylist', rules: RULES },
    ]))
    expect(mockPresetCreate).toHaveBeenCalledTimes(1)
  })

  test('an unreadable presets file does not fail the import', async () => {
    const zip = new JSZip()
    zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'Imported' }))
    zip.file('project.json', JSON.stringify({ id: 'old-project', name: 'Imported' }))
    zip.file('presets/user_mute_rules_presets.json', '{not json')
    const fd = new FormData()
    fd.set('file', new File([await zip.generateAsync({ type: 'uint8array' }) as BlobPart], 'export.zip'))
    const res = await POST(new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd }))
    expect(res.status).toBe(200)
    expect(mockPresetCreate).not.toHaveBeenCalled()
  })
})
