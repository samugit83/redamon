/**
 * update_recon_settings and the Jev engine flags.
 *
 * The MCP writer requires an explicit owner-owned Jev selection for a switch-on
 * or a changed non-null provider id. A legacy stored `true` never blocks an
 * unrelated write, and a failed provider lookup refuses.
 *
 * Over MCP the token's user must be the project's owner (a mismatch is always a
 * hard deny), so the acting account and the owner are the same here; the check
 * reads the stored row's owner regardless.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  updateManyProjects: vi.fn(),
  providerFind: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findProject(...a),
      updateMany: (...a: unknown[]) => h.updateManyProjects(...a),
    },
    userLlmProvider: { findFirst: (...a: unknown[]) => h.providerFind(...a) },
    jobQueue: { findMany: async () => [] },
    projectAuthProfile: { findUnique: async () => null },
    fireteamSettingsAudit: { createMany: async () => ({}) },
    scanSchedule: { findMany: async () => [] },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: async () => null,
  describeScanWriters: async () => null,
}))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => undefined) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { updateReconSettings } from './writeTools'
import type { McpContext } from './tools'

const READ_AT = new Date('2026-09-29T08:00:00.000Z')

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'recon:settings'] as never,
  },
})

let stored: Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  stored = {
    id: 'p1', userId: 'owner', updatedAt: READ_AT, jevProviderId: null,
    ffufAiUseJev: false, nucleiTagsAiUseJev: false, wafAiUseJev: false, takeoverAiUseJev: false,
  }
  h.findProject.mockImplementation(async () => ({ ...stored }))
  h.updateManyProjects.mockResolvedValue({ count: 1 })
  h.providerFind.mockResolvedValue(null)
})

describe('update_recon_settings: a switch onto Jev', () => {
  test('with an explicit provider selection on the owner\'s account it is written', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    stored.jevProviderId = 'jev-selected'
    const r = await updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true })
    expect(r.projectId).toBe('p1')
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ ffufAiUseJev: true })
  })

  test('the lookup is for the stored selection, owner and both Jev provider types', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    stored.jevProviderId = 'jev-selected'
    await updateReconSettings(ctx(), 'p1', { wafAiUseJev: true })
    expect(h.providerFind).toHaveBeenCalledWith({ where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } }, select: { id: true } })
  })

  test('without a provider selection it is refused, naming the field, and nothing is written', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { nucleiTagsAiUseJev: true }))
      .rejects.toThrow(/nucleiTagsAiUseJev.*select an explicit Jev provider/s)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('it fails closed when the lookup throws', async () => {
    h.providerFind.mockRejectedValue(new Error('db down'))
    stored.jevProviderId = 'jev-selected'
    await expect(updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true }))
      .rejects.toThrow("Couldn't verify the project's Jev provider, try again.")
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })
})

describe('update_recon_settings: provider selection changes', () => {
  test('a changed non-null selection is validated and written even without a switch-on', async () => {
    stored.jevProviderId = 'jev-before'
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    await updateReconSettings(ctx(), 'p1', { jevProviderId: 'jev-selected' })
    expect(h.providerFind).toHaveBeenCalledWith({
      where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ jevProviderId: 'jev-selected' })
  })

  test('a changed unavailable selection is refused even with legacy enabled hooks', async () => {
    stored.ffufAiUseJev = true
    stored.jevProviderId = 'jev-before'
    await expect(updateReconSettings(ctx(), 'p1', { jevProviderId: 'jev-selected' }))
      .rejects.toThrow('does not belong to the project owner')
    expect(h.providerFind).toHaveBeenCalledWith({
      where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('clearing a selection permits static fallback for an already enabled hook', async () => {
    stored.ffufAiUseJev = true
    stored.jevProviderId = 'jev-before'
    await updateReconSettings(ctx(), 'p1', { jevProviderId: null })
    expect(h.providerFind).not.toHaveBeenCalled()
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ jevProviderId: null })
  })

  test('an account provider cannot enable a hook with a null selection', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    await expect(updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true, jevProviderId: null }))
      .rejects.toThrow('select an explicit Jev provider')
    expect(h.providerFind).not.toHaveBeenCalled()
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })
})

describe('update_recon_settings: a stored Jev choice is not a reason to refuse', () => {
  test('an unchanged true with no provider selection still allows an unrelated write', async () => {
    stored.ffufAiUseJev = true
    const r = await updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true, naabuThreads: 25 })
    expect(r.projectId).toBe('p1')
    expect(h.providerFind).not.toHaveBeenCalled()
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ ffufAiUseJev: true, naabuThreads: 25 })
  })

  test('switching back to the LLM needs no provider selection', async () => {
    stored.wafAiUseJev = true
    await updateReconSettings(ctx(), 'p1', { wafAiUseJev: false })
    expect(h.providerFind).not.toHaveBeenCalled()
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ wafAiUseJev: false })
  })
})

describe('update_recon_settings: turning on a Jev-only hook', () => {
  test.each(['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
    'serializedScanJevRank'])(
    '%s without a provider selection is refused and nothing is written', async (field) => {
      await expect(updateReconSettings(ctx(), 'p1', { [field]: true }))
        .rejects.toThrow(new RegExp(`${field}.*select an explicit Jev provider`, 's'))
      expect(h.updateManyProjects).not.toHaveBeenCalled()
    })

  test('with an explicit provider selection it is written', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    stored.jevProviderId = 'jev-selected'
    await updateReconSettings(ctx(), 'p1', { ffufJevBasePaths: true })
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ ffufJevBasePaths: true })
  })
})
