/**
 * create_project and the Jev engine flags.
 *
 * A new project starts with every engine on the LLM, so an engine flag in
 * `settings` is a switch-on and needs an explicit creator-owned Jev selection. The
 * check runs before anything is written, so a refusal leaves no project behind.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  providerFind: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
    },
    userLlmProvider: { findFirst: (...a: unknown[]) => h.providerFind(...a) },
    engagementAuthorization: {
      create: vi.fn(), findFirst: vi.fn(), findUnique: vi.fn(), findMany: vi.fn(), count: vi.fn(),
    },
    scanJob: { findFirst: vi.fn() },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: vi.fn(async () => null) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { createProject } from './engagementTools'
import type { McpContext } from './tools'

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'creator', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'project:create'] as never,
  },
})

const args = (settings: Record<string, unknown>) => ({
  name: 'test', engagementKind: 'internal' as const, targetDomain: 'example.com', settings,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.providerFind.mockResolvedValue(null)
  h.audit.mockResolvedValue(undefined)
})

describe('create_project: a Jev engine flag in settings', () => {
  test('with an explicit provider selection on the creating account it reaches the create call', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    const r = await createProject(ctx(), args({ ffufAiUseJev: true, jevProviderId: 'jev-selected' }))
    expect(r.created).toBe(true)
    expect(h.createProject.mock.calls[0][0].data).toMatchObject({ ffufAiUseJev: true, jevProviderId: 'jev-selected' })
    expect(h.providerFind).toHaveBeenCalledWith({ where: { id: 'jev-selected', userId: 'creator', providerType: { in: ['jev', 'jev_openrouter'] } }, select: { id: true } })
  })

  test('without a provider selection it is refused and no project is created', async () => {
    await expect(createProject(ctx(), args({ wafAiUseJev: true })))
      .rejects.toThrow(/wafAiUseJev.*select an explicit Jev provider/s)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('an account provider cannot enable a hook with a null project selection', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    await expect(createProject(ctx(), args({ wafAiUseJev: true, jevProviderId: null })))
      .rejects.toThrow(/wafAiUseJev.*select an explicit Jev provider/s)
    expect(h.providerFind).not.toHaveBeenCalled()
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('an unavailable or foreign selected provider cannot create a project', async () => {
    await expect(createProject(ctx(), args({ ffufAiUseJev: true, jevProviderId: 'jev-selected' })))
      .rejects.toThrow('does not belong to the project owner')
    expect(h.providerFind).toHaveBeenCalledWith({
      where: { id: 'jev-selected', userId: 'creator', providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('it fails closed when the lookup throws', async () => {
    h.providerFind.mockRejectedValue(new Error('db down'))
    await expect(createProject(ctx(), args({ takeoverAiUseJev: true, jevProviderId: 'jev-selected' })))
      .rejects.toThrow("Couldn't verify the project's Jev provider, try again.")
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('settings with no engine flag never touch the provider table', async () => {
    await createProject(ctx(), args({ naabuThreads: 25 }))
    expect(h.providerFind).not.toHaveBeenCalled()
  })
})

describe('create_project: a Jev-only hook flag in settings', () => {
  test.each(['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
    'serializedScanJevRank'])(
    '%s without a provider selection is refused and no project is created', async (field) => {
      await expect(createProject(ctx(), args({ [field]: true })))
        .rejects.toThrow(new RegExp(`${field}.*select an explicit Jev provider`, 's'))
      expect(h.createProject).not.toHaveBeenCalled()
    })

  test('with an explicit provider selection it reaches the create call', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    const r = await createProject(ctx(), args({ httpxJevPageType: true, jevProviderId: 'jev-selected' }))
    expect(r.created).toBe(true)
    expect(h.createProject.mock.calls[0][0].data).toMatchObject({ httpxJevPageType: true, jevProviderId: 'jev-selected' })
  })
})
