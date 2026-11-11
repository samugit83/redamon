/**
 * create_project gives every new project its own ownership token (L-16).
 *
 * Without one in `settings` the project used to get Prisma's literal default,
 * the same value on every install, so one published TXT record verified every
 * project that kept it. A missing, empty or legacy token is now replaced by a
 * fresh random one; a token the caller chose is kept.
 *
 * Same harness as engagementTools.skillToggles.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ createProject: vi.fn(), findProject: vi.fn() }))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: (...a: unknown[]) => h.findProject(...a),
    },
    engagementAuthorization: {
      create: vi.fn(), findFirst: async () => null, findUnique: async () => null,
      findMany: async () => [], count: async () => 0,
    },
    scanJob: { findFirst: async () => null },
    userLlmProvider: { count: async () => 0 },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => undefined) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { createProject } from './engagementTools'
import type { McpContext } from './tools'

const LEGACY = 'your-secret-token-here'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'creator', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'project:create'] as never,
  },
})

// The target guardrail is off so the test never waits on an agent.
const create = (settings: Record<string, unknown> = {}) => createProject(ctx(), {
  name: 'test', engagementKind: 'internal', targetDomain: 'example.invalid',
  settings: { targetGuardrailEnabled: false, ...settings } as never,
})

const tokenOf = (call: number) => h.createProject.mock.calls[call][0].data.ownershipToken

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.findProject.mockResolvedValue(null)
})

describe('create_project: the ownership token', () => {
  test('a project created without one gets a random one, different each time', async () => {
    await create()
    await create({ verifyDomainOwnership: true })
    expect(tokenOf(0)).toMatch(UUID)
    expect(tokenOf(1)).toMatch(UUID)
    expect(tokenOf(0)).not.toBe(tokenOf(1))
  })

  test.each([
    ['the old shared default', LEGACY],
    ['an empty value', ''],
  ])('%s is replaced by a fresh token', async (_label, value) => {
    await create({ verifyDomainOwnership: true, ownershipToken: value })
    expect(tokenOf(0)).toMatch(UUID)
  })

  test('a token the caller chose is kept', async () => {
    await create({ verifyDomainOwnership: true, ownershipToken: 'k7-agent-token' })
    expect(tokenOf(0)).toBe('k7-agent-token')
  })
})
