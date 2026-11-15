/**
 * `mcpProjectAccess` with `actingAs` (AI Navigator plan §7.9, §10.2 row 13): an admin acting as a
 * write collaborator reaches the share at Read and never more; a real MCP token (no `actingAs`) is
 * unchanged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

const h = vi.hoisted(() => ({ opts: [] as unknown[] }))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (_s: unknown, _p: string, opts: { actingAs?: boolean } = {}) => {
    h.opts.push(opts)
    // projectAccess's own rule: under act-as a share reads as Read.
    return opts.actingAs
      ? { project: { id: 'P1', userId: 'owner' }, level: 'read', toggles: { rawData: true }, via: 'share' }
      : { project: { id: 'P1', userId: 'owner' }, level: 'write', toggles: { rawData: true, runScans: true }, via: 'share' }
  },
}))

import { mcpProjectAccess, McpLevelDenied } from './mcpAuth'

const reach = { allowlist: ['P1'] }

describe('mcpProjectAccess actingAs', () => {
  test('without it: the write share reaches W (a real token, unchanged)', async () => {
    const out = await mcpProjectAccess({ userId: 'bob', sharedProjects: reach }, 'P1', 'W')
    expect(out.access.level).toBe('write')
    expect(h.opts.at(-1)).toEqual({})
  })

  test('with it: projectAccess is asked with actingAs and a write tool is refused', async () => {
    await expect(mcpProjectAccess({ userId: 'bob', sharedProjects: reach, actingAs: true }, 'P1', 'W')).rejects.toBeInstanceOf(McpLevelDenied)
    expect(h.opts.at(-1)).toEqual({ actingAs: true })
    const read = await mcpProjectAccess({ userId: 'bob', sharedProjects: reach, actingAs: true }, 'P1', 'R')
    expect(read.access.level).toBe('read')
  })
})
