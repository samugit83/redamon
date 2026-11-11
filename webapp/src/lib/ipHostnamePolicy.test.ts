/**
 * markOutOfPolicy as it ships now: no Subdomain with source 'ip_hostname_selection'
 * exists before the late-name scan writes scanned names, so a narrowing has nothing
 * to mark and the truthful answer is true, with no graph or database call. The
 * step that adds the tenant-keyed write replaces this file's assertions; its
 * callers (PUT /api/projects/[id], MCP update_project_scope) stay as they are.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

const touched = vi.fn()
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => { touched('neo4j'); throw new Error('no graph') } }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => { touched(`prisma.${String(k)}`); throw new Error('no db') } }) }))

import { markOutOfPolicy } from './ipHostnamePolicy'

describe('markOutOfPolicy before scanned names exist', () => {
  test.each(['ip_only', 'record_only', 'record_filter', 'scan_all'])('narrowing to %s answers true', async (mode) => {
    await expect(markOutOfPolicy('p1', 'owner', { ipHostnameMode: mode, ipHostnameInclude: ['*.example.com'] }))
      .resolves.toBe(true)
  })

  test('it reads and writes nothing', async () => {
    await markOutOfPolicy('p1', 'owner', { ipHostnameMode: 'record_only' })
    expect(touched).not.toHaveBeenCalled()
  })
})
