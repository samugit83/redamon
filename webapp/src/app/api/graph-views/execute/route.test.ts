/**
 * POST /api/graph-views/execute — the saved-view Cypher path.
 *
 * This route matters for mute because it is a SECOND, independent tenant filter:
 * saved views render into the same graph screen as the live loader but never
 * touch `liveRead.ts` or the Python chokepoint, so the exclusion has to be
 * enforced here separately. The feature plan asserted this path did not exist.
 *
 * Covered here: that the exclusion actually reaches the executed query, that a
 * view asking about suppressed findings is refused before Neo4j is opened, and
 * that neither check broke the ordinary read-only/tenancy guards around them.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRun = vi.fn()
const mockClose = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()

vi.mock('../../graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: mockClose }),
}))
vi.mock('../../graph/format', () => ({
  formatGraphRecords: () => ({ nodes: [], links: [] }),
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))

import { POST } from './route'

const req = (body: unknown) =>
  new NextRequest('http://x/api/graph-views/execute', {
    method: 'POST',
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' },
  })

const run = (cypherQuery: string) => POST(req({ cypherQuery, projectId: 'p1' }))

/** The Cypher that actually reached the driver. */
const executed = () => String(mockRun.mock.calls[0]?.[0] ?? '')

beforeEach(() => {
  vi.clearAllMocks()
  mockRequireEff.mockResolvedValue({ userId: 'owner' })
  mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  mockRun.mockResolvedValue({ records: [] })
})

describe('a saved view cannot surface suppressed findings', () => {
  test('the executed query excludes muted nodes', async () => {
    const res = await run('MATCH (v:Vulnerability) RETURN v')

    expect(res.status).toBe(200)
    expect(executed()).toContain('!Muted')
    expect(executed()).toContain('project_id: $projectId')
  })

  test('a union view excludes muted on BOTH branches', async () => {
    // `:A|B&!Muted` would parse as `A OR (B AND NOT Muted)` and return a muted A.
    await run('MATCH (n:Secret|Vulnerability) RETURN n')

    expect(executed()).toContain('Secret&!Muted|Vulnerability&!Muted')
  })

  test('an unlabelled view still excludes muted', async () => {
    await run('MATCH (n) RETURN n')

    expect(executed()).toContain('n:!Muted')
  })

  test('a view naming the reserved label is refused, and Neo4j is never opened', async () => {
    const res = await run('MATCH (n:Muted) RETURN n')

    expect(res.status).toBe(400)
    await expect(res.json()).resolves.toMatchObject({
      error: expect.stringContaining('reserved'),
    })
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('a view filtering on the label is refused too', async () => {
    // The exclusion is automatic; asking about it can only be an attempt to
    // inspect what was suppressed.
    const res = await run('MATCH (v:Vulnerability) WHERE NOT v:Muted RETURN v')

    expect(res.status).toBe(400)
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('the word inside a string literal is not treated as a label reference', async () => {
    const res = await run("MATCH (v:Vulnerability) WHERE v.name = 'Muted' RETURN v")

    expect(res.status).toBe(200)
    expect(executed()).toContain("'Muted'")
  })
})

describe('the surrounding guards still hold', () => {
  test('a write is still rejected before anything else', async () => {
    const res = await run('MATCH (n:Vulnerability) DETACH DELETE n')

    expect(res.status).toBe(400)
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('a cross-user project is refused before Neo4j is opened', async () => {
    mockRequireProjectAccess.mockResolvedValue(
      NextResponse.json({ error: 'Not found' }, { status: 404 }),
    )

    const res = await run('MATCH (v:Vulnerability) RETURN v')

    expect(res.status).toBe(404)
    expect(mockRun).not.toHaveBeenCalled()
  })

  test('a reference-label view is left unscoped and unmuted', async () => {
    // CVE/MitreData/Capec carry no project_id and are never muted; filtering
    // them would match nothing and blind every view that traverses to a CVE.
    await run('MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c')

    expect(executed()).toContain('(c:CVE)')
  })
})
