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
const mockOpen = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()

vi.mock('../../graph/neo4j', () => ({
  getGraphSession: (...a: unknown[]) => {
    mockOpen(...a)
    return { run: (...r: unknown[]) => mockRun(...r), close: mockClose }
  },
}))
vi.mock('../../graph/format', () => ({
  formatGraphRecords: () => ({ nodes: [], links: [] }),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
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

describe('a view cannot write, whatever its text (fix of the 4.3 review finding 1)', () => {
  test('the view runs in a read-only session, so Neo4j itself refuses a write the checks miss', async () => {
    const res = await run('MATCH (v:Vulnerability) RETURN v')
    expect(res.status).toBe(200)
    expect(mockOpen).toHaveBeenCalledWith({ readOnly: true })
  })

  test.each([
    ["MATCH (n) WHERE n.url <> 'http://x' DETACH DELETE n", 'DETACH'],
    ["MATCH (n) WHERE n.url <> 'http://x' SET n.name = 'x'", 'SET'],
    ["MATCH (n) WHERE n.url <> 'http://x' CREATE (m:Host)", 'CREATE'],
    ["LOAD CSV FROM 'http://169.254.169.254/' AS row RETURN row", 'LOAD'],
  ])('a write behind a string holding // is refused before Neo4j is opened: %s', async (query, word) => {
    const res = await run(query)
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain(`found: ${word}`)
    expect(mockOpen).not.toHaveBeenCalled()
    expect(mockRun).not.toHaveBeenCalled()
  })

  test.each([
    ['MATCH (n:`Domain`) RETURN n', 200],
    ['MATCH (n /* ( */) RETURN n', 200],
    ["MATCH (n {name: '('}) RETURN n", 200],
    ['MATCH(n) RETURN n', 200],
    ['MATCH (n {name: toString(1)}) RETURN n', 200], // scoped since the review of 4.6 (finding 4)
    ["MATCH (n:Domain {project_id: 'P-someone-else'}) RETURN n", 400],
    ["MATCH (n) WHERE n.name = 'open RETURN n", 400],
  ])('a node pattern the filter used to miss is scoped or refused, never run open: %s', async (query, status) => {
    const res = await run(query)
    expect(res.status).toBe(status)
    if (status === 200) expect(executed()).toContain('project_id: $projectId')
    else expect(mockRun).not.toHaveBeenCalled()
  })
})

describe('a failed query says why without echoing it (G-25)', () => {
  test('a Neo4j error answers its status code, never the message that quotes the query', async () => {
    mockRun.mockRejectedValue(Object.assign(
      new Error("Invalid input 'x': expected ... \"MATCH (s:Subdomain {name:'admin.target.example'})\""),
      { code: 'Neo.ClientError.Statement.SyntaxError' }))
    const res = await run('MATCH (s:Subdomain) RETURN s')
    expect(res.status).toBe(500)
    const text = await res.text()
    expect(JSON.parse(text)).toEqual({ error: 'Query execution failed', code: 'Neo.ClientError.Statement.SyntaxError' })
    expect(text).not.toContain('admin.target.example')
  })

  test('a dropped database connection is ServiceUnavailable', async () => {
    mockRun.mockRejectedValue(Object.assign(new Error('Could not perform discovery'), {
      name: 'Neo4jError', code: 'ServiceUnavailable' }))
    const res = await run('MATCH (s:Subdomain) RETURN s')
    expect((await res.json()).code).toBe('ServiceUnavailable')
  })
})

describe('the review of 4.6: a query the filter does not positively read is refused before Neo4j', () => {
  test.each([
    ['MATCH (`x y`) RETURN `x y`', 'cannot be tenant-scoped'],
    ['MATCH (é) RETURN é', 'non-ASCII'],
    ['MATCH (n IS Domain) RETURN n', 'cannot be tenant-scoped'],
    ['MATCH (n$) RETURN n$', '$projectId'],
    ['MATCH (n\u001c) RETURN n', 'control character'],
    ['MATCH (n\u0007) RETURN n\u0007', 'control character'],
    ["MATCH (a:Domain) RETURN apoc.cypher.runFirstColumnMany\u001c('MATCH (n) RETURN n', {})", 'control character'],
    ["MATCH (a:Domain) RETURN apoc.cypher.runFirstColumnMany('MATCH (n) RETURN n', {})", "built-in functions only"],
    ['MATCH (a:Domain) WITH a LIMIT 1 MATCH p=(c1:CVE)-[]-{,}(c2:CVE) RETURN p', 'Variable-length'],
    ['MATCH p=(a:Technology)- -+(c:CVE) RETURN p', 'Variable-length'],
    ['MATCH (a:Domain) WITH count(a) AS c MATCH (x:CVE) RETURN x', 'cannot be tenant-scoped'],
  ])('%s', async (query, why) => {
    const res = await run(query)
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain(why)
    expect(mockOpen).not.toHaveBeenCalled()
    expect(mockRun).not.toHaveBeenCalled()
  })

  test.each([
    ['MATCH (n:(Domain|Subdomain)) RETURN n', 'MATCH (n:(Domain|Subdomain)&!Muted {project_id: $projectId}) RETURN n'],
    ["MATCH (n:Domain {name: toLower('X')}) RETURN n", "MATCH (n:Domain&!Muted {project_id: $projectId, name: toLower('X')}) RETURN n"],
    ['MATCH (d:Domain) RETURN d.name AS show', 'MATCH (d:Domain&!Muted {project_id: $projectId}) RETURN d.name AS show'],
    ['MATCH (n:Domain {project_id: $projectId}) RETURN n', 'MATCH (n:Domain&!Muted {project_id: $projectId}) RETURN n'],
  ])('an owner view the checks used to refuse or leave open runs scoped: %s', async (query, expected) => {
    const res = await run(query)
    expect(res.status).toBe(200)
    expect(executed()).toBe(expected)
  })

  test('the owner reads step content, so a view filtering on it runs (Raw data & files is theirs)', async () => {
    const res = await run("MATCH (s:ChainStep) WHERE s.thought STARTS WITH 'a' RETURN s")
    expect(res.status).toBe(200)
    expect(executed()).toContain('(s:ChainStep&!Muted {project_id: $projectId})')
  })
})
