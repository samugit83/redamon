/**
 * What a failing graph query TELLS the caller.
 *
 * REGRESSION (e2e finding): the raw-Cypher path threw every refusal reason
 * away. `agentFailure` quoted the agent's message only when the body carried a
 * `stage` field, which only the natural-language path sets. `/graph/exec` -
 * the `graph:cypher` permission, the one place an agent writes the query
 * ITSELF and therefore most needs to know what it got wrong - answered every
 * refusal with a flat "graph query failed."
 *
 * So an agent that sent a MERGE was not told writes are forbidden, and an agent
 * that sent `MATCH (n)` was not told the pattern needs a label. Both retry the
 * same query forever. The agent's 4xx strings are written for the caller (the
 * raw exception is logged, never returned), so quoting them is safe - which is
 * exactly what the two `stage` branches already did.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'

const h = vi.hoisted(() => ({ fetch: vi.fn() }))

vi.mock('@/lib/agentFetch', () => ({ agentBaseUrl: () => 'http://agent:8000' }))
vi.mock('@/lib/agentAuth', () => ({ internalKeyHeaders: () => ({}) }))

import { execCypher, nlQuery } from './graphClient'

// graphClient posts with the global fetch, so that is the seam.
const failing = (status: number, body: Record<string, unknown>) =>
  ({ ok: false, status, json: async () => body })

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', h.fetch)
})

describe('a refused Cypher query says WHY', () => {
  test('a write refusal names the operation that was rejected', async () => {
    h.fetch.mockResolvedValue(failing(403, {
      error: 'write operation rejected (MERGE); read-only',
    }))
    await expect(execCypher('u1', 'p1', 'MERGE (d:Domain {name: "x"})'))
      .rejects.toThrow(/write operation rejected \(MERGE\); read-only/)
  })

  test('an unscopable pattern tells the caller to label it', async () => {
    h.fetch.mockResolvedValue(failing(400, {
      error: 'Query rejected: node pattern (n) could not be scoped to this project. '
           + 'Give every node pattern an explicit label, e.g. MATCH (p:Package), '
           + 'instead of matching (n) and testing the label in a WHERE clause.',
    }))
    await expect(execCypher('u1', 'p1', 'MATCH (n) RETURN n'))
      .rejects.toThrow(/explicit label/)
  })

  test('the reserved Muted label is refused by name', async () => {
    h.fetch.mockResolvedValue(failing(400, {
      error: "Query rejected: the 'Muted' label is reserved and cannot be referenced.",
    }))
    await expect(execCypher('u1', 'p1', 'MATCH (v:Vulnerability:Muted) RETURN v'))
      .rejects.toThrow(/'Muted' label is reserved/)
  })

  test('an oversized result tells the caller to narrow it', async () => {
    h.fetch.mockResolvedValue(failing(413, {
      error: 'result too large, narrow your query',
    }))
    await expect(execCypher('u1', 'p1', 'MATCH (d:Domain) RETURN d'))
      .rejects.toThrow(/narrow your query/)
  })

  // The other half of the contract: a 5xx is the deployment's problem, not the
  // caller's, and its text is NOT written for an agent to act on.
  test('a server-side failure stays generic', async () => {
    h.fetch.mockResolvedValue(failing(500, { error: 'graph query failed' }))
    await expect(execCypher('u1', 'p1', 'MATCH (d:Domain) RETURN d'))
      .rejects.toMatchObject({ code: 'agent_failed' })
  })

  test('a 4xx with no message at all still fails cleanly', async () => {
    h.fetch.mockResolvedValue(failing(400, {}))
    await expect(execCypher('u1', 'p1', 'MATCH (d:Domain) RETURN d'))
      .rejects.toThrow(/failed/)
  })

  test('a non-JSON error body does not crash the caller', async () => {
    h.fetch.mockResolvedValue({
      ok: false, status: 400, json: async () => { throw new Error('not json') },
    })
    await expect(execCypher('u1', 'p1', 'MATCH (d:Domain) RETURN d'))
      .rejects.toThrow(/failed/)
  })

  // The refusal quotes the caller's pattern, and the caller may be a model (AI Navigator):
  // the caller reads it, the log keeps the status and stage only.
  test('the log keeps the status, never the refusal text that quotes the query', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.fetch.mockResolvedValue(failing(400, {
      error: "Query rejected: node pattern (n {name: 'probe-host-5521.example.test'}) could not be scoped.",
    }))
    await expect(execCypher('u1', 'p1', "MATCH (n {name: 'probe-host-5521.example.test'}) RETURN n"))
      .rejects.toThrow(/probe-host-5521/)
    const text = logged.mock.calls.flat().map(String).join(' ')
    expect(text).toContain('400')
    expect(text).not.toContain('probe-host-5521')
    logged.mockRestore()
  })
})

describe('the natural-language path keeps the split it already had', () => {
  test('a generation failure is reported as one', async () => {
    h.fetch.mockResolvedValue(failing(400, {
      stage: 'generate', error: 'Could not turn that question into a query.',
    }))
    await expect(nlQuery('u1', 'p1', 'how many wombats?'))
      .rejects.toMatchObject({ code: 'generate_failed' })
  })

  test('an execution failure is reported as one', async () => {
    h.fetch.mockResolvedValue(failing(400, {
      stage: 'execute', error: 'The query could not be run.',
    }))
    await expect(nlQuery('u1', 'p1', 'list every port'))
      .rejects.toMatchObject({ code: 'execute_failed' })
  })
})
