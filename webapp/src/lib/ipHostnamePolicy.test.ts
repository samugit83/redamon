/**
 * Hostnames on target IPs after a policy change (design §6.3, decision D-19).
 *
 * admittedByCurrentPolicy is the one filter every reader of scanned names
 * applies: a name counts as scanned only while the project's CURRENT policy
 * admits it (record_filter: include minus exclude; scan_all: any; ip_only,
 * record_only, a project out of IP mode, an unreadable filter: none).
 *
 * markOutOfPolicy runs after a narrowing commits (PUT /api/projects/[id], MCP
 * update_project_scope, a Scan Timeline activation): it reads the project's
 * scanned names (`Subdomain {source: 'ip_hostname_selection'}` with reason
 * `scanned`) and marks those the policy no longer admits `out_of_policy`, all
 * on the tenant key. It answers true once the graph agrees; a graph failure
 * rejects, and the callers turn that into `hostnamePolicyMarked: false` while
 * the save stands.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const graph = vi.hoisted(() => ({ names: [] as unknown[], calls: [] as { query: string; params: Record<string, unknown> }[],
  fail: null as Error | null, closed: 0 }))

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    executeWrite: async (work: (tx: unknown) => Promise<unknown>) => work({
      run: async (query: string, params: Record<string, unknown>) => {
        if (graph.fail) throw graph.fail
        graph.calls.push({ query, params })
        return { records: query.includes('RETURN s.name AS name')
          ? graph.names.map(n => ({ get: (k: string) => (k === 'name' ? n : null) })) : [] }
      },
    }),
    close: async () => { graph.closed += 1 },
  }),
}))

import { admittedByCurrentPolicy, markOutOfPolicy } from './ipHostnamePolicy'
import { admittedByCurrentPolicy as previewCopy } from './ipHostnamePreview'

const NAMES = ['app.example.com', 'old.example.com', 'blog.example.net']
const row = (over: Record<string, unknown> = {}) => ({
  ipMode: true, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'],
  ipHostnameExclude: ['old.example.com'], ...over,
})

beforeEach(() => {
  graph.names = [...NAMES]
  graph.calls = []
  graph.fail = null
  graph.closed = 0
})

describe('admittedByCurrentPolicy', () => {
  test('record_filter admits include minus exclude; scan_all every name', () => {
    expect(admittedByCurrentPolicy(NAMES, row())).toEqual(['app.example.com'])
    expect(admittedByCurrentPolicy(NAMES, row({ ipHostnameMode: 'scan_all' }))).toEqual(NAMES)
  })

  test('no name in the other modes, out of IP mode, with an unreadable filter or no row', () => {
    for (const r of [row({ ipHostnameMode: 'record_only' }), row({ ipHostnameMode: 'ip_only' }),
      row({ ipHostnameMode: 'nonsense' }), row({ ipMode: false }), row({ ipHostnameExclude: ['**.x'] }),
      row({ ipHostnameInclude: ['203.0.113.10'] })]) {
      expect(admittedByCurrentPolicy(NAMES, r)).toEqual([])
    }
    expect(admittedByCurrentPolicy(NAMES, null)).toEqual([])
    expect(admittedByCurrentPolicy(NAMES, undefined)).toEqual([])
  })

  test('missing filter lists read as empty', () => {
    expect(admittedByCurrentPolicy(NAMES, { ipMode: true, ipHostnameMode: 'record_filter' })).toEqual([])
  })

  test('the preview reads the same single copy', () => {
    expect(previewCopy).toBe(admittedByCurrentPolicy)
  })
})

describe('markOutOfPolicy', () => {
  test('reads the scanned names on the tenant key', async () => {
    await markOutOfPolicy('p1', 'owner', row())
    const read = graph.calls[0]
    expect(read.query).toContain("MATCH (s:Subdomain {user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'})")
    expect(read.query).toContain("s.ip_hostname_reason = 'scanned'")
    expect(read.params).toEqual({ uid: 'owner', pid: 'p1' })
  })

  test('marks exactly the names the new policy no longer admits', async () => {
    await expect(markOutOfPolicy('p1', 'owner', row())).resolves.toBe(true)
    const mark = graph.calls[1]
    expect(mark.query).toContain('MATCH (s:Subdomain {name: name, user_id: $uid, project_id: $pid, source: \'ip_hostname_selection\'})')
    expect(mark.query).toContain("WHERE s.ip_hostname_reason = 'scanned'")
    expect(mark.query).toContain("SET s.ip_hostname_reason = 'out_of_policy', s.ip_hostname_evaluated_at = datetime()")
    expect(mark.params).toEqual({ names: ['old.example.com', 'blog.example.net'], uid: 'owner', pid: 'p1' })
    expect(graph.closed).toBe(1)
  })

  test.each(['ip_only', 'record_only'])('narrowing to %s marks every scanned name', async (mode) => {
    await markOutOfPolicy('p1', 'owner', row({ ipHostnameMode: mode }))
    expect(graph.calls[1].params.names).toEqual(NAMES)
  })

  test('leaving IP mode marks every scanned name', async () => {
    await markOutOfPolicy('p1', 'owner', row({ ipMode: false }))
    expect(graph.calls[1].params.names).toEqual(NAMES)
  })

  test('nothing to mark writes nothing and answers true', async () => {
    await expect(markOutOfPolicy('p1', 'owner', row({ ipHostnameMode: 'scan_all' }))).resolves.toBe(true)
    expect(graph.calls).toHaveLength(1)
    graph.names = []
    await expect(markOutOfPolicy('p1', 'owner', row())).resolves.toBe(true)
  })

  test('a junk name from the graph is ignored', async () => {
    graph.names = ['old.example.com', null, 42]
    await markOutOfPolicy('p1', 'owner', row())
    expect(graph.calls[1].params.names).toEqual(['old.example.com'])
  })

  test('a graph failure rejects and still closes the session', async () => {
    graph.fail = new Error('neo4j down')
    await expect(markOutOfPolicy('p1', 'owner', row())).rejects.toThrow('neo4j down')
    expect(graph.closed).toBe(1)
  })
})
