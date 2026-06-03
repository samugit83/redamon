/**
 * Unit tests for NodeDetailsTable pure helpers.
 *
 * Run: npx vitest run src/app/graph/components/NodeDetailsTable/nodeDetailsHelpers.test.ts
 */

import { describe, test, expect } from 'vitest'
import type { TableRow } from '../../hooks/useTableData'
import type { GraphNode } from '../../types'
import {
  groupRowsByType,
  deriveDynamicColumnKeys,
  toggleHiddenColumn,
} from './nodeDetailsHelpers'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeNode(
  type: string,
  id: string,
  properties: Record<string, unknown> = {},
  name?: string
): GraphNode {
  return {
    id,
    name: name ?? id,
    type,
    properties,
  }
}

function makeRow(node: GraphNode): TableRow {
  return {
    node,
    connectionsIn: [],
    connectionsOut: [],
    getLevel2: () => [],
    getLevel3: () => [],
  }
}

// ---------------------------------------------------------------------------
// groupRowsByType
// ---------------------------------------------------------------------------

describe('groupRowsByType', () => {
  test('returns empty structures for empty input', () => {
    const r = groupRowsByType([])
    expect(r.sortedTypes).toEqual([])
    expect(r.typeCounts.size).toBe(0)
    expect(r.rowsByType.size).toBe(0)
  })

  test('counts and partitions by type', () => {
    const rows = [
      makeRow(makeNode('Domain', 'd1')),
      makeRow(makeNode('Subdomain', 's1')),
      makeRow(makeNode('Subdomain', 's2')),
      makeRow(makeNode('Domain', 'd2')),
      makeRow(makeNode('IP', 'i1')),
    ]
    const r = groupRowsByType(rows)
    expect(r.typeCounts.get('Domain')).toBe(2)
    expect(r.typeCounts.get('Subdomain')).toBe(2)
    expect(r.typeCounts.get('IP')).toBe(1)
    expect(r.rowsByType.get('Domain')!.map(x => x.node.id)).toEqual(['d1', 'd2'])
    expect(r.rowsByType.get('Subdomain')!.map(x => x.node.id)).toEqual(['s1', 's2'])
  })

  test('sortedTypes is locale-sorted ascending', () => {
    const rows = [
      makeRow(makeNode('Zeta', 'z1')),
      makeRow(makeNode('Alpha', 'a1')),
      makeRow(makeNode('Mike', 'm1')),
    ]
    expect(groupRowsByType(rows).sortedTypes).toEqual(['Alpha', 'Mike', 'Zeta'])
  })

  test('preserves row insertion order within each type', () => {
    const rows = [
      makeRow(makeNode('Domain', 'd1')),
      makeRow(makeNode('Domain', 'd2')),
      makeRow(makeNode('Domain', 'd3')),
    ]
    expect(groupRowsByType(rows).rowsByType.get('Domain')!.map(x => x.node.id)).toEqual([
      'd1',
      'd2',
      'd3',
    ])
  })
})

// ---------------------------------------------------------------------------
// deriveDynamicColumnKeys
// ---------------------------------------------------------------------------

describe('deriveDynamicColumnKeys', () => {
  test('empty rows → empty keys', () => {
    expect(deriveDynamicColumnKeys([])).toEqual([])
  })

  test('union of all property keys across rows, sorted', () => {
    const rows = [
      makeRow(makeNode('Domain', 'd1', { registrar: 'GoDaddy', country: 'US' })),
      makeRow(makeNode('Domain', 'd2', { registrar: 'Namecheap', city: 'NYC' })),
      makeRow(makeNode('Domain', 'd3', { whois_emails: ['a@b.com'] })),
    ]
    expect(deriveDynamicColumnKeys(rows)).toEqual([
      'city',
      'country',
      'registrar',
      'whois_emails',
    ])
  })

  test('omits HIDDEN_KEYS (project_id, user_id)', () => {
    const rows = [
      makeRow(makeNode('Domain', 'd1', { name: 'foo', project_id: 'p1', user_id: 'u1', target: 'x' })),
    ]
    expect(deriveDynamicColumnKeys(rows)).toEqual(['target'])
  })

  test('omits "name" key (always rendered as fixed column)', () => {
    const rows = [
      makeRow(makeNode('Endpoint', 'e1', { name: 'GET /api', method: 'GET' })),
    ]
    expect(deriveDynamicColumnKeys(rows)).toEqual(['method'])
  })

  test('a property present on only ONE row still appears as a column', () => {
    const rows = [
      makeRow(makeNode('Vuln', 'v1', { severity: 'high' })),
      makeRow(makeNode('Vuln', 'v2', { severity: 'low', cwe_id: 'CWE-79' })),
    ]
    expect(deriveDynamicColumnKeys(rows)).toContain('cwe_id')
  })

  test('result is stable across calls (sorted)', () => {
    const rows = [
      makeRow(makeNode('X', '1', { z: 1, a: 2, m: 3 })),
      makeRow(makeNode('X', '2', { b: 4, y: 5 })),
    ]
    const a = deriveDynamicColumnKeys(rows)
    const b = deriveDynamicColumnKeys(rows)
    expect(a).toEqual(b)
    expect(a).toEqual(['a', 'b', 'm', 'y', 'z'])
  })

  test('prioritizes first and last seen metadata before other keys', () => {
    const rows = [
      makeRow(makeNode('Domain', 'd1', {
        registrar: 'GoDaddy',
        last_seen_job_id: 'full-20260529T141530Z-abcdef12',
        first_seen: '2026-05-29T14:15:30Z',
      })),
      makeRow(makeNode('Domain', 'd2', {
        last_seen: '2026-05-29T14:15:30Z',
        first_seen_job_id: 'full-20260529T141530Z-abcdef12',
      })),
    ]

    expect(deriveDynamicColumnKeys(rows)).toEqual([
      'first_seen',
      'last_seen',
      'first_seen_job_id',
      'last_seen_job_id',
      'registrar',
    ])
  })
})

// ---------------------------------------------------------------------------
// toggleHiddenColumn
// ---------------------------------------------------------------------------

describe('toggleHiddenColumn', () => {
  test('adds key when not present', () => {
    expect(toggleHiddenColumn(['a', 'b'], 'c').sort()).toEqual(['a', 'b', 'c'])
  })

  test('removes key when present', () => {
    expect(toggleHiddenColumn(['a', 'b', 'c'], 'b').sort()).toEqual(['a', 'c'])
  })

  test('does not mutate input array', () => {
    const original = ['a', 'b']
    toggleHiddenColumn(original, 'c')
    expect(original).toEqual(['a', 'b'])
  })

  test('toggle twice returns to original membership', () => {
    const after = toggleHiddenColumn(toggleHiddenColumn(['a'], 'b'), 'b')
    expect(after.sort()).toEqual(['a'])
  })

  test('handles empty starting list', () => {
    expect(toggleHiddenColumn([], 'x')).toEqual(['x'])
  })
})
