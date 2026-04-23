/**
 * Unit tests for graph formatting utilities.
 *
 * Run: npx vitest run src/app/api/graph/format.test.ts
 */

import { describe, test, expect } from 'vitest'
import {
  getNodeName,
  serializeProperties,
  formatGraphRecords,
  type Neo4jNode,
} from './format'

// ---------------------------------------------------------------------------
// Helper to build a minimal Neo4jNode
// ---------------------------------------------------------------------------
function makeNode(
  label: string,
  props: Record<string, unknown> = {},
  id = 1,
): Neo4jNode {
  return {
    identity: { low: id, high: 0 },
    labels: [label],
    properties: props,
  }
}

// ---------------------------------------------------------------------------
// getNodeName
// ---------------------------------------------------------------------------

describe('getNodeName', () => {
  test('Domain returns name property', () => {
    expect(getNodeName(makeNode('Domain', { name: 'example.com' }))).toBe('example.com')
  })

  test('Subdomain returns name property', () => {
    expect(getNodeName(makeNode('Subdomain', { name: 'api.example.com' }))).toBe('api.example.com')
  })

  test('IP returns address property', () => {
    expect(getNodeName(makeNode('IP', { address: '192.168.1.1' }))).toBe('192.168.1.1')
  })

  test('Port shows number/protocol', () => {
    expect(getNodeName(makeNode('Port', { number: 443, protocol: 'tcp' }))).toBe('443/tcp')
  })

  test('Port defaults to tcp protocol', () => {
    expect(getNodeName(makeNode('Port', { number: 80 }))).toBe('80/tcp')
  })

  test('Service shows name:port', () => {
    expect(getNodeName(makeNode('Service', { name: 'HTTP', port_number: 80 }))).toBe('HTTP:80')
  })

  test('Service shows name only when no port', () => {
    expect(getNodeName(makeNode('Service', { name: 'SSH' }))).toBe('SSH')
  })

  test('Technology shows name and version', () => {
    expect(getNodeName(makeNode('Technology', { name: 'nginx', version: '1.18' }))).toBe('nginx v1.18')
  })

  test('Technology shows name only when no version', () => {
    expect(getNodeName(makeNode('Technology', { name: 'nginx' }))).toBe('nginx')
  })

  test('CVE shows id and severity with cvss', () => {
    const result = getNodeName(makeNode('CVE', { id: 'CVE-2021-44228', severity: 'CRITICAL', cvss: 10.0 }))
    expect(result).toBe('CVE-2021-44228\nCRITICAL (10)')
  })

  test('CVE shows id and severity without cvss', () => {
    const result = getNodeName(makeNode('CVE', { id: 'CVE-2021-44228', severity: 'HIGH' }))
    expect(result).toBe('CVE-2021-44228\nHIGH')
  })

  test('CVE shows id only when no severity', () => {
    expect(getNodeName(makeNode('CVE', { id: 'CVE-2021-44228' }))).toBe('CVE-2021-44228')
  })

  test('Endpoint shows method and path', () => {
    expect(getNodeName(makeNode('Endpoint', { method: 'GET', path: '/api/users' }))).toBe('GET /api/users')
  })

  test('Parameter shows name and position', () => {
    expect(getNodeName(makeNode('Parameter', { name: 'id', position: 'query' }))).toBe('id (query)')
  })

  test('Header truncates long values', () => {
    const longValue = 'a'.repeat(50)
    const result = getNodeName(makeNode('Header', { name: 'X-Custom', value: longValue }))
    expect(result).toBe(`X-Custom: ${'a'.repeat(30)}...`)
  })

  test('BaseURL shows scheme://host', () => {
    expect(getNodeName(makeNode('BaseURL', { url: 'https://example.com:8443/path' }))).toBe('https://example.com:8443')
  })

  test('Vulnerability shows name and severity', () => {
    const result = getNodeName(makeNode('Vulnerability', { name: 'SQL Injection', severity: 'critical' }))
    expect(result).toBe('SQL Injection\n[CRITICAL]')
  })

  test('Vulnerability truncates long names', () => {
    const longName = 'A'.repeat(40)
    const result = getNodeName(makeNode('Vulnerability', { name: longName, severity: 'high' }))
    expect(result).toBe(`${'A'.repeat(30)}...\n[HIGH]`)
  })

  test('AttackChain shows title and status', () => {
    const result = getNodeName(makeNode('AttackChain', { title: 'Network Scan', status: 'active' }))
    expect(result).toBe('Step 0\nChain\nNetwork Scan\n[active]')
  })

  test('ChainStep shows iteration and tool', () => {
    const result = getNodeName(makeNode('ChainStep', { iteration: 3, tool_name: 'nmap_scan', success: true }))
    expect(result).toBe('Step 3\nnmap_scan')
  })

  test('ChainStep shows FAIL tag when success is false', () => {
    const result = getNodeName(makeNode('ChainStep', { iteration: 1, tool_name: 'exploit', success: false }))
    expect(result).toBe('Step 1\nexploit\n[FAIL]')
  })

  test('ExploitGvm shows label and target', () => {
    const result = getNodeName(makeNode('ExploitGvm', { target_ip: '10.0.0.1', cve_ids: ['CVE-2021-1234'] }))
    expect(result).toBe('GVM EXPLOIT\nCVE-2021-1234\n10.0.0.1')
  })

  test('DNSRecord shows type and value', () => {
    expect(getNodeName(makeNode('DNSRecord', { type: 'A', value: '1.2.3.4' }))).toBe('A\n1.2.3.4')
  })

  test('MitreData shows cwe_id and name', () => {
    const result = getNodeName(makeNode('MitreData', { cwe_id: 'CWE-79', cwe_name: 'Cross-site Scripting' }))
    expect(result).toBe('CWE-79\nCross-site Scripting')
  })

  test('fallback to generic property', () => {
    expect(getNodeName(makeNode('Unknown', { title: 'My Title' }))).toBe('My Title')
  })

  test('fallback to label when no props match', () => {
    expect(getNodeName(makeNode('CustomType', {}))).toBe('CustomType')
  })
})

// ---------------------------------------------------------------------------
// serializeProperties
// ---------------------------------------------------------------------------

describe('serializeProperties', () => {
  test('converts Neo4j Int64 to number', () => {
    const result = serializeProperties({ count: { low: 42, high: 0 } })
    expect(result.count).toBe(42)
  })

  test('passes through plain values', () => {
    const result = serializeProperties({ name: 'test', flag: true })
    expect(result).toEqual({ name: 'test', flag: true })
  })

  test('converts Int64 inside arrays', () => {
    const result = serializeProperties({
      ids: [{ low: 1, high: 0 }, { low: 2, high: 0 }, 'text'],
    })
    expect(result.ids).toEqual([1, 2, 'text'])
  })

  test('handles null and undefined', () => {
    const result = serializeProperties({ a: null, b: undefined })
    expect(result.a).toBe(null)
    expect(result.b).toBe(undefined)
  })

  test('handles empty object', () => {
    expect(serializeProperties({})).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// formatGraphRecords
// ---------------------------------------------------------------------------

describe('formatGraphRecords', () => {
  function makeRecord(
    source: Neo4jNode,
    target: Neo4jNode,
    relType: string,
    relId = 100,
  ) {
    return {
      get(key: string) {
        if (key === 'n') return source
        if (key === 'm') return target
        if (key === 'r') return {
          identity: { low: relId, high: 0 },
          start: source.identity,
          end: target.identity,
          type: relType,
          properties: {},
        }
        return null
      },
    }
  }

  test('formats a single relationship record', () => {
    const domain = makeNode('Domain', { name: 'example.com' }, 1)
    const sub = makeNode('Subdomain', { name: 'api.example.com' }, 2)
    const record = makeRecord(domain, sub, 'HAS_SUBDOMAIN')

    const result = formatGraphRecords([record])

    expect(result.nodes).toHaveLength(2)
    expect(result.links).toHaveLength(1)
    expect(result.nodes[0].id).toBe('1')
    expect(result.nodes[0].name).toBe('example.com')
    expect(result.nodes[0].type).toBe('Domain')
    expect(result.nodes[1].id).toBe('2')
    expect(result.links[0]).toEqual({ source: '1', target: '2', type: 'HAS_SUBDOMAIN' })
  })

  test('deduplicates nodes by identity', () => {
    const domain = makeNode('Domain', { name: 'example.com' }, 1)
    const sub1 = makeNode('Subdomain', { name: 'api.example.com' }, 2)
    const sub2 = makeNode('Subdomain', { name: 'www.example.com' }, 3)

    const records = [
      makeRecord(domain, sub1, 'HAS_SUBDOMAIN', 100),
      makeRecord(domain, sub2, 'HAS_SUBDOMAIN', 101),
    ]

    const result = formatGraphRecords(records)

    // domain appears only once despite being source in both records
    expect(result.nodes).toHaveLength(3)
    expect(result.links).toHaveLength(2)
  })

  test('handles empty records array', () => {
    const result = formatGraphRecords([])
    expect(result.nodes).toEqual([])
    expect(result.links).toEqual([])
  })

  test('skips records with null nodes', () => {
    const nullRecord = {
      get(key: string) {
        if (key === 'n') return null
        if (key === 'm') return makeNode('Sub', { name: 'test' }, 5)
        if (key === 'r') return { identity: { low: 1, high: 0 }, start: { low: 0, high: 0 }, end: { low: 5, high: 0 }, type: 'REL', properties: {} }
        return null
      },
    }
    const result = formatGraphRecords([nullRecord])
    expect(result.nodes).toEqual([])
    expect(result.links).toEqual([])
  })

  test('serializes Neo4j Int64 properties', () => {
    const node = makeNode('Port', { number: { low: 443, high: 0 } as any }, 10)
    const target = makeNode('Service', { name: 'HTTPS' }, 11)
    const record = makeRecord(node, target, 'RUNS_SERVICE')

    const result = formatGraphRecords([record])
    expect(result.nodes[0].properties.number).toBe(443)
  })
})
