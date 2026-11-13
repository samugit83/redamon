/**
 * Unit tests for graph formatting utilities.
 *
 * Run: npx vitest run src/app/api/graph/format.test.ts
 */

import { describe, test, expect } from 'vitest'
import { int, type Node } from 'neo4j-driver'
import {
  getNodeName,
  serializeProperties,
  formatGraphRecords,
  type Neo4jNode,
} from './format'
import { driverNode, driverPath, driverRecord, driverRel } from './__testing__/driverValues'

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

  // -- Certificate (Phase 0.7) ---------------------------------------------
  // Before the Certificate branch existed, every certificate fell through to
  // the generic `props.name || props.address || ... || label` chain. A
  // Certificate has none of those properties, so EVERY certificate in the
  // project rendered as the literal string "Certificate" -- indistinguishable
  // from every other one in /graph.
  test('Certificate shows subject CN with the issuer on a second line', () => {
    expect(getNodeName(makeNode('Certificate', {
      subject_cn: 'mail.acme.com',
      issuer: "CN=R3, O=Let's Encrypt",
    }))).toBe("mail.acme.com\nCN=R3, O=Let's Encrypt")
  })

  test('Certificate with no issuer shows just the subject CN', () => {
    expect(getNodeName(makeNode('Certificate', { subject_cn: 'mail.acme.com' })))
      .toBe('mail.acme.com')
  })

  test('SAN-only certificate (empty CN) falls back to its first SAN', () => {
    // Modern certs increasingly ship an empty Subject CN; these are exactly the
    // ones tlsx surfaces, so they must not render as "Certificate".
    expect(getNodeName(makeNode('Certificate', {
      subject_cn: '',
      san: ['mail.acme.com', 'imap.acme.com'],
    }))).toBe('mail.acme.com')
  })

  test('certificate with neither CN nor SAN falls back to cert_key, never the label', () => {
    expect(getNodeName(makeNode('Certificate', { cert_key: 'sha256:aabbcc' })))
      .toBe('sha256:aabbcc')
  })

  test('a certificate never renders as the bare label "Certificate"', () => {
    const name = getNodeName(makeNode('Certificate', { subject_cn: 'a.com', issuer: 'X' }))
    expect(name).not.toBe('Certificate')
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
  // A record of three driver values: two nodes and the relationship between them.
  function makeRecord(source: Node, target: Node, relType: string, relId = 100) {
    const rel = driverRel(relId, source.identity.toNumber(), target.identity.toNumber(), relType)
    return driverRecord({ n: source, m: target, r: rel })
  }

  test('formats a single relationship record', () => {
    const domain = driverNode(1, ['Domain'], { name: 'example.com' })
    const sub = driverNode(2, ['Subdomain'], { name: 'api.example.com' })
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
    const domain = driverNode(1, ['Domain'], { name: 'example.com' })
    const sub1 = driverNode(2, ['Subdomain'], { name: 'api.example.com' })
    const sub2 = driverNode(3, ['Subdomain'], { name: 'www.example.com' })

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

  test('skips null node values but keeps valid nodes', () => {
    // A record where the `n` field is null (e.g. from an OPTIONAL MATCH miss).
    // The formatter scans every key and registers only valid Node objects, so
    // the null `n` contributes nothing while the valid `m` node still registers
    // — and, crucially, the null value does not crash the formatter.
    const nullRecord = driverRecord({ n: null, m: driverNode(5, ['Sub'], { name: 'test' }), r: driverRel(1, 0, 5, 'REL') })
    const result = formatGraphRecords([nullRecord])
    // Only the valid node registers; the null `n` produced no node.
    expect(result.nodes).toHaveLength(1)
    expect(result.nodes[0].id).toBe('5')
    expect(result.nodes[0].name).toBe('test')
  })

  test('serializes Neo4j Int64 properties', () => {
    const node = driverNode(10, ['Port'], { number: int(443) })
    const target = driverNode(11, ['Service'], { name: 'HTTPS' })
    const record = makeRecord(node, target, 'RUNS_SERVICE')

    const result = formatGraphRecords([record])
    expect(result.nodes[0].properties.number).toBe(443)
  })

  test('a path registers each of its nodes and relationships', () => {
    const domain = driverNode(1, ['Domain'], { name: 'example.com' })
    const sub = driverNode(2, ['Subdomain'], { name: 'api.example.com' })
    const ip = driverNode(3, ['IP'], { address: '10.0.0.1' })
    const path = driverPath(domain, [[driverRel(100, 1, 2, 'HAS_SUBDOMAIN'), sub], [driverRel(101, 2, 3, 'RESOLVES_TO'), ip]])

    const result = formatGraphRecords([driverRecord({ p: path })])

    expect(result.nodes.map(n => [n.id, n.type])).toEqual([['1', 'Domain'], ['2', 'Subdomain'], ['3', 'IP']])
    expect(result.links).toEqual([
      { source: '1', target: '2', type: 'HAS_SUBDOMAIN' },
      { source: '2', target: '3', type: 'RESOLVES_TO' },
    ])
  })
})

// A saved view's query writes every value it returns, and can write one shaped like a node or a
// relationship (step 4.9 review). Only what the driver built from a graph structure is one; a
// map the query built is a plain value, a tabular row that graphReadView withholds below R*.
describe('formatGraphRecords: a value the query built is never a graph object', () => {
  const STEP = { project_id: 'p', thought: 'rbac-fake-thought', tool_args_summary: 'sshpass -p rbac-fake-pass ssh admin@app.rbac.test', tool_name: 'ssh' }

  // What the driver hands back for
  //   RETURN {identity: {low: id(s), high: 0}, labels: ['Domain'], properties: properties(s)} AS n
  const forgedNode = () => ({ identity: { low: 7, high: 0 }, labels: ['Domain'], properties: { ...STEP } })
  //   RETURN {type: s.thought, start: {low: 1}, end: {low: 2}} AS r
  const forgedRel = () => ({ type: STEP.thought, start: { low: 1, high: 0 }, end: { low: 2, high: 0 } })

  // The driver assigns a map's keys one by one (`value[key] = ...`), so a map key `__proto__`
  // sets the map's prototype: to a real node, or to a map holding the marker isNode reads.
  function withPrototype(proto: object, own: object): object {
    const map: Record<string, unknown> = {}
    map['__proto__'] = proto
    return Object.assign(map, own)
  }

  test.each([
    ['a map with a node\'s keys', forgedNode()],
    ['a map with the driver\'s node marker as a key', { ...forgedNode(), __isNode__: true }],
    ['a map whose prototype is a map holding the marker', withPrototype({ __isNode__: true }, forgedNode())],
    ['a map whose prototype is a real node', withPrototype(driverNode(1, ['Domain'], { name: 'app.rbac.test' }), forgedNode())],
  ])('%s is a tabular row, not a node', (_what, value) => {
    const { nodes, links } = formatGraphRecords([driverRecord({ n: value })])
    expect(nodes).toHaveLength(1)
    expect(nodes[0]).toMatchObject({ id: 'row-0', type: 'QueryResult' })
    expect(nodes.some(n => n.type === 'Domain')).toBe(false)
    expect(links).toEqual([])
  })

  test.each([
    ['a map with a relationship\'s keys', forgedRel()],
    ['a map with the driver\'s relationship marker', { ...forgedRel(), __isRelationship__: true }],
    ['a map whose prototype is a real relationship', withPrototype(driverRel(9, 1, 2, 'HAS_SUBDOMAIN'), forgedRel())],
  ])('%s is a tabular row, never a link', (_what, value) => {
    const { nodes, links } = formatGraphRecords([driverRecord({ r: value })])
    expect(links).toEqual([])
    expect(nodes.map(n => n.type)).toEqual(['QueryResult'])
  })

  test('a map with a path\'s keys, or the path marker, is a tabular row', () => {
    const fake = { start: forgedNode(), end: forgedNode(), segments: [{ start: forgedNode(), relationship: forgedRel(), end: forgedNode() }], __isPath__: true }
    const { nodes, links } = formatGraphRecords([driverRecord({ p: fake })])
    expect(nodes.map(n => n.type)).toEqual(['QueryResult'])
    expect(links).toEqual([])
  })

  test('beside a real node, a forged one is dropped, not registered', () => {
    const domain = driverNode(1, ['Domain'], { name: 'app.rbac.test' })
    const { nodes, links } = formatGraphRecords([driverRecord({ d: domain, n: forgedNode(), r: forgedRel() })])
    expect(nodes.map(n => n.id)).toEqual(['1'])
    expect(links).toEqual([])
    expect(JSON.stringify(nodes)).not.toMatch(/rbac-fake/)
  })
})

describe('node name truncation', () => {
  // REGRESSION: a GuardDog metadata_mismatch finding stores a multi-line
  // manifest diff in `title`. MalPackageFinding has no `name`, so the fallback
  // chain reached `title` and the whole dump became the node's displayed name.
  const dump =
    'Difference between manifest and package.json found: \n' +
    Array.from({ length: 40 }, (_, i) =>
      `  @next/swc-${i}: Manifest("13.4.7"), package.json("None") \n`).join('')

  // getNodeName takes a NODE, not (label, props). Called with two arguments it
  // threw on `node.labels[0]` and the assertions below never ran, so the guard
  // they exist to protect was effectively untested.
  test('keeps a long multi-line title from becoming the node name', () => {
    const name = getNodeName(makeNode('MalPackageFinding', { title: dump }))
    expect(dump.length).toBeGreaterThan(1000)
    expect(name.length).toBeLessThanOrEqual(80)
    expect(name).not.toContain('\n')
  })

  test('leaves a short name untouched', () => {
    expect(getNodeName(makeNode('Package', { name: 'pkg:npm/axios@1.14.1' })))
      .toBe('pkg:npm/axios@1.14.1')
  })
})
