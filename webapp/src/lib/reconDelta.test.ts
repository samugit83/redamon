/**
 * Scan Timeline — Recon Delta diff algorithm (Section 6).
 *
 * The whole feature rests on the stable identity key: node ids are NOT comparable
 * across versions, so if identity is wrong the diff reports the entire graph as
 * replaced. These tests pin the identity rules, the volatile-field exclusions,
 * and the security lenses.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  identityKey,
  computeReconDelta,
  buildDeltaOverlay,
  IDENTITY_KEYS,
  VOLATILE_PROPERTIES,
} from './reconDelta'
import { COVERAGE_STAMP_PROPERTIES } from './coverageStamps'
import type { FormattedGraphData, FormattedNode } from '@/app/api/graph/format'

const node = (
  id: string,
  type: string,
  properties: Record<string, unknown>,
  name = ''
): FormattedNode => ({ id, type, name: name || String(properties.name ?? properties.address ?? id), properties })

const graph = (
  nodes: FormattedNode[],
  links: Array<{ source: string; target: string; type: string }> = []
): FormattedGraphData => ({ nodes, links })

describe('identityKey', () => {
  test('is independent of the node id (ids differ across versions)', () => {
    const a = node('123', 'IP', { address: '10.0.0.1' })
    const b = node('some-uuid', 'IP', { address: '10.0.0.1' })
    expect(identityKey(a)).toBe(identityKey(b))
  })

  test('a port is identified by host + number + protocol, not by number alone', () => {
    const p1 = node('1', 'Port', { ip_address: '10.0.0.1', number: 443, protocol: 'tcp' })
    const p2 = node('2', 'Port', { ip_address: '10.0.0.2', number: 443, protocol: 'tcp' })
    const p3 = node('3', 'Port', { ip_address: '10.0.0.1', number: 443, protocol: 'udp' })
    expect(identityKey(p1)).not.toBe(identityKey(p2))
    expect(identityKey(p1)).not.toBe(identityKey(p3))
  })

  test('technology version is a CHANGE, not a new identity', () => {
    const before = node('1', 'Technology', { name: 'nginx', version: '1.20' })
    const after = node('2', 'Technology', { name: 'nginx', version: '1.25' })
    expect(identityKey(before)).toBe(identityKey(after))
    expect(IDENTITY_KEYS.Technology).toEqual(['name'])
  })

  test('different types never collide', () => {
    expect(identityKey(node('1', 'Subdomain', { name: 'x.tld' })))
      .not.toBe(identityKey(node('2', 'Domain', { name: 'x.tld' })))
  })

  test('an unknown type falls back to the first identifying property', () => {
    const k = identityKey(node('1', 'WeirdThing', { url: 'https://x.tld/a', extra: 1 }))
    expect(k).toBe('WeirdThing::url=https://x.tld/a')
  })

  test('a node with nothing identifying still gets a distinct, volatile-free key', () => {
    const a = identityKey({ id: '1', type: 'Blob', name: '', properties: { a: 1, last_seen: 'monday' } })
    const b = identityKey({ id: '2', type: 'Blob', name: '', properties: { a: 1, last_seen: 'tuesday' } })
    const c = identityKey({ id: '3', type: 'Blob', name: '', properties: { a: 2 } })
    expect(a).toBe(b)      // volatile difference only -> same asset
    expect(a).not.toBe(c)
  })
})

describe('computeReconDelta', () => {
  const before = graph(
    [
      node('1', 'Domain', { name: 'x.tld' }),
      node('2', 'Subdomain', { name: 'www.x.tld' }),
      node('3', 'IP', { address: '10.0.0.1' }),
      node('4', 'Port', { ip_address: '10.0.0.1', number: 22, protocol: 'tcp' }),
      node('5', 'Technology', { name: 'nginx', version: '1.20' }),
      node('6', 'Vulnerability', { template_id: 'old-cve', matched_at: 'https://x.tld', severity: 'high' }),
    ],
    [
      { source: '1', target: '2', type: 'HAS_SUBDOMAIN' },
      { source: '2', target: '3', type: 'RESOLVES_TO' },
      { source: '3', target: '4', type: 'HAS_PORT' },
    ]
  )

  const after = graph(
    [
      node('a', 'Domain', { name: 'x.tld' }),
      node('b', 'Subdomain', { name: 'www.x.tld' }),
      node('c', 'IP', { address: '10.0.0.1' }),
      node('d', 'Port', { ip_address: '10.0.0.1', number: 22, protocol: 'tcp' }),
      // new exposure
      node('e', 'Port', { ip_address: '10.0.0.1', number: 6379, protocol: 'tcp' }),
      // version drift
      node('f', 'Technology', { name: 'nginx', version: '1.25' }),
      // new finding
      node('g', 'Vulnerability', { template_id: 'new-cve', matched_at: 'https://x.tld', severity: 'critical' }),
    ],
    [
      { source: 'a', target: 'b', type: 'HAS_SUBDOMAIN' },
      { source: 'b', target: 'c', type: 'RESOLVES_TO' },
      { source: 'c', target: 'd', type: 'HAS_PORT' },
      { source: 'c', target: 'e', type: 'HAS_PORT' },
    ]
  )

  const delta = computeReconDelta(before, after)

  test('classifies added / removed / changed / stable', () => {
    expect(delta.addedNodes.map(n => n.type).sort()).toEqual(['Port', 'Vulnerability'])
    expect(delta.removedNodes.map(n => n.type)).toEqual(['Vulnerability'])
    expect(delta.changedNodes.map(n => n.name)).toEqual(['nginx'])
    // Domain, Subdomain, IP and the ssh Port carried over untouched.
    expect(delta.totals.stable).toBe(4)
    expect(delta.totals).toMatchObject({ fromNodes: 6, toNodes: 7, added: 2, removed: 1, changed: 1 })
  })

  test('reports the changed field old -> new', () => {
    expect(delta.changedNodes[0].changes).toEqual([{ field: 'version', from: '1.20', to: '1.25' }])
    expect(delta.changedNodes[0].previousProperties).toMatchObject({ version: '1.20' })
  })

  test('diffs relationships by identity, not by node id', () => {
    expect(delta.addedLinks).toHaveLength(1)
    expect(delta.addedLinks[0]).toMatchObject({ type: 'HAS_PORT' })
    expect(delta.addedLinks[0].targetKey).toContain('number=6379')
    // The three carried-over edges must NOT look new just because ids changed.
    expect(delta.removedLinks).toHaveLength(0)
  })

  test('scorecard counts per type, most-changed first', () => {
    const byType = Object.fromEntries(delta.scorecard.map(s => [s.type, s]))
    expect(byType.Port).toMatchObject({ added: 1, removed: 0, changed: 0, fromCount: 1, toCount: 2 })
    expect(byType.Vulnerability).toMatchObject({ added: 1, removed: 1 })
    expect(byType.Technology).toMatchObject({ changed: 1 })
    expect(byType.Domain).toMatchObject({ added: 0, removed: 0, changed: 0 })
    const churn = delta.scorecard.map(s => s.added + s.removed + s.changed)
    expect([...churn]).toEqual([...churn].sort((a, b) => b - a))
  })

  test('security lenses surface the findings that matter', () => {
    expect(delta.lenses.newlyExposedPorts.map(p => p.properties.number)).toEqual([6379])
    expect(delta.lenses.closedPorts).toEqual([])
    expect(delta.lenses.newVulnerabilities.map(v => v.properties.template_id)).toEqual(['new-cve'])
    expect(delta.lenses.resolvedVulnerabilities.map(v => v.properties.template_id)).toEqual(['old-cve'])
    expect(delta.lenses.technologyVersionChanges).toHaveLength(1)
  })

  test('an identical graph with different ids is a no-op diff', () => {
    const reindexed = graph(
      before.nodes.map((n, i) => ({ ...n, id: `re-${i}` })),
      before.links.map(l => ({
        ...l,
        source: `re-${before.nodes.findIndex(n => n.id === l.source)}`,
        target: `re-${before.nodes.findIndex(n => n.id === l.target)}`,
      }))
    )
    const d = computeReconDelta(before, reindexed)
    expect(d.totals).toMatchObject({ added: 0, removed: 0, changed: 0, addedLinks: 0, removedLinks: 0 })
    expect(d.totals.stable).toBe(6)
  })

  test('volatile properties never register as a change', () => {
    const a = graph([node('1', 'IP', { address: '10.0.0.1', last_seen: 'monday', scan_id: 'run-1' })])
    const b = graph([node('2', 'IP', { address: '10.0.0.1', last_seen: 'tuesday', scan_id: 'run-2' })])
    const d = computeReconDelta(a, b)
    expect(d.totals).toMatchObject({ added: 0, removed: 0, changed: 0, stable: 1 })
    expect(VOLATILE_PROPERTIES.has('last_seen')).toBe(true)
  })

  test("an IP's ownership tag tracks target state, so a real change shows (plan 11.3)", () => {
    // The lists are written sorted by recon, so the same state compares equal.
    const props = { address: '198.51.100.20', ownership: 'unknown', current_dns_names: 1,
      ownership_reasons: ['default certificate covers no target domain', 'no CDN or edge signal'],
      default_cert_names: ['a.example.com', 'b.example.com'] }
    for (const p of ['ownership', 'ownership_reasons', 'default_cert_names', 'current_dns_names']) {
      expect(VOLATILE_PROPERTIES.has(p)).toBe(false)
    }
    const a = graph([node('1', 'IP', props)])
    expect(computeReconDelta(a, graph([node('2', 'IP', { ...props })])).totals)
      .toMatchObject({ changed: 0, stable: 1 })
    const moved = graph([node('3', 'IP', { ...props, ownership: 'shared_edge', current_dns_names: 0 })])
    expect(computeReconDelta(a, moved).totals).toMatchObject({ changed: 1 })
  })

  test('a BaseURL coverage stamp never registers as a change (plan 09.1)', () => {
    // Every run restamps every host it looked at; the target did not change.
    for (const p of COVERAGE_STAMP_PROPERTIES) expect(VOLATILE_PROPERTIES.has(p)).toBe(true)
    const a = graph([node('1', 'BaseURL', { url: 'https://app.example.com', js_recon_status: 'complete',
      js_recon_inputs: 4, js_recon_outputs: 0, js_recon_at: 'monday' })])
    const b = graph([node('2', 'BaseURL', { url: 'https://app.example.com', js_recon_status: 'partial',
      js_recon_inputs: 2, js_recon_outputs: 1, js_recon_reason: 'file cap', js_recon_at: 'tuesday',
      nuclei_status: 'complete' })])
    expect(computeReconDelta(a, b).totals).toMatchObject({ changed: 0, stable: 1 })
  })

  test("Jev's assessment of a serialized candidate never registers as a change", () => {
    // Switching Jev off between scans drops the fields; a score drifts between
    // scans of an unchanged blob. The candidate's own format still counts.
    const base = { source: 'serialized_scan', matched_at: 'https://x.tld/api', deser_location: 'data',
                   deser_format: 'native_java' }
    const jev = { deser_jev_format: 'native_java', deser_jev_format_confidence: 99,
                  deser_jev_exploitability: 80, deser_jev_source: 'jev_classifier' }
    const withJev = graph([node('1', 'Vulnerability', { ...base, ...jev })])
    const withoutJev = graph([node('2', 'Vulnerability', base)])
    const drifted = graph([node('3', 'Vulnerability', { ...base, ...jev, deser_jev_exploitability: 64 })])
    expect(computeReconDelta(withJev, withoutJev).totals).toMatchObject({ changed: 0, stable: 1 })
    expect(computeReconDelta(withJev, drifted).totals).toMatchObject({ changed: 0, stable: 1 })
    const reformatted = graph([node('4', 'Vulnerability', { ...base, deser_format: 'jackson_json' })])
    expect(computeReconDelta(withoutJev, reformatted).totals.stable).toBe(0)
  })

  test('a hostname recorded on a target IP changes only when its evidence does', () => {
    // Every IP-mode run re-evaluates every recorded name and stamps the time;
    // the same names with the same reasons are no change, a new reason is one.
    const recorded = { domain: 'web.example.com', sources: ['ptr'], ips_seen: ['203.0.113.10'],
                       ip_hostname_reason: 'record_only', ip_hostname_org: 'example.com' }
    const run1 = graph([node('1', 'ExternalDomain', { ...recorded, ip_hostname_evaluated_at: 'monday' })])
    const run2 = graph([node('2', 'ExternalDomain', { ...recorded, ip_hostname_evaluated_at: 'tuesday' })])
    expect(VOLATILE_PROPERTIES.has('ip_hostname_evaluated_at')).toBe(true)
    expect(computeReconDelta(run1, run2).totals).toMatchObject({ changed: 0, stable: 1 })
    const refused = graph([node('3', 'ExternalDomain', {
      ...recorded, ip_hostname_reason: 'roe_excluded', ip_hostname_evaluated_at: 'wednesday' })])
    const d = computeReconDelta(run2, refused)
    expect(d.totals).toMatchObject({ changed: 1, stable: 0 })
    expect(VOLATILE_PROPERTIES.has('ip_hostname_reason')).toBe(false)
  })

  test('an empty base means everything is new (first comparison)', () => {
    const d = computeReconDelta(graph([]), after)
    expect(d.totals.added).toBe(7)
    expect(d.totals.removed).toBe(0)
  })

  test('a wiped target means everything is removed', () => {
    const d = computeReconDelta(before, graph([]))
    expect(d.totals.removed).toBe(6)
    expect(d.totals.added).toBe(0)
  })

  test('duplicate identities on one side collapse instead of double-counting', () => {
    const dup = graph([
      node('1', 'IP', { address: '10.0.0.1' }),
      node('2', 'IP', { address: '10.0.0.1' }),
    ])
    const d = computeReconDelta(dup, dup)
    expect(d.totals).toMatchObject({ fromNodes: 1, toNodes: 1, added: 0, removed: 0 })
  })
})

describe('the Node ID a delta row carries', () => {
  // A stored version keeps no internal ids, and its nodes may have been deleted
  // or recreated since. Only a node on the side read from the LIVE graph has an
  // id worth showing; everything else must be null, never a guess.
  const past = graph([
    node('x1', 'Port', { ip_address: '10.0.0.1', number: 22, protocol: 'tcp' }),
    node('x2', 'Technology', { name: 'nginx', version: '1.20' }),
  ])
  const live = graph([
    node('y1', 'Port', { ip_address: '10.0.0.1', number: 6379, protocol: 'tcp' }),
    node('y2', 'Technology', { name: 'nginx', version: '1.25' }),
  ])
  const liveIds = new Map([['y1', '101'], ['y2', '102']])

  test('past -> live: added and changed rows name the live node; removed rows cannot', () => {
    const d = computeReconDelta(past, live, { to: liveIds })
    expect(d.addedNodes.map(n => n.nodeId)).toEqual(['101'])
    expect(d.changedNodes.map(n => n.nodeId)).toEqual(['102'])
    expect(d.removedNodes.map(n => n.nodeId)).toEqual([null])
  })

  test('live -> past: a removed row is still in the live graph, an added one is not', () => {
    const d = computeReconDelta(live, past, { from: liveIds })
    expect(d.removedNodes.map(n => n.nodeId)).toEqual(['101'])
    // Changed exists on both sides, so the live side names it.
    expect(d.changedNodes.map(n => n.nodeId)).toEqual(['102'])
    expect(d.addedNodes.map(n => n.nodeId)).toEqual([null])
  })

  test('two stored versions name nothing', () => {
    const d = computeReconDelta(past, live)
    for (const n of [...d.addedNodes, ...d.removedNodes, ...d.changedNodes]) {
      expect(n.nodeId).toBeNull()
    }
  })

  test('a live node the capture has no id for is null, not undefined', () => {
    const d = computeReconDelta(past, live, { to: new Map() })
    expect(d.addedNodes[0].nodeId).toBeNull()
  })
})

describe('buildDeltaOverlay', () => {
  const before = graph([
    node('1', 'IP', { address: '10.0.0.1' }),
    node('2', 'IP', { address: '10.0.0.2' }),
    node('3', 'Technology', { name: 'nginx', version: '1.20' }),
  ])
  const after = graph([
    node('a', 'IP', { address: '10.0.0.1' }),
    node('b', 'IP', { address: '10.0.0.3' }),
    node('c', 'Technology', { name: 'nginx', version: '1.25' }),
  ])

  test('merges both sides and tags every node with its delta state', () => {
    const delta = computeReconDelta(before, after)
    const overlay = buildDeltaOverlay(before, after, delta)
    const states = Object.fromEntries(
      overlay.nodes.map(n => [n.properties.address ?? n.properties.name, n.deltaState])
    )
    expect(states).toEqual({
      '10.0.0.1': 'stable',
      '10.0.0.2': 'removed',
      '10.0.0.3': 'added',
      nginx: 'changed',
    })
  })

  test('a surviving node keeps its CURRENT properties, not the old ones', () => {
    const delta = computeReconDelta(before, after)
    const overlay = buildDeltaOverlay(before, after, delta)
    const tech = overlay.nodes.find(n => n.type === 'Technology')!
    expect(tech.properties.version).toBe('1.25')
  })

  test('overlay ids are identity keys, so links from both sides line up', () => {
    const b = graph([node('1', 'IP', { address: '1.1.1.1' }), node('2', 'Port', { ip_address: '1.1.1.1', number: 80, protocol: 'tcp' })],
      [{ source: '1', target: '2', type: 'HAS_PORT' }])
    const a = graph([node('x', 'IP', { address: '1.1.1.1' }), node('y', 'Port', { ip_address: '1.1.1.1', number: 80, protocol: 'tcp' })],
      [{ source: 'x', target: 'y', type: 'HAS_PORT' }])
    const overlay = buildDeltaOverlay(b, a, computeReconDelta(b, a))
    expect(overlay.links).toHaveLength(1)
    expect(overlay.nodes.map(n => n.id)).toEqual(overlay.nodes.map(n => identityKey(n)))
  })
})

describe('a muted finding is not reported as fixed', () => {
  // Recon Delta lists what disappeared between two scans. A finding that
  // vanished because an operator MUTED it was not remediated, and reporting it
  // under `resolvedVulnerabilities` would overstate the remediation numbers.
  //
  // Both sides of the diff are produced by snapshotToGraphPayload (the "current"
  // side via captureGraphSnapshot, the stored side via loadSnapshot), and that
  // function filters muted nodes out. So by the time the diff runs, a muted
  // finding is absent from BOTH inputs -- which is what makes it appear in
  // neither list. These assert that end state.
  const vuln = (id: string) =>
    node(id, 'Vulnerability', { name: 'SQLi', matched_at: 'https://x.tld/a' })

  test('absent from both sides: neither added nor resolved', () => {
    const before = graph([vuln('1')])
    const after = graph([vuln('2')])
    const delta = computeReconDelta(before, after)

    expect(delta.lenses.resolvedVulnerabilities).toEqual([])
    expect(delta.lenses.newVulnerabilities).toEqual([])
  })

  test('a finding filtered out of the SECOND side only would read as resolved', () => {
    // The failure mode this guards, stated as its opposite: if the payload
    // conversion filtered the stored side but not the live side (or vice versa),
    // the diff would report a mute as a fix. Asserting the asymmetric case
    // produces `resolved` proves the symmetric filtering above is load-bearing.
    const before = graph([vuln('1')])
    const after = graph([])
    const delta = computeReconDelta(before, after)

    expect(delta.lenses.resolvedVulnerabilities).toHaveLength(1)
  })

  test('a genuinely fixed finding is still reported as resolved', () => {
    // Muting must not blunt the feature: a finding that really went away still
    // shows up.
    const before = graph([vuln('1'), node('9', 'IP', { address: '10.0.0.1' })])
    const after = graph([node('9', 'IP', { address: '10.0.0.1' })])
    const delta = computeReconDelta(before, after)

    expect(delta.lenses.resolvedVulnerabilities).toHaveLength(1)
  })
})

describe('recon coverage (circuit breakers)', () => {
  const domain = (props: Record<string, unknown>): FormattedNode =>
    node('d1', 'Domain', { name: 'example.test', ...props }, 'example.test')

  test('is null when no Domain carries a coverage record', () => {
    const delta = computeReconDelta(graph([]), graph([node('1', 'IP', { address: '10.0.0.1' })]))
    expect(delta.coverage).toBeNull()
  })

  test('aggregates distinct sources, skipped hosts and truncation from the newer side', () => {
    const to = graph([
      domain({
        recon_coverage_gaps: JSON.stringify([
          { source: 'shodan', reason: 'x' },
          { source: 'nuclei', reason: 'y' },
        ]),
        recon_skipped_hosts: ['a.example.test:443', 'b.example.test:443'],
        recon_nuclei_truncated: true,
      }),
    ])
    const delta = computeReconDelta(graph([]), to)
    expect(delta.coverage).toEqual({
      sources: ['nuclei', 'shodan'],
      skippedHosts: 2,
      nucleiTruncated: true,
    })
  })

  test('a malformed gaps value fails closed (null), never a partial read', () => {
    const to = graph([domain({ recon_coverage_gaps: '{not json' })])
    expect(computeReconDelta(graph([]), to).coverage).toBeNull()
  })

  test('rejects a gap whose source is over 64 chars (untrusted import)', () => {
    const to = graph([domain({ recon_coverage_gaps: JSON.stringify([{ source: 'x'.repeat(65) }]) })])
    expect(computeReconDelta(graph([]), to).coverage).toBeNull()
  })

  test("a removed scan root's gaps and skipped hosts are not this scope's (§4.11.7)", () => {
    const to = graph([domain({
      name: 'example.test',
      recon_coverage_gaps: JSON.stringify([
        { source: 'shodan', root: 'api.example.test' },
        { source: 'nuclei', root: 'old.example.test' },
        { source: 'urlscan' },
      ]),
      recon_skipped_hosts: ['x.api.example.test:443', 'y.old.example.test:443'],
    })])
    const delta = computeReconDelta(graph([]), to, {}, new Set(['api.example.test']))
    expect(delta.coverage).toEqual({ sources: ['shodan', 'urlscan'], skippedHosts: 1, nucleiTruncated: false })
    // With no scope to compare against nothing is dropped.
    expect(computeReconDelta(graph([]), to).coverage?.sources).toEqual(['nuclei', 'shodan', 'urlscan'])
  })

  test('the org Domain run stamps never make it read as changed', () => {
    const before = graph([domain({ scan_timestamp: 't1', port_scan_timestamp: 't1', recon_coverage_roots: ['a'],
      recon_coverage_run: 'r1', vuln_scan_timestamp: 't1' })])
    const after = graph([domain({ scan_timestamp: 't2', port_scan_timestamp: 't2', recon_coverage_roots: ['a', 'b'],
      recon_coverage_run: 'r2', vuln_scan_timestamp: 't2' })])
    expect(computeReconDelta(before, after).changedNodes).toHaveLength(0)
  })

  test('the coverage record never makes a Domain read as changed', () => {
    const before = graph([domain({ recon_coverage_gaps: '[]', recon_coverage_at: '2026-01-01' })])
    const after = graph([domain({
      recon_coverage_gaps: JSON.stringify([{ source: 'shodan' }]),
      recon_coverage_at: '2026-02-02',
      recon_skipped_hosts: ['a:443'],
      recon_nuclei_truncated: true,
    })])
    const delta = computeReconDelta(before, after)
    expect(delta.changedNodes).toHaveLength(0)
  })
})
