/**
 * Unit tests for injectProjectFilter.
 *
 * Run: npx vitest run src/app/api/graph-views/execute/injectProjectFilter.test.ts
 */

import { describe, test, expect } from 'vitest'
import { injectProjectFilter, findUnscopedNodePattern, namesMutedLabel, hasVariableLengthPath, findDisallowedCall } from './injectProjectFilter'

describe('injectProjectFilter', () => {
  test('injects project_id into bare node pattern', () => {
    const input = 'MATCH (d:Domain) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain&!Muted {project_id: $projectId}) RETURN d')
  })

  test('injects project_id into node with existing properties', () => {
    const input = 'MATCH (d:Domain {name: "example.com"}) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain&!Muted {project_id: $projectId, name: "example.com"}) RETURN d')
  })

  test('injects into multiple nodes', () => {
    const input = 'MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, s'
    const result = injectProjectFilter(input)
    expect(result).toContain('(d:Domain&!Muted {project_id: $projectId})')
    expect(result).toContain('(s:Subdomain&!Muted {project_id: $projectId})')
  })

  test('skips CVE nodes (global label)', () => {
    const input = 'MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c'
    const result = injectProjectFilter(input)
    expect(result).toContain('(t:Technology&!Muted {project_id: $projectId})')
    expect(result).toContain('(c:CVE)')
    expect(result).not.toContain('(c:CVE {project_id')
  })

  test('skips MitreData nodes (global label)', () => {
    const input = 'MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN c, m'
    const result = injectProjectFilter(input)
    expect(result).toContain('(c:CVE)')
    expect(result).toContain('(m:MitreData)')
    expect(result).not.toContain('(m:MitreData {project_id')
  })

  test('skips Capec nodes (global label)', () => {
    const input = 'MATCH (m:MitreData)-[:HAS_CAPEC]->(cap:Capec) RETURN m, cap'
    const result = injectProjectFilter(input)
    expect(result).not.toContain('(cap:Capec {project_id')
  })

  test('SCOPES ExploitGvm nodes: they are per-tenant data, not reference data', () => {
    // Regression: ExploitGvm was wrongly on the global-exempt list, leaving
    // `MATCH (e:ExploitGvm)` unscoped and cross-tenant.
    const input = 'MATCH (e:ExploitGvm) RETURN e'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (e:ExploitGvm&!Muted {project_id: $projectId}) RETURN e')
  })

  test('preserves existing props on global labels', () => {
    const input = 'MATCH (c:CVE {severity: "CRITICAL"}) RETURN c'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (c:CVE {severity: "CRITICAL"}) RETURN c')
  })

  test('handles complex query with mixed labels', () => {
    const input = `
      MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(ip:IP)
      MATCH (ip)-[:HAS_PORT]->(p:Port)
      MATCH (t:Technology {name: "nginx"})-[:HAS_KNOWN_CVE]->(c:CVE)
      RETURN d, s, ip, p, t, c
    `
    const result = injectProjectFilter(input)
    expect(result).toContain('(d:Domain&!Muted {project_id: $projectId})')
    expect(result).toContain('(s:Subdomain&!Muted {project_id: $projectId})')
    expect(result).toContain('(ip:IP&!Muted {project_id: $projectId})')
    expect(result).toContain('(p:Port&!Muted {project_id: $projectId})')
    expect(result).toContain('(t:Technology&!Muted {project_id: $projectId, name: "nginx"})')
    expect(result).toContain('(c:CVE)')
    expect(result).not.toContain('(c:CVE {project_id')
  })

  test('handles empty braces', () => {
    const input = 'MATCH (d:Domain {}) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain&!Muted {project_id: $projectId}) RETURN d')
  })

  test('handles query with LIMIT', () => {
    const input = 'MATCH (v:Vulnerability {severity: "critical"}) RETURN v LIMIT 50'
    const result = injectProjectFilter(input)
    expect(result).toContain('(v:Vulnerability&!Muted {project_id: $projectId, severity: "critical"})')
    expect(result).toContain('LIMIT 50')
  })
})

describe('injectProjectFilter — cross-tenant node patterns (regression)', () => {
  test('scopes an UNLABELED variable node (the leak vector)', () => {
    // Previously (n) got no project_id and could read across tenants.
    expect(injectProjectFilter('MATCH (n) RETURN n')).toBe(
      'MATCH (n:!Muted {project_id: $projectId}) RETURN n'
    )
  })

  test('scopes an unlabeled variable node with existing props', () => {
    expect(injectProjectFilter('MATCH (n {name: "x"}) RETURN n')).toBe(
      'MATCH (n:!Muted {project_id: $projectId, name: "x"}) RETURN n'
    )
  })

  test('scopes a label-only node (no variable)', () => {
    expect(injectProjectFilter('MATCH (:Host) RETURN 1')).toBe(
      'MATCH (:Host&!Muted {project_id: $projectId}) RETURN 1'
    )
  })

  test('scopes an anonymous node in a relationship path', () => {
    const out = injectProjectFilter('MATCH (a:Host)-[:R]->() RETURN a')
    expect(out).toContain('(a:Host&!Muted {project_id: $projectId})')
    expect(out).toContain('(:!Muted {project_id: $projectId})')
  })

  test('does NOT double-inject the tenant filter, and still adds the mute exclusion (review of 4.6, finding 5)', () => {
    const input = 'MATCH (n:Host {project_id: $projectId}) RETURN n'
    expect(injectProjectFilter(input)).toBe('MATCH (n:Host&!Muted {project_id: $projectId}) RETURN n')
  })

  test('does NOT mangle a function call like count(n)', () => {
    const input = 'MATCH (n:Host) RETURN count(n)'
    const out = injectProjectFilter(input)
    expect(out).toContain('(n:Host&!Muted {project_id: $projectId})')
    expect(out).toContain('count(n)')
    expect(out).not.toContain('count(n {')
  })

  test('does NOT mangle a parenthesized WHERE expression', () => {
    const input = 'MATCH (n:Host) WHERE (n.port > 1000) RETURN n'
    const out = injectProjectFilter(input)
    expect(out).toContain('(n.port > 1000)')
  })
})

describe('findUnscopedNodePattern', () => {
  test('flags a raw unlabeled variable node before injection', () => {
    expect(findUnscopedNodePattern('MATCH (n) RETURN n')).toBe('n')
  })

  test('flags a raw labeled node before injection', () => {
    expect(findUnscopedNodePattern('MATCH (h:Host) RETURN h')).toBe('h:Host')
  })

  test('returns null once injectProjectFilter has scoped the query', () => {
    const cases = [
      'MATCH (n) RETURN n',
      'MATCH (h:Host)-[:R]->(s:Svc) RETURN h, s',
      'MATCH (h:Host)-[:R]->() RETURN h',
      'MATCH (:Host) RETURN 1',
      'MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c',
      'MATCH (n:Host) RETURN count(n)',
    ]
    for (const q of cases) {
      expect(findUnscopedNodePattern(injectProjectFilter(q))).toBeNull()
    }
  })

  test('exempts a reference label ONLY when the query is anchored to tenant data', () => {
    // Anchored: a scoped Technology pattern is present, so the CVE is exempt.
    const anchored = injectProjectFilter('MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c')
    expect(findUnscopedNodePattern(anchored)).toBeNull()
  })

  test('flags a lone reference query with no tenant anchor', () => {
    // `MATCH (c:CVE) RETURN c` would dump every CVE in the database. Mirrors the
    // Python filter's no-anchor refusal.
    expect(findUnscopedNodePattern('MATCH (c:CVE) RETURN c')).toBe('c:CVE')
    expect(findUnscopedNodePattern('MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN c, m')).not.toBeNull()
  })

  test('never exempts a label EXPRESSION that merely mentions a reference label', () => {
    // The hole this closes: `(n:!CVE)` means all NON-CVE nodes (tenant data),
    // and `(n:A|CVE)` is a union. Both must be scoped, not exempted.
    expect(injectProjectFilter('MATCH (n:!CVE) RETURN n')).toContain('project_id: $projectId')
    expect(injectProjectFilter('MATCH (n:Domain|CVE) RETURN n')).toContain('project_id: $projectId')
    expect(findUnscopedNodePattern('MATCH (n:!CVE) RETURN n')).toBe('n:!CVE')
  })

  test('an anonymous waypoint node passes once scoped, and is flagged before (review of 4.6: every node pattern is scoped)', () => {
    const query = 'MATCH (h:Host {project_id: $projectId})-[:R]->() RETURN h'
    expect(findUnscopedNodePattern(injectProjectFilter(query))).toBeNull()
    expect(findUnscopedNodePattern('MATCH (h:Host&!Muted {project_id: $projectId})-[:R]->() RETURN h')).toBe('(anonymous)')
  })
})

describe('variable-length / quantified paths are refused', () => {
  test('flags a variable-length relationship', () => {
    expect(hasVariableLengthPath('MATCH (a:Host)-[*1..3]->(b:Host) RETURN a, b')).toBe(true)
    expect(hasVariableLengthPath('MATCH p=(:CVE)-[*2]-(:CVE) RETURN p')).toBe(true)
    expect(hasVariableLengthPath('MATCH (a)-[:R*]->(b) RETURN a')).toBe(true)
  })

  test('flags a quantified path/relationship', () => {
    expect(hasVariableLengthPath('MATCH ((a)-[:R]->(b)){1,3} RETURN a')).toBe(true)
    expect(hasVariableLengthPath('MATCH (a)-[:R]->{1,3}(b) RETURN a')).toBe(true)
  })

  test('does not flag ordinary fixed-hop paths, list slices or maps', () => {
    expect(hasVariableLengthPath('MATCH (a:Host)-[:R]->(b:Svc) RETURN a, b')).toBe(false)
    expect(hasVariableLengthPath('MATCH (n:Host) RETURN collect(n)[0..2]')).toBe(false)
    expect(hasVariableLengthPath('MATCH (n:Host) RETURN n{.name, .port}')).toBe(false)
    // A `*` inside a string literal is data, not a var-length hop.
    expect(hasVariableLengthPath("MATCH (n:Host) WHERE n.note = '[*]' RETURN n")).toBe(false)
  })
})

describe('namespaced function/procedure calls are refused', () => {
  test('flags apoc function forms that need no CALL', () => {
    expect(findDisallowedCall("RETURN apoc.cypher.runFirstColumnSingle('MATCH (n) RETURN n', {}) AS x")).toBe('apoc.cypher.runFirstColumnSingle')
    expect(findDisallowedCall("RETURN apoc.load.json('http://x/') AS x")).toBe('apoc.load.json')
  })

  test('sees through backticks, spacing and comments', () => {
    expect(findDisallowedCall('RETURN `apoc`.`cypher`.`runFirstColumnMany`("x", {}) AS x')).toBe('apoc.cypher.runFirstColumnMany')
    expect(findDisallowedCall('RETURN apoc . cypher . runFirstColumnSingle("x", {}) AS x')).toBe('apoc.cypher.runFirstColumnSingle')
    expect(findDisallowedCall('RETURN apoc/**/.cypher.runFirstColumnSingle("x", {}) AS x')).toBe('apoc.cypher.runFirstColumnSingle')
  })

  test('allows built-in temporal/spatial functions and plain reads', () => {
    expect(findDisallowedCall('MATCH (n:Host) RETURN duration.between(n.a, n.b)')).toBeNull()
    expect(findDisallowedCall('MATCH (n:Host) RETURN point.distance(n.p, n.q)')).toBeNull()
    expect(findDisallowedCall('MATCH (n:Host) RETURN count(n), toString(id(n)), n.name')).toBeNull()
    // A function name inside a string is data.
    expect(findDisallowedCall("MATCH (n:Host) WHERE n.note = 'apoc.load.json(x)' RETURN n")).toBeNull()
  })
})

describe('suppressed findings are excluded from saved views', () => {
  // A saved view renders into the same graph screen as the live loader, so it
  // is a second enforcement site for mute -- with its own scoping code that
  // does not share a line with graph_db/tenant_filter.py. These mirror
  // tests/test_tenant_filter_muted.py so the two cannot drift apart silently.

  test('every node-pattern shape gets the mute exclusion', () => {
    const cases: [string, string][] = [
      ['MATCH (v:Vulnerability) RETURN v', '(v:Vulnerability&!Muted {'],
      ['MATCH (n) RETURN n', '(n:!Muted {'],
      ['MATCH (:Secret) RETURN 1', '(:Secret&!Muted {'],
      ['MATCH (h:Host)-[:R]->() RETURN h', '(:!Muted {'],
      ['MATCH (n {name: "x"}) RETURN n', '(n:!Muted {'],
    ]
    for (const [query, expected] of cases) {
      expect(injectProjectFilter(query)).toContain(expected)
    }
  })

  test('a union is distributed so the exclusion binds to every branch', () => {
    // `:A|B&!Muted` would mean `A OR (B AND NOT Muted)` and return a muted A.
    // Parentheses would be correct too, but INTERIOR cannot re-parse them.
    expect(injectProjectFilter('MATCH (n:Secret|Vulnerability) RETURN n'))
      .toContain('(n:Secret&!Muted|Vulnerability&!Muted {')
  })

  test('a legacy colon conjunction is respelled, not appended to', () => {
    // Neo4j 5 rejects a pattern mixing ':' conjunction with '&'.
    const out = injectProjectFilter('MATCH (n:Vulnerability:Nuclei) RETURN n')
    expect(out).toContain('(n:Vulnerability&Nuclei&!Muted {')
    expect(out).not.toContain('Vulnerability:Nuclei')
  })

  test('a global reference label gets neither tenant filter nor mute term', () => {
    // Reference nodes carry no project_id and are never muted.
    expect(injectProjectFilter('MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c'))
      .toContain('(c:CVE)')
  })

  test('the rewritten form still passes the backstop', () => {
    // The failure this guards: findUnscopedNodePattern re-scans this function's
    // own output, so a mute term it cannot read means every view is refused.
    const cases = [
      'MATCH (v:Vulnerability) RETURN v',
      'MATCH (n) RETURN n',
      'MATCH (n:Secret|Vulnerability) RETURN n',
      'MATCH (n:Vulnerability:Nuclei) RETURN n',
      'MATCH (h:Host)-[:R]->() RETURN h',
      'MATCH (:Secret) RETURN 1',
    ]
    for (const q of cases) {
      expect(findUnscopedNodePattern(injectProjectFilter(q))).toBeNull()
    }
  })

  test('injecting twice is a no-op', () => {
    for (const q of ['MATCH (v:Vulnerability) RETURN v', 'MATCH (n) RETURN n']) {
      const once = injectProjectFilter(q)
      expect(injectProjectFilter(once)).toBe(once)
    }
  })

  test('naming the reserved label is detected', () => {
    for (const q of [
      'MATCH (n:Muted) RETURN n',
      'MATCH (v:Vulnerability) WHERE v:Muted RETURN v',
      'MATCH (v:Vulnerability) WHERE NOT v:Muted RETURN v',
    ]) {
      expect(namesMutedLabel(q)).toBe(true)
    }
  })

  test('the word in a comment or string literal is not a label reference', () => {
    expect(namesMutedLabel("MATCH (v:Vulnerability) WHERE v.note = 'Muted' RETURN v")).toBe(false)
    expect(namesMutedLabel('MATCH (v:Vulnerability) // Muted\nRETURN v')).toBe(false)
    // Lowercase is an ordinary property name, not the label.
    expect(namesMutedLabel('MATCH (v:Vulnerability) RETURN v.muted')).toBe(false)
  })
})
