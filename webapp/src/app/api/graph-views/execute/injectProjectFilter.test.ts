/**
 * Unit tests for injectProjectFilter.
 *
 * Run: npx vitest run src/app/api/graph-views/execute/injectProjectFilter.test.ts
 */

import { describe, test, expect } from 'vitest'
import { injectProjectFilter } from './injectProjectFilter'

describe('injectProjectFilter', () => {
  test('injects project_id into bare node pattern', () => {
    const input = 'MATCH (d:Domain) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain {project_id: $projectId}) RETURN d')
  })

  test('injects project_id into node with existing properties', () => {
    const input = 'MATCH (d:Domain {name: "example.com"}) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain {project_id: $projectId, name: "example.com"}) RETURN d')
  })

  test('injects into multiple nodes', () => {
    const input = 'MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, s'
    const result = injectProjectFilter(input)
    expect(result).toContain('(d:Domain {project_id: $projectId})')
    expect(result).toContain('(s:Subdomain {project_id: $projectId})')
  })

  test('skips CVE nodes (global label)', () => {
    const input = 'MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c'
    const result = injectProjectFilter(input)
    expect(result).toContain('(t:Technology {project_id: $projectId})')
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

  test('skips ExploitGvm nodes (global label)', () => {
    const input = 'MATCH (e:ExploitGvm) RETURN e'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (e:ExploitGvm) RETURN e')
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
    expect(result).toContain('(d:Domain {project_id: $projectId})')
    expect(result).toContain('(s:Subdomain {project_id: $projectId})')
    expect(result).toContain('(ip:IP {project_id: $projectId})')
    expect(result).toContain('(p:Port {project_id: $projectId})')
    expect(result).toContain('(t:Technology {project_id: $projectId, name: "nginx"})')
    expect(result).toContain('(c:CVE)')
    expect(result).not.toContain('(c:CVE {project_id')
  })

  test('handles empty braces', () => {
    const input = 'MATCH (d:Domain {}) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain {project_id: $projectId}) RETURN d')
  })

  test('handles query with LIMIT', () => {
    const input = 'MATCH (v:Vulnerability {severity: "critical"}) RETURN v LIMIT 50'
    const result = injectProjectFilter(input)
    expect(result).toContain('(v:Vulnerability {project_id: $projectId, severity: "critical"})')
    expect(result).toContain('LIMIT 50')
  })
})
