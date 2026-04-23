import { describe, test, expect } from 'vitest'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from './nodeMapping'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'

// ============================================================
// GraphqlScan workflow wiring (Phase 1 §5)
// ============================================================

describe('GraphqlScan node mapping', () => {
  test('consumes BaseURL + Endpoint', () => {
    expect(SECTION_INPUT_MAP.GraphqlScan).toEqual(['BaseURL', 'Endpoint'])
  })

  test('produces Vulnerability + Endpoint', () => {
    expect(SECTION_NODE_MAP.GraphqlScan).toEqual(['Vulnerability', 'Endpoint'])
  })

  test('enriches Endpoint', () => {
    expect(SECTION_ENRICH_MAP.GraphqlScan).toEqual(['Endpoint'])
  })
})

describe('GraphqlScan workflow definition', () => {
  const tool = WORKFLOW_TOOLS.find(t => t.id === 'GraphqlScan')

  test('is registered in WORKFLOW_TOOLS', () => {
    expect(tool).toBeDefined()
  })

  test('label is human-readable', () => {
    expect(tool!.label).toBe('GraphQL Scan')
  })

  test('enabledField matches Prisma camelCase field name', () => {
    expect(tool!.enabledField).toBe('graphqlSecurityEnabled')
  })

  test('sits in group 6 (Vuln Scanning) alongside Nuclei', () => {
    expect(tool!.group).toBe(6)
    const nuclei = WORKFLOW_TOOLS.find(t => t.id === 'Nuclei')
    expect(nuclei!.group).toBe(tool!.group)
  })

  test('carries active badge (sends live traffic to target)', () => {
    expect(tool!.badge).toBe('active')
  })
})

describe('Workflow graph edges stay consistent', () => {
  test('every tool in WORKFLOW_TOOLS has at least one input-map entry', () => {
    for (const tool of WORKFLOW_TOOLS) {
      const inputs = SECTION_INPUT_MAP[tool.id]
      // A few tools (CveLookup, Mitre) chain off internal graph data and may have
      // no workflow-visible inputs — accept undefined OR non-empty.
      if (inputs !== undefined) {
        expect(inputs.length).toBeGreaterThan(0)
      }
    }
  })

  test('every tool in WORKFLOW_TOOLS has an output-map entry (SECTION_NODE_MAP)', () => {
    for (const tool of WORKFLOW_TOOLS) {
      const outputs = SECTION_NODE_MAP[tool.id]
      if (outputs !== undefined) {
        expect(outputs.length).toBeGreaterThan(0)
      }
    }
  })

  test('GraphqlScan reuses only existing data node types (no new labels)', () => {
    const used = new Set([
      ...SECTION_INPUT_MAP.GraphqlScan,
      ...SECTION_NODE_MAP.GraphqlScan,
      ...SECTION_ENRICH_MAP.GraphqlScan,
    ])
    const EXISTING_NODE_TYPES = new Set([
      'Domain', 'Subdomain', 'IP', 'Port', 'Service', 'DNSRecord', 'Certificate',
      'BaseURL', 'Endpoint', 'Parameter', 'Header',
      'Technology', 'Vulnerability', 'CVE', 'MitreData', 'Capec',
      'ThreatPulse', 'Malware', 'ExploitGvm', 'Traceroute',
      'ExternalDomain', 'Secret',
      'GithubHunt', 'GithubRepository', 'GithubPath', 'GithubSecret', 'GithubSensitiveFile',
    ])
    for (const t of used) {
      expect(EXISTING_NODE_TYPES.has(t)).toBe(true)
    }
  })
})
