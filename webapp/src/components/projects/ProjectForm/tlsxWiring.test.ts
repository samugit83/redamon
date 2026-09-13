/**
 * Wiring tests for Tlsx across the project-form / workflow-graph layer.
 *
 * H6: the partial-recon backend for tlsx was complete -- a dispatch branch in
 * `recon/partial_recon.py`, a `run_tlsx` module, input/output/enrich node maps,
 * and even a modal test -- but `Tlsx` was never added to
 * PARTIAL_RECON_SUPPORTED_TOOLS, which is the single flag that renders the play
 * button. So the feature existed and had no way to be started, and nothing
 * failed: the modal test passes because it drives the modal directly.
 *
 * Every other layer has a test that would catch its own omission. This is the
 * one that catches the registration.
 *
 * Mirrors vhostSniWiring.test.ts.
 */
import { describe, test, expect } from 'vitest'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from './nodeMapping'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'
import { PARTIAL_RECON_SUPPORTED_TOOLS, PARTIAL_RECON_PHASE_MAP } from '@/lib/recon-types'

const EXISTING_NODE_TYPES = new Set([
  'Domain', 'Subdomain', 'IP', 'Port', 'Service', 'DNSRecord', 'Certificate',
  'BaseURL', 'Endpoint', 'Parameter', 'Header',
  'Technology', 'Vulnerability', 'CVE', 'MitreData', 'Capec',
  'ThreatPulse', 'Malware', 'ExploitGvm', 'Traceroute',
  'ExternalDomain', 'Secret', 'UserInput',
  'GithubHunt', 'GithubRepository', 'GithubPath', 'GithubSecret', 'GithubSensitiveFile',
])

describe('WORKFLOW_TOOLS -- Tlsx entry', () => {
  const tool = WORKFLOW_TOOLS.find(t => t.id === 'Tlsx')

  test('is registered', () => {
    expect(tool).toBeDefined()
  })

  test('enabledField matches the Prisma camelCase column', () => {
    expect(tool!.enabledField).toBe('tlsxEnabled')
  })

  test('sits in the port-scan group, because it consumes open ports', () => {
    expect(tool!.group).toBe(3)
  })

  test('is badged active: it sends real handshakes', () => {
    expect(tool!.badge).toBe('active')
  })
})

describe('partial recon registration', () => {
  test('Tlsx renders a play button', () => {
    expect(
      PARTIAL_RECON_SUPPORTED_TOOLS.has('Tlsx'),
      'recon/partial_recon.py dispatches Tlsx, but the UI shows no way to start it',
    ).toBe(true)
  })

  test('Tlsx has a non-empty phase list for the progress readout', () => {
    const phases = PARTIAL_RECON_PHASE_MAP['Tlsx']
    expect(phases, 'missing phases fall back to a bare "Running"').toBeDefined()
    expect(phases.length).toBeGreaterThan(0)
  })

  test('every partial-capable tool has a phase list', () => {
    for (const id of PARTIAL_RECON_SUPPORTED_TOOLS) {
      expect(PARTIAL_RECON_PHASE_MAP[id], `${id} has no phase list`).toBeDefined()
    }
  })
})

describe('node maps use existing labels only', () => {
  test('inputs are IP and Port, both graph-sourced', () => {
    expect(SECTION_INPUT_MAP.Tlsx).toEqual(['IP', 'Port'])
  })

  test('outputs are Certificate and Subdomain', () => {
    expect(SECTION_NODE_MAP.Tlsx).toEqual(['Certificate', 'Subdomain'])
  })

  test('it enriches Service rather than creating one', () => {
    // Service.name is part of the MERGE key, so tlsx must never create one.
    expect(SECTION_ENRICH_MAP.Tlsx).toEqual(['Service'])
  })

  test('no map invents a node label', () => {
    for (const [map, name] of [
      [SECTION_INPUT_MAP.Tlsx, 'SECTION_INPUT_MAP'],
      [SECTION_NODE_MAP.Tlsx, 'SECTION_NODE_MAP'],
      [SECTION_ENRICH_MAP.Tlsx, 'SECTION_ENRICH_MAP'],
    ] as const) {
      for (const label of map || []) {
        expect(EXISTING_NODE_TYPES.has(label), `${name} invents ${label}`).toBe(true)
      }
    }
  })
})
