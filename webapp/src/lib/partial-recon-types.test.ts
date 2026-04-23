import { describe, test, expect } from 'vitest'
import {
  PARTIAL_RECON_SUPPORTED_TOOLS,
  PARTIAL_RECON_PHASES,
  PARTIAL_RECON_PHASE_MAP,
} from './recon-types'
import type {
  PartialReconStatus,
  PartialReconState,
  PartialReconListResponse,
  GraphInputs,
  PartialReconParams,
  UserTargets,
} from './recon-types'

// === PARTIAL_RECON_SUPPORTED_TOOLS ===
describe('PARTIAL_RECON_SUPPORTED_TOOLS', () => {
  test('contains SubdomainDiscovery', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('SubdomainDiscovery')).toBe(true)
  })

  test('contains Naabu', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Naabu')).toBe(true)
  })

  test('contains Masscan', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Masscan')).toBe(true)
  })

  test('contains Nmap', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Nmap')).toBe(true)
  })

  test('contains Httpx', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Httpx')).toBe(true)
  })

  test('contains Katana', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Katana')).toBe(true)
  })

  test('contains Hakrawler', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Hakrawler')).toBe(true)
  })

  test('contains Jsluice', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Jsluice')).toBe(true)
  })

  test('contains JsRecon', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('JsRecon')).toBe(true)
  })

  test('contains Shodan', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Shodan')).toBe(true)
  })

  test('contains OsintEnrichment', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('OsintEnrichment')).toBe(true)
  })

  test('contains SecurityChecks', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('SecurityChecks')).toBe(true)
  })

  test('contains Urlscan', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Urlscan')).toBe(true)
  })

  test('contains Uncover', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Uncover')).toBe(true)
  })

  test('contains Nuclei', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Nuclei')).toBe(true)
  })

  test('contains GraphqlScan (Phase 1 §9.5)', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('GraphqlScan')).toBe(true)
  })

  test('contains SubdomainTakeover', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('SubdomainTakeover')).toBe(true)
  })

  test('does not contain unsupported tools', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('GVM')).toBe(false)
  })
})

// === PARTIAL_RECON_PHASE_MAP ===
describe('PARTIAL_RECON_PHASE_MAP', () => {
  test('has SubdomainDiscovery phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery'][0]).toBe('Subdomain Discovery')
  })

  test('has Naabu phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Naabu']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Naabu'][0]).toBe('Port Scanning')
  })

  test('has Masscan phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Masscan']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Masscan'][0]).toBe('Port Scanning')
  })

  test('has Nmap phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Nmap']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Nmap'][0]).toBe('Nmap Service Detection')
  })

  test('has Httpx phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Httpx']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Httpx'][0]).toBe('HTTP Probing')
  })

  test('has Katana phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Katana']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Katana'][0]).toBe('Resource Enumeration')
  })

  test('has Hakrawler phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Hakrawler']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Hakrawler'][0]).toBe('Resource Enumeration')
  })

  test('has Jsluice phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Jsluice']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Jsluice'][0]).toBe('Resource Enumeration')
  })

  test('has JsRecon phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['JsRecon']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['JsRecon'][0]).toBe('JS Recon')
  })

  test('has Shodan phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Shodan']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Shodan'][0]).toBe('Shodan Enrichment')
  })

  test('has OsintEnrichment phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['OsintEnrichment']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['OsintEnrichment'][0]).toBe('OSINT Enrichment')
  })

  test('has SecurityChecks phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['SecurityChecks']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['SecurityChecks'][0]).toBe('Security Checks')
  })

  test('has Urlscan phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Urlscan']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Urlscan'][0]).toBe('URLScan Enrichment')
  })

  test('has Uncover phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Uncover']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Uncover'][0]).toBe('Uncover Expansion')
  })

  test('has Nuclei phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['Nuclei']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['Nuclei'][0]).toBe('Vulnerability Scanning')
  })

  test('has SubdomainTakeover phases', () => {
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainTakeover']).toHaveLength(1)
    expect(PARTIAL_RECON_PHASE_MAP['SubdomainTakeover'][0]).toBe('Subdomain Takeover Detection')
  })

  test('has GraphqlScan phases (Phase 1 §9.5)', () => {
    const phases = PARTIAL_RECON_PHASE_MAP['GraphqlScan']
    expect(phases).toBeDefined()
    expect(phases.length).toBeGreaterThan(0)
    expect(phases).toContain('Endpoint Discovery')
    expect(phases).toContain('Introspection Testing')
    expect(phases).toContain('Vulnerability Detection')
  })

  test('each supported tool has a phase entry', () => {
    for (const toolId of PARTIAL_RECON_SUPPORTED_TOOLS) {
      expect(PARTIAL_RECON_PHASE_MAP[toolId]).toBeDefined()
      expect(PARTIAL_RECON_PHASE_MAP[toolId].length).toBeGreaterThan(0)
    }
  })
})

// === PARTIAL_RECON_PHASES (backward compat) ===
describe('PARTIAL_RECON_PHASES', () => {
  test('defaults to SubdomainDiscovery phases', () => {
    expect(PARTIAL_RECON_PHASES).toHaveLength(1)
    expect(PARTIAL_RECON_PHASES[0]).toBe('Subdomain Discovery')
  })

  test('is an array', () => {
    expect(Array.isArray(PARTIAL_RECON_PHASES)).toBe(true)
  })
})

// === Type Shape Validation ===
describe('PartialReconState type shape', () => {
  test('default idle state has required fields', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      run_id: 'run-001',
      tool_id: 'SubdomainDiscovery',
      status: 'idle',
      container_id: null,
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    }
    expect(state.project_id).toBe('proj-123')
    expect(state.status).toBe('idle')
    expect(state.stats).toBeNull()
  })

  test('completed state with stats', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      run_id: 'run-002',
      tool_id: 'SubdomainDiscovery',
      status: 'completed',
      container_id: 'abc123',
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:05:00Z',
      error: null,
      stats: { subdomains_total: 15, subdomains_new: 8, subdomains_existing: 7, ips_total: 12 },
    }
    expect(state.stats?.subdomains_new).toBe(8)
    expect(state.stats?.subdomains_existing).toBe(7)
  })

  test('error state with error message', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      run_id: 'run-003',
      tool_id: 'SubdomainDiscovery',
      status: 'error',
      container_id: null,
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:01:00Z',
      error: 'Container exited with code 1',
      stats: null,
    }
    expect(state.error).toBeTruthy()
  })
})

describe('PartialReconStatus values', () => {
  test.each<PartialReconStatus>([
    'idle', 'starting', 'running', 'completed', 'error', 'stopping',
  ])('accepts valid status: %s', (status) => {
    const state: PartialReconState = {
      project_id: 'p', run_id: 'r', tool_id: 't', status,
      container_id: null, started_at: null, completed_at: null, error: null, stats: null,
    }
    expect(state.status).toBe(status)
  })
})

describe('GraphInputs type shape', () => {
  test('from graph source', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 42,
      source: 'graph',
    }
    expect(inputs.source).toBe('graph')
    expect(inputs.existing_subdomains_count).toBe(42)
  })

  test('from settings fallback', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.source).toBe('settings')
    expect(inputs.existing_subdomains_count).toBe(0)
  })

  test('null domain when no data', () => {
    const inputs: GraphInputs = {
      domain: null,
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.domain).toBeNull()
  })

  test('with existing_ips_count for Naabu', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      source: 'graph',
    }
    expect(inputs.existing_ips_count).toBe(5)
  })

  test('with existing_ports_count for Nmap', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      existing_ports_count: 23,
      source: 'graph',
    }
    expect(inputs.existing_ports_count).toBe(23)
  })

  test('with existing_baseurls_count for Httpx', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 10,
      existing_ips_count: 5,
      existing_ports_count: 23,
      existing_baseurls_count: 8,
      source: 'graph',
    }
    expect(inputs.existing_baseurls_count).toBe(8)
  })

  test('with existing_baseurls for Katana dropdown', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      existing_baseurls_count: 3,
      existing_baseurls: ['https://example.com', 'https://api.example.com', 'https://www.example.com'],
      source: 'graph',
    }
    expect(inputs.existing_baseurls).toHaveLength(3)
    expect(inputs.existing_baseurls).toContain('https://api.example.com')
  })
})

describe('PartialReconParams type shape', () => {
  test('minimal params', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('SubdomainDiscovery')
    expect(params.user_inputs).toHaveLength(0)
    expect(params.settings_overrides).toBeUndefined()
  })

  test('full params with user inputs and overrides', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: ['api.example.com', 'admin.example.com'],
      settings_overrides: { SUBFINDER_ENABLED: false },
    }
    expect(params.user_inputs).toHaveLength(2)
    expect(params.settings_overrides).toBeDefined()
  })

  test('Naabu params with structured user_targets', () => {
    const targets: UserTargets = {
      subdomains: ['api.example.com'],
      ips: ['10.0.0.1', '192.168.1.0/24'],
      ip_attach_to: 'api.example.com',
    }
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: targets,
    }
    expect(params.tool_id).toBe('Naabu')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(2)
    expect(params.user_targets?.ip_attach_to).toBe('api.example.com')
  })

  test('Naabu params with generic IPs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: [], ips: ['10.0.0.1'], ip_attach_to: null },
    }
    expect(params.user_targets?.ip_attach_to).toBeNull()
  })

  test('Naabu params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Naabu',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Nmap params with structured user_targets', () => {
    const params: PartialReconParams = {
      tool_id: 'Nmap',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: [], ips: ['10.0.0.1'], ip_attach_to: null, ports: [8443, 9090] },
    }
    expect(params.tool_id).toBe('Nmap')
    expect(params.user_targets?.ips).toHaveLength(1)
    expect(params.user_targets?.ip_attach_to).toBeNull()
    expect(params.user_targets?.ports).toHaveLength(2)
    expect(params.user_targets?.ports).toContain(8443)
  })

  test('Nmap params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Nmap',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Httpx params with structured user_targets', () => {
    const params: PartialReconParams = {
      tool_id: 'Httpx',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: { subdomains: ['api.example.com'], ips: [], ip_attach_to: null },
    }
    expect(params.tool_id).toBe('Httpx')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(0)
  })

  test('Httpx params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Httpx',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Masscan params with structured user_targets', () => {
    const targets: UserTargets = {
      subdomains: ['api.example.com'],
      ips: ['10.0.0.1', '192.168.1.0/24'],
      ip_attach_to: 'api.example.com',
    }
    const params: PartialReconParams = {
      tool_id: 'Masscan',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: targets,
    }
    expect(params.tool_id).toBe('Masscan')
    expect(params.user_targets?.subdomains).toHaveLength(1)
    expect(params.user_targets?.ips).toHaveLength(2)
    expect(params.user_targets?.ip_attach_to).toBe('api.example.com')
  })

  test('Katana params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Katana',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com', 'https://api.example.com:8443'],
        url_attach_to: 'https://example.com',
      },
    }
    expect(params.tool_id).toBe('Katana')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBe('https://example.com')
  })

  test('Katana params with generic URLs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Katana',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com'], url_attach_to: null,
      },
    }
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('Katana params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Katana',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Hakrawler params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Hakrawler',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com', 'https://api.example.com'],
        url_attach_to: null,
      },
    }
    expect(params.tool_id).toBe('Hakrawler')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('Hakrawler params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Hakrawler',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Jsluice params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Jsluice',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com/js/app.js', 'https://example.com/js/vendor.js'],
        url_attach_to: 'https://example.com',
      },
    }
    expect(params.tool_id).toBe('Jsluice')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBe('https://example.com')
  })

  test('Jsluice params with generic URLs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Jsluice',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com/js/app.js'], url_attach_to: null,
      },
    }
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('Jsluice params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Jsluice',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('JsRecon params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'JsRecon',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com/assets/app.js', 'https://example.com/assets/vendor.js'],
        url_attach_to: 'https://example.com',
      },
    }
    expect(params.tool_id).toBe('JsRecon')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBe('https://example.com')
  })

  test('JsRecon params with generic URLs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'JsRecon',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com/assets/app.js'], url_attach_to: null,
      },
    }
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('JsRecon params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'JsRecon',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Shodan params (graph only, no user inputs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Shodan',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('Shodan')
    expect(params.user_targets).toBeUndefined()
  })

  test('OsintEnrichment params (graph only, no user inputs)', () => {
    const params: PartialReconParams = {
      tool_id: 'OsintEnrichment',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('OsintEnrichment')
    expect(params.user_targets).toBeUndefined()
  })

  test('SecurityChecks params (graph only, no user inputs)', () => {
    const params: PartialReconParams = {
      tool_id: 'SecurityChecks',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('SecurityChecks')
    expect(params.user_targets).toBeUndefined()
  })

  test('Urlscan params (graph only, no user inputs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Urlscan',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('Urlscan')
    expect(params.user_targets).toBeUndefined()
  })

  test('Nuclei params with structured user_targets (URLs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Nuclei',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com', 'https://api.example.com:8443'],
        url_attach_to: 'https://example.com',
      },
    }
    expect(params.tool_id).toBe('Nuclei')
    expect(params.user_targets?.urls).toHaveLength(2)
    expect(params.user_targets?.url_attach_to).toBe('https://example.com')
  })

  test('Nuclei params with generic URLs (no attach)', () => {
    const params: PartialReconParams = {
      tool_id: 'Nuclei',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      user_targets: {
        subdomains: [], ips: [], ip_attach_to: null,
        urls: ['https://example.com/login'], url_attach_to: null,
      },
    }
    expect(params.user_targets?.url_attach_to).toBeNull()
  })

  test('Nuclei params without user_targets (graph only)', () => {
    const params: PartialReconParams = {
      tool_id: 'Nuclei',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.user_targets).toBeUndefined()
  })

  test('Uncover params (domain only, no user inputs)', () => {
    const params: PartialReconParams = {
      tool_id: 'Uncover',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
    }
    expect(params.tool_id).toBe('Uncover')
    expect(params.user_targets).toBeUndefined()
  })
})

describe('GraphInputs with existing_subdomains', () => {
  test('Naabu graph inputs include subdomain list', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 2,
      existing_subdomains: ['www.example.com', 'api.example.com'],
      existing_ips_count: 5,
      source: 'graph',
    }
    expect(inputs.existing_subdomains).toHaveLength(2)
    expect(inputs.existing_subdomains).toContain('api.example.com')
  })

  test('Nuclei graph inputs include BaseURLs list and Endpoints count', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      existing_baseurls_count: 3,
      existing_baseurls: ['https://example.com', 'https://api.example.com', 'https://www.example.com'],
      existing_endpoints_count: 42,
      source: 'graph',
    }
    expect(inputs.existing_baseurls).toHaveLength(3)
    expect(inputs.existing_baseurls).toContain('https://api.example.com')
    expect(inputs.existing_endpoints_count).toBe(42)
  })

  test('SecurityChecks graph inputs include subdomains, IPs, and BaseURLs counts', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 3,
      existing_ips_count: 5,
      existing_baseurls_count: 2,
      source: 'graph',
    }
    expect(inputs.existing_subdomains_count).toBe(3)
    expect(inputs.existing_ips_count).toBe(5)
    expect(inputs.existing_baseurls_count).toBe(2)
  })
})

// === PartialReconListResponse (parallel recon) ===
describe('PartialReconListResponse type shape', () => {
  test('empty runs list', () => {
    const resp: PartialReconListResponse = {
      project_id: 'proj-1',
      runs: [],
    }
    expect(resp.runs).toHaveLength(0)
    expect(resp.project_id).toBe('proj-1')
  })

  test('multiple concurrent runs', () => {
    const resp: PartialReconListResponse = {
      project_id: 'proj-1',
      runs: [
        {
          project_id: 'proj-1', run_id: 'r1', tool_id: 'Naabu',
          status: 'running', container_id: 'c1', started_at: '2026-04-14T10:00:00Z',
          completed_at: null, error: null, stats: null,
        },
        {
          project_id: 'proj-1', run_id: 'r2', tool_id: 'Httpx',
          status: 'starting', container_id: 'c2', started_at: '2026-04-14T10:01:00Z',
          completed_at: null, error: null, stats: null,
        },
        {
          project_id: 'proj-1', run_id: 'r3', tool_id: 'SubdomainDiscovery',
          status: 'completed', container_id: null, started_at: '2026-04-14T09:50:00Z',
          completed_at: '2026-04-14T09:55:00Z', error: null, stats: { subdomains_new: 5 },
        },
      ],
    }
    expect(resp.runs).toHaveLength(3)
    expect(resp.runs[0].run_id).toBe('r1')
    expect(resp.runs[1].status).toBe('starting')
    expect(resp.runs[2].stats?.subdomains_new).toBe(5)
  })

  test('each run has unique run_id', () => {
    const resp: PartialReconListResponse = {
      project_id: 'proj-1',
      runs: [
        { project_id: 'proj-1', run_id: 'aaa', tool_id: 'Naabu', status: 'running', container_id: null, started_at: null, completed_at: null, error: null, stats: null },
        { project_id: 'proj-1', run_id: 'bbb', tool_id: 'Naabu', status: 'running', container_id: null, started_at: null, completed_at: null, error: null, stats: null },
      ],
    }
    const runIds = resp.runs.map(r => r.run_id)
    expect(new Set(runIds).size).toBe(runIds.length)
  })

  test('same tool can appear multiple times', () => {
    const resp: PartialReconListResponse = {
      project_id: 'proj-1',
      runs: [
        { project_id: 'proj-1', run_id: 'r1', tool_id: 'Naabu', status: 'running', container_id: null, started_at: null, completed_at: null, error: null, stats: null },
        { project_id: 'proj-1', run_id: 'r2', tool_id: 'Naabu', status: 'starting', container_id: null, started_at: null, completed_at: null, error: null, stats: null },
      ],
    }
    expect(resp.runs[0].tool_id).toBe('Naabu')
    expect(resp.runs[1].tool_id).toBe('Naabu')
    expect(resp.runs[0].run_id).not.toBe(resp.runs[1].run_id)
  })
})

describe('PartialReconState run_id field', () => {
  test('run_id is required in state', () => {
    const state: PartialReconState = {
      project_id: 'proj-1',
      run_id: '550e8400-e29b-41d4-a716-446655440000',
      tool_id: 'Katana',
      status: 'running',
      container_id: 'abc',
      started_at: '2026-04-14T10:00:00Z',
      completed_at: null,
      error: null,
      stats: null,
    }
    expect(state.run_id).toBe('550e8400-e29b-41d4-a716-446655440000')
    expect(state.run_id.length).toBe(36)
  })

  test('stopping state with run_id', () => {
    const state: PartialReconState = {
      project_id: 'proj-1',
      run_id: 'stop-run',
      tool_id: 'Nuclei',
      status: 'stopping',
      container_id: 'xyz',
      started_at: '2026-04-14T10:00:00Z',
      completed_at: null,
      error: null,
      stats: null,
    }
    expect(state.status).toBe('stopping')
    expect(state.run_id).toBe('stop-run')
  })
})
