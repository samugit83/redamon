/**
 * Unit tests for the User Project Preset utility functions.
 *
 * Tests verify:
 *   - extractPresetSettings correctly strips excluded fields
 *   - extractPresetSettings preserves all non-excluded fields
 *   - PRESET_EXCLUDED_FIELDS set contains exactly the expected fields
 *   - Forward-compatibility: defaults-merge strategy works correctly
 *   - Edge cases: empty objects, unknown fields, nested JSON values
 */
import { describe, test, expect } from 'vitest'
import { PRESET_EXCLUDED_FIELDS, extractPresetSettings } from './project-preset-utils'

// ============================================================
// PRESET_EXCLUDED_FIELDS
// ============================================================

describe('PRESET_EXCLUDED_FIELDS', () => {
  test('is a Set', () => {
    expect(PRESET_EXCLUDED_FIELDS).toBeInstanceOf(Set)
  })

  test('contains all target-specific fields', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('targetDomain')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('subdomainList')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('ipMode')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('targetIps')).toBe(true)
  })

  test('contains project identity fields', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('name')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('description')).toBe(true)
  })

  test('contains binary/file-tied fields', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('roeDocumentData')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('roeDocumentName')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('roeDocumentMimeType')).toBe(true)
    expect(PRESET_EXCLUDED_FIELDS.has('jsReconUploadedFiles')).toBe(true)
  })

  test('has exactly 10 excluded fields', () => {
    expect(PRESET_EXCLUDED_FIELDS.size).toBe(10)
  })

  test('does NOT exclude recon settings fields', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('naabuEnabled')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('nucleiEnabled')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('katanaDepth')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('scanModules')).toBe(false)
  })

  test('does NOT exclude agent behaviour fields', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('agentOpenaiModel')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('agentMaxIterations')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('agentToolPhaseMap')).toBe(false)
  })

  test('does NOT exclude reconPresetId (should be preserved)', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('reconPresetId')).toBe(false)
  })

  test('does NOT exclude RoE text/rule fields (only binary)', () => {
    expect(PRESET_EXCLUDED_FIELDS.has('roeEnabled')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('roeRawText')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('roeClientName')).toBe(false)
    expect(PRESET_EXCLUDED_FIELDS.has('roeForbiddenTools')).toBe(false)
  })
})

// ============================================================
// extractPresetSettings
// ============================================================

describe('extractPresetSettings', () => {
  test('strips all excluded fields', () => {
    const formData: Record<string, unknown> = {
      name: 'Test Project',
      description: 'A description',
      targetDomain: 'example.com',
      subdomainList: ['sub1.example.com'],
      ipMode: false,
      targetIps: ['192.168.1.1'],
      roeDocumentData: Buffer.from('binary'),
      roeDocumentName: 'roe.pdf',
      roeDocumentMimeType: 'application/pdf',
      jsReconUploadedFiles: ['file1.js'],
      // These should be preserved:
      naabuEnabled: true,
      nucleiEnabled: false,
      agentMaxIterations: 50,
    }

    const result = extractPresetSettings(formData)

    // Excluded fields should be absent
    expect(result).not.toHaveProperty('name')
    expect(result).not.toHaveProperty('description')
    expect(result).not.toHaveProperty('targetDomain')
    expect(result).not.toHaveProperty('subdomainList')
    expect(result).not.toHaveProperty('ipMode')
    expect(result).not.toHaveProperty('targetIps')
    expect(result).not.toHaveProperty('roeDocumentData')
    expect(result).not.toHaveProperty('roeDocumentName')
    expect(result).not.toHaveProperty('roeDocumentMimeType')
    expect(result).not.toHaveProperty('jsReconUploadedFiles')

    // Preserved fields should be present with correct values
    expect(result.naabuEnabled).toBe(true)
    expect(result.nucleiEnabled).toBe(false)
    expect(result.agentMaxIterations).toBe(50)
  })

  test('returns empty object when all fields are excluded', () => {
    const formData: Record<string, unknown> = {
      name: 'Test',
      targetDomain: 'example.com',
    }
    const result = extractPresetSettings(formData)
    expect(Object.keys(result).length).toBe(0)
  })

  test('returns all fields when none are excluded', () => {
    const formData: Record<string, unknown> = {
      naabuEnabled: true,
      nucleiEnabled: false,
      katanaDepth: 3,
      reconPresetId: 'full-active-scan',
    }
    const result = extractPresetSettings(formData)
    expect(Object.keys(result).length).toBe(4)
    expect(result).toEqual(formData)
  })

  test('handles empty input', () => {
    const result = extractPresetSettings({})
    expect(result).toEqual({})
  })

  test('preserves complex value types (arrays, objects, null)', () => {
    const formData: Record<string, unknown> = {
      scanModules: ['port_scan', 'vuln_scan'],
      agentToolPhaseMap: { query_graph: ['informational'] },
      nucleiTemplates: [],
      agentLport: null,
      naabuEnabled: true,
      katanaTimeout: 3600,
      httpxProbeHash: 'sha256',
    }

    const result = extractPresetSettings(formData)

    expect(result.scanModules).toEqual(['port_scan', 'vuln_scan'])
    expect(result.agentToolPhaseMap).toEqual({ query_graph: ['informational'] })
    expect(result.nucleiTemplates).toEqual([])
    expect(result.agentLport).toBeNull()
    expect(result.naabuEnabled).toBe(true)
    expect(result.katanaTimeout).toBe(3600)
    expect(result.httpxProbeHash).toBe('sha256')
  })

  test('preserves boolean false values (not accidentally filtered)', () => {
    const formData: Record<string, unknown> = {
      gauEnabled: false,
      stealthMode: false,
      ffufEnabled: false,
    }
    const result = extractPresetSettings(formData)
    expect(result.gauEnabled).toBe(false)
    expect(result.stealthMode).toBe(false)
    expect(result.ffufEnabled).toBe(false)
  })

  test('preserves zero and empty string values', () => {
    const formData: Record<string, unknown> = {
      ffufRate: 0,
      agentInformationalSystemPrompt: '',
      nucleiRetries: 0,
    }
    const result = extractPresetSettings(formData)
    expect(result.ffufRate).toBe(0)
    expect(result.agentInformationalSystemPrompt).toBe('')
    expect(result.nucleiRetries).toBe(0)
  })

  test('does not mutate input object', () => {
    const formData: Record<string, unknown> = {
      name: 'Test',
      naabuEnabled: true,
    }
    const original = { ...formData }
    extractPresetSettings(formData)
    expect(formData).toEqual(original)
  })
})

// ============================================================
// Forward-compatibility: defaults-merge strategy
// ============================================================

describe('defaults-merge strategy', () => {
  // Simulates what UserPresetDrawer does: { ...defaults, ...presetSettings }

  test('preset values override defaults', () => {
    const defaults = {
      naabuEnabled: true,
      naabuTopPorts: '1000',
      katanaDepth: 2,
    }
    const presetSettings = {
      naabuEnabled: false,
      naabuTopPorts: '100',
      katanaDepth: 5,
    }

    const merged = { ...defaults, ...presetSettings }

    expect(merged.naabuEnabled).toBe(false)
    expect(merged.naabuTopPorts).toBe('100')
    expect(merged.katanaDepth).toBe(5)
  })

  test('missing fields in preset fall through to defaults', () => {
    const defaults = {
      naabuEnabled: true,
      nucleiEnabled: true,
      // newFieldAddedLater is a field that didn't exist when preset was saved
      newFieldAddedLater: 'default-value',
      anotherNewField: 42,
    }
    const presetSettings = {
      naabuEnabled: false,
      nucleiEnabled: false,
      // Does NOT have newFieldAddedLater or anotherNewField
    }

    const merged = { ...defaults, ...presetSettings }

    expect(merged.naabuEnabled).toBe(false)     // from preset
    expect(merged.nucleiEnabled).toBe(false)     // from preset
    expect(merged.newFieldAddedLater).toBe('default-value')  // from defaults
    expect(merged.anotherNewField).toBe(42)      // from defaults
  })

  test('empty preset results in pure defaults', () => {
    const defaults = {
      naabuEnabled: true,
      nucleiEnabled: true,
      katanaDepth: 2,
    }
    const presetSettings = {}

    const merged = { ...defaults, ...presetSettings }

    expect(merged).toEqual(defaults)
  })

  test('preset can override with falsy values (false, 0, empty string)', () => {
    const defaults = {
      naabuEnabled: true,
      katanaDepth: 2,
      agentInformationalSystemPrompt: 'default prompt',
    }
    const presetSettings = {
      naabuEnabled: false,
      katanaDepth: 0,
      agentInformationalSystemPrompt: '',
    }

    const merged = { ...defaults, ...presetSettings }

    expect(merged.naabuEnabled).toBe(false)
    expect(merged.katanaDepth).toBe(0)
    expect(merged.agentInformationalSystemPrompt).toBe('')
  })

  test('target fields are absent from both defaults and preset (preserved from form)', () => {
    const defaults = {
      naabuEnabled: true,
    }
    const presetSettings = {
      naabuEnabled: false,
    }

    const merged = { ...defaults, ...presetSettings }

    // Target fields should never be in the merged result
    expect(merged).not.toHaveProperty('targetDomain')
    expect(merged).not.toHaveProperty('subdomainList')
    expect(merged).not.toHaveProperty('ipMode')
    expect(merged).not.toHaveProperty('targetIps')
    expect(merged).not.toHaveProperty('name')
  })

  test('reconPresetId preserved in preset for badge sync', () => {
    const defaults = {
      naabuEnabled: true,
    }
    const presetSettings = {
      naabuEnabled: false,
      reconPresetId: 'full-active-scan',
    }

    const merged = { ...defaults, ...presetSettings }
    expect(merged.reconPresetId).toBe('full-active-scan')
  })

  test('reconPresetId null in preset clears badge', () => {
    const defaults = {
      naabuEnabled: true,
    }
    const presetSettings = {
      naabuEnabled: false,
      reconPresetId: null,
    }

    const merged = { ...defaults, ...presetSettings }
    expect(merged.reconPresetId).toBeNull()
  })
})

// ============================================================
// Integration: full roundtrip (extract -> merge -> verify)
// ============================================================

describe('preset roundtrip', () => {
  test('extract then merge preserves all non-excluded fields', () => {
    const formData: Record<string, unknown> = {
      // Excluded (target/identity)
      name: 'My Project',
      description: 'My description',
      targetDomain: 'example.com',
      subdomainList: ['a.example.com'],
      ipMode: false,
      targetIps: [],
      roeDocumentData: null,
      roeDocumentName: '',
      roeDocumentMimeType: '',
      jsReconUploadedFiles: [],
      // Included
      naabuEnabled: true,
      nucleiEnabled: false,
      katanaDepth: 4,
      scanModules: ['port_scan'],
      agentMaxIterations: 200,
      reconPresetId: 'stealth-recon',
      agentToolPhaseMap: { kali_shell: ['exploitation'] },
      roeEnabled: true,
      roeClientName: 'ACME Corp',
    }

    // Step 1: Extract (what SavePresetModal does)
    const settings = extractPresetSettings(formData)

    // Verify excluded fields are gone
    expect(settings).not.toHaveProperty('name')
    expect(settings).not.toHaveProperty('targetDomain')
    expect(settings).not.toHaveProperty('subdomainList')

    // Step 2: Merge with defaults (what UserPresetDrawer does)
    const defaults: Record<string, unknown> = {
      naabuEnabled: false,       // will be overridden by preset
      nucleiEnabled: true,       // will be overridden by preset
      katanaDepth: 2,            // will be overridden by preset
      newFutureField: 'future',  // not in preset, should survive
    }

    const merged = { ...defaults, ...settings }

    // Preset values win
    expect(merged.naabuEnabled).toBe(true)
    expect(merged.nucleiEnabled).toBe(false)
    expect(merged.katanaDepth).toBe(4)
    expect(merged.scanModules).toEqual(['port_scan'])
    expect(merged.agentMaxIterations).toBe(200)
    expect(merged.reconPresetId).toBe('stealth-recon')
    expect(merged.roeEnabled).toBe(true)
    expect(merged.roeClientName).toBe('ACME Corp')

    // Defaults fill in gaps
    expect(merged.newFutureField).toBe('future')

    // Target fields still absent
    expect(merged).not.toHaveProperty('name')
    expect(merged).not.toHaveProperty('targetDomain')
  })

  test('extracting twice from same data is idempotent', () => {
    const formData: Record<string, unknown> = {
      name: 'X',
      targetDomain: 'x.com',
      naabuEnabled: true,
      katanaDepth: 3,
    }

    const first = extractPresetSettings(formData)
    const second = extractPresetSettings(formData)

    expect(first).toEqual(second)
  })

  test('extracting from a realistic form snapshot produces clean JSON-safe output', () => {
    // Simulate a realistic subset of ProjectFormData
    const formData: Record<string, unknown> = {
      name: 'Pentest ACME',
      description: 'Q2 external pentest',
      targetDomain: 'acme.com',
      subdomainList: [],
      ipMode: false,
      targetIps: [],
      roeDocumentData: null,
      roeDocumentName: '',
      roeDocumentMimeType: '',
      jsReconUploadedFiles: [],
      reconPresetId: 'full-active-scan',
      scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
      naabuEnabled: true,
      naabuTopPorts: '1000',
      naabuRateLimit: 1000,
      masscanEnabled: true,
      masscanRate: 5000,
      nmapEnabled: true,
      httpxEnabled: true,
      nucleiEnabled: true,
      nucleiSeverity: ['critical', 'high', 'medium', 'low'],
      nucleiDastMode: true,
      katanaEnabled: true,
      katanaDepth: 4,
      katanaMaxUrls: 2000,
      ffufEnabled: true,
      gauEnabled: false,
      agentOpenaiModel: 'claude-opus-4-6',
      agentMaxIterations: 100,
      agentToolPhaseMap: { query_graph: ['informational', 'exploitation'] },
      roeEnabled: true,
      roeClientName: 'ACME',
      stealthMode: false,
    }

    const settings = extractPresetSettings(formData)

    // Should be JSON-serializable (no binary data, no circular refs)
    const json = JSON.stringify(settings)
    const parsed = JSON.parse(json)
    expect(parsed).toEqual(settings)

    // Should have all non-excluded fields
    expect(Object.keys(settings).length).toBe(Object.keys(formData).length - PRESET_EXCLUDED_FIELDS.size)
  })
})
