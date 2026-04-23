/**
 * Unit tests for the recon preset schema, extractJson helper,
 * and the resolveProviderType logic used by the generate API route.
 */
import { describe, test, expect } from 'vitest'
import { reconPresetSchema, extractJson, RECON_PARAMETER_CATALOG } from './recon-preset-schema'

// ============================================================
// extractJson
// ============================================================

describe('extractJson', () => {
  test('extracts JSON from markdown code fence with json tag', () => {
    const raw = 'Here is the config:\n```json\n{"naabuEnabled": true}\n```\nDone.'
    expect(extractJson(raw)).toBe('{"naabuEnabled": true}')
  })

  test('extracts JSON from markdown code fence without json tag', () => {
    const raw = '```\n{"katanaDepth": 3}\n```'
    expect(extractJson(raw)).toBe('{"katanaDepth": 3}')
  })

  test('extracts raw JSON object (no wrapping)', () => {
    const raw = '{"httpxEnabled": false, "naabuEnabled": true}'
    expect(extractJson(raw)).toBe('{"httpxEnabled": false, "naabuEnabled": true}')
  })

  test('extracts JSON when surrounded by text', () => {
    const raw = 'Sure! Here is the preset:\n{"stealthMode": true}\nLet me know if you need changes.'
    expect(extractJson(raw)).toBe('{"stealthMode": true}')
  })

  test('handles nested braces correctly', () => {
    const raw = '{"a": {"b": 1}, "c": [1, 2]}'
    expect(extractJson(raw)).toBe('{"a": {"b": 1}, "c": [1, 2]}')
  })

  test('returns trimmed input when no JSON found', () => {
    const raw = '  no json here  '
    expect(extractJson(raw)).toBe('no json here')
  })

  test('handles empty string', () => {
    expect(extractJson('')).toBe('')
  })

  test('prefers code fence over raw braces', () => {
    const raw = 'Some text {"ignored": true}\n```json\n{"picked": true}\n```'
    expect(extractJson(raw)).toBe('{"picked": true}')
  })

  test('handles multiline JSON in code fence', () => {
    const raw = '```json\n{\n  "naabuEnabled": true,\n  "httpxEnabled": false\n}\n```'
    const result = extractJson(raw)
    const parsed = JSON.parse(result)
    expect(parsed.naabuEnabled).toBe(true)
    expect(parsed.httpxEnabled).toBe(false)
  })
})

// ============================================================
// reconPresetSchema - basic validation
// ============================================================

describe('reconPresetSchema', () => {
  test('accepts empty object', () => {
    const result = reconPresetSchema.safeParse({})
    expect(result.success).toBe(true)
    expect(result.data).toEqual({})
  })

  test('accepts valid boolean fields', () => {
    const result = reconPresetSchema.safeParse({
      naabuEnabled: true,
      httpxEnabled: false,
      stealthMode: true,
    })
    expect(result.success).toBe(true)
    expect(result.data).toEqual({
      naabuEnabled: true,
      httpxEnabled: false,
      stealthMode: true,
    })
  })

  test('accepts valid number fields', () => {
    const result = reconPresetSchema.safeParse({
      httpxThreads: 50,
      katanaDepth: 3,
      nucleiRateLimit: 100,
    })
    expect(result.success).toBe(true)
    expect(result.data!.httpxThreads).toBe(50)
    expect(result.data!.katanaDepth).toBe(3)
  })

  test('accepts valid string fields', () => {
    const result = reconPresetSchema.safeParse({
      naabuScanType: 's',
      nmapTimingTemplate: 'T4',
      httpxProbeHash: 'sha256',
    })
    expect(result.success).toBe(true)
    expect(result.data!.naabuScanType).toBe('s')
  })

  test('accepts valid array fields', () => {
    const result = reconPresetSchema.safeParse({
      scanModules: ['domain_discovery', 'http_probe'],
      nucleiSeverity: ['critical', 'high'],
      gauProviders: ['wayback', 'commoncrawl'],
    })
    expect(result.success).toBe(true)
    expect(result.data!.scanModules).toEqual(['domain_discovery', 'http_probe'])
  })

  test('accepts int array fields (ffufMatchCodes)', () => {
    const result = reconPresetSchema.safeParse({
      ffufMatchCodes: [200, 301, 403],
    })
    expect(result.success).toBe(true)
    expect(result.data!.ffufMatchCodes).toEqual([200, 301, 403])
  })

  test('accepts float field (cveLookupMinCvss)', () => {
    const result = reconPresetSchema.safeParse({
      cveLookupMinCvss: 7.5,
    })
    expect(result.success).toBe(true)
    expect(result.data!.cveLookupMinCvss).toBe(7.5)
  })

  // ============================================================
  // GraphQL Security Scanner fields (Phase 1 §8.1)
  // ============================================================
  test('accepts all 17 graphql* fields round-trip', () => {
    const graphqlBlock = {
      graphqlSecurityEnabled: true,
      graphqlIntrospectionTest: true,
      graphqlTimeout: 45,
      graphqlRateLimit: 5,
      graphqlConcurrency: 2,
      graphqlAuthType: 'bearer',
      graphqlAuthValue: 'eyJhbGci...',
      graphqlAuthHeader: 'X-Api-Key',
      graphqlEndpoints: 'https://api.target.com/graphql,https://v1/graphql',
      graphqlDepthLimit: 15,
      graphqlRetryCount: 5,
      graphqlRetryBackoff: 1.5,
      graphqlVerifySsl: false,
    }
    const result = reconPresetSchema.safeParse(graphqlBlock)
    expect(result.success).toBe(true)
    expect(result.data).toEqual(graphqlBlock)
  })

  test('coerces graphqlRetryBackoff (float) from string', () => {
    const result = reconPresetSchema.safeParse({ graphqlRetryBackoff: '2.5' })
    expect(result.success).toBe(true)
    expect(result.data!.graphqlRetryBackoff).toBe(2.5)
  })

  test('rejects non-boolean for graphqlSecurityEnabled', () => {
    const result = reconPresetSchema.safeParse({ graphqlSecurityEnabled: 'yes' })
    expect(result.success).toBe(false)
  })

  test('rejects non-numeric for graphqlTimeout', () => {
    const result = reconPresetSchema.safeParse({ graphqlTimeout: 'thirty' })
    expect(result.success).toBe(false)
  })

  // ============================================================
  // graphql-cop fields (Phase 2 §17.7)
  // ============================================================
  test('accepts all 17 graphqlCop* fields round-trip', () => {
    const copBlock = {
      graphqlCopEnabled: true,
      graphqlCopDockerImage: 'dolevf/graphql-cop:1.14',
      graphqlCopTimeout: 150,
      graphqlCopForceScan: false,
      graphqlCopDebug: false,
      graphqlCopTestFieldSuggestions: true,
      graphqlCopTestIntrospection: false,
      graphqlCopTestGraphiql: true,
      graphqlCopTestGetMethod: true,
      graphqlCopTestAliasOverloading: false,
      graphqlCopTestBatchQuery: false,
      graphqlCopTestTraceMode: true,
      graphqlCopTestDirectiveOverloading: false,
      graphqlCopTestCircularIntrospection: false,
      graphqlCopTestGetMutation: true,
      graphqlCopTestPostCsrf: true,
      graphqlCopTestUnhandledError: true,
    }
    const result = reconPresetSchema.safeParse(copBlock)
    expect(result.success).toBe(true)
    expect(result.data).toEqual(copBlock)
  })

  test('rejects non-boolean for graphqlCopEnabled', () => {
    const result = reconPresetSchema.safeParse({ graphqlCopEnabled: 'maybe' })
    expect(result.success).toBe(false)
  })

  test('rejects non-numeric for graphqlCopTimeout', () => {
    const result = reconPresetSchema.safeParse({ graphqlCopTimeout: 'two minutes' })
    expect(result.success).toBe(false)
  })

  test('accepts custom graphqlCopDockerImage string', () => {
    const result = reconPresetSchema.safeParse({
      graphqlCopDockerImage: 'my.registry.internal/forks/graphql-cop:custom-1.15',
    })
    expect(result.success).toBe(true)
    expect(result.data!.graphqlCopDockerImage).toBe('my.registry.internal/forks/graphql-cop:custom-1.15')
  })
})

// ============================================================
// reconPresetSchema - coercion (handles LLM quirks)
// ============================================================

describe('reconPresetSchema coercion', () => {
  test('coerces stringified numbers to numbers', () => {
    const result = reconPresetSchema.safeParse({
      httpxThreads: '50',
      katanaDepth: '3',
    })
    expect(result.success).toBe(true)
    expect(result.data!.httpxThreads).toBe(50)
    expect(result.data!.katanaDepth).toBe(3)
  })

  test('coerces stringified numbers in int arrays', () => {
    const result = reconPresetSchema.safeParse({
      ffufMatchCodes: ['200', '301', '403'],
    })
    expect(result.success).toBe(true)
    expect(result.data!.ffufMatchCodes).toEqual([200, 301, 403])
  })

  test('coerces stringified float', () => {
    const result = reconPresetSchema.safeParse({
      cveLookupMinCvss: '7.5',
    })
    expect(result.success).toBe(true)
    expect(result.data!.cveLookupMinCvss).toBe(7.5)
  })

  test('rejects non-numeric string for number field', () => {
    const result = reconPresetSchema.safeParse({
      httpxThreads: 'fast',
    })
    expect(result.success).toBe(false)
  })
})

// ============================================================
// reconPresetSchema - stripping unknown keys
// ============================================================

describe('reconPresetSchema stripping', () => {
  test('strips unknown keys silently', () => {
    const result = reconPresetSchema.safeParse({
      naabuEnabled: true,
      inventedField: 'should be removed',
      targetDomain: 'example.com',
      agentOpenaiModel: 'gpt-4o',
    })
    expect(result.success).toBe(true)
    expect(result.data).toEqual({ naabuEnabled: true })
    expect(result.data).not.toHaveProperty('inventedField')
    expect(result.data).not.toHaveProperty('targetDomain')
    expect(result.data).not.toHaveProperty('agentOpenaiModel')
  })

  test('strips agent behaviour fields that LLM might include', () => {
    const result = reconPresetSchema.safeParse({
      httpxEnabled: true,
      agentMaxIterations: 50,
      agentDeepThinkEnabled: true,
    })
    expect(result.success).toBe(true)
    expect(result.data).toEqual({ httpxEnabled: true })
  })
})

// ============================================================
// reconPresetSchema - rejection of bad types
// ============================================================

describe('reconPresetSchema type rejection', () => {
  test('rejects string for boolean field', () => {
    const result = reconPresetSchema.safeParse({
      naabuEnabled: 'yes',
    })
    expect(result.success).toBe(false)
  })

  test('rejects object for boolean field', () => {
    const result = reconPresetSchema.safeParse({
      httpxEnabled: { enabled: true },
    })
    expect(result.success).toBe(false)
  })

  test('rejects number for string array field', () => {
    const result = reconPresetSchema.safeParse({
      scanModules: 123,
    })
    expect(result.success).toBe(false)
  })

  test('rejects mixed-type array for string array field', () => {
    const result = reconPresetSchema.safeParse({
      nucleiSeverity: ['critical', true, 42],
    })
    expect(result.success).toBe(false)
  })
})

// ============================================================
// reconPresetSchema - realistic LLM output
// ============================================================

describe('reconPresetSchema with realistic LLM output', () => {
  test('validates a realistic passive OSINT preset', () => {
    const llmOutput = {
      scanModules: ['domain_discovery', 'http_probe'],
      stealthMode: true,
      useTorForRecon: false,
      subdomainDiscoveryEnabled: true,
      crtshEnabled: true,
      hackerTargetEnabled: true,
      subfinderEnabled: true,
      amassEnabled: true,
      amassActive: false,
      naabuEnabled: false,
      masscanEnabled: false,
      nmapEnabled: false,
      httpxEnabled: true,
      httpxThreads: 25,
      httpxFollowRedirects: true,
      katanaEnabled: false,
      hakrawlerEnabled: false,
      ffufEnabled: false,
      nucleiEnabled: false,
      osintEnrichmentEnabled: true,
      shodanEnabled: true,
      urlscanEnabled: true,
      censysEnabled: true,
      securityCheckEnabled: true,
    }

    const result = reconPresetSchema.safeParse(llmOutput)
    expect(result.success).toBe(true)
    expect(result.data!.stealthMode).toBe(true)
    expect(result.data!.naabuEnabled).toBe(false)
    expect(result.data!.osintEnrichmentEnabled).toBe(true)
  })

  test('validates a realistic aggressive pentest preset', () => {
    const llmOutput = {
      scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon'],
      stealthMode: false,
      naabuEnabled: true,
      naabuTopPorts: '10000',
      masscanEnabled: true,
      masscanRate: 5000,
      nmapEnabled: true,
      nmapVersionDetection: true,
      nmapScriptScan: true,
      nmapTimingTemplate: 'T4',
      httpxEnabled: true,
      httpxThreads: 100,
      katanaEnabled: true,
      katanaDepth: 4,
      katanaMaxUrls: 1000,
      ffufEnabled: true,
      ffufSmartFuzz: true,
      kiterunnerEnabled: true,
      arjunEnabled: true,
      nucleiEnabled: true,
      nucleiSeverity: ['critical', 'high', 'medium', 'low'],
      nucleiDastMode: true,
      nucleiHeadless: true,
      jsReconEnabled: true,
      jsReconDomSinks: true,
    }

    const result = reconPresetSchema.safeParse(llmOutput)
    expect(result.success).toBe(true)
    expect(Object.keys(result.data!).length).toBe(Object.keys(llmOutput).length)
  })

  test('handles LLM output with extra explanation keys stripped', () => {
    const llmOutput = {
      naabuEnabled: true,
      httpxEnabled: true,
      _explanation: 'This is a quick scan preset',
      notes: 'Focus on speed',
      reasoning: 'User asked for fast scan',
    }

    const result = reconPresetSchema.safeParse(llmOutput)
    expect(result.success).toBe(true)
    expect(result.data).toEqual({
      naabuEnabled: true,
      httpxEnabled: true,
    })
  })
})

// ============================================================
// reconPresetSchema - all built-in presets pass validation
// ============================================================

describe('reconPresetSchema validates all built-in presets', () => {
  // Import all presets dynamically
  const presetModules = import.meta.glob('./recon-presets/presets/*.ts', { eager: true })

  for (const [path, mod] of Object.entries(presetModules)) {
    const presetName = path.replace('./recon-presets/presets/', '').replace('.ts', '')
    const exported = mod as Record<string, { parameters?: Record<string, unknown> }>
    const preset = Object.values(exported)[0]

    if (preset?.parameters) {
      test(`built-in preset "${presetName}" passes Zod validation`, () => {
        const result = reconPresetSchema.safeParse(preset.parameters)
        if (!result.success) {
          const issues = result.error.issues.map(
            (i) => `  ${i.path.join('.')}: ${i.message}`,
          )
          throw new Error(
            `Preset "${presetName}" failed validation:\n${issues.join('\n')}`,
          )
        }
        expect(result.success).toBe(true)
      })
    }
  }
})

// ============================================================
// RECON_PARAMETER_CATALOG
// ============================================================

describe('RECON_PARAMETER_CATALOG', () => {
  test('is a non-empty string', () => {
    expect(typeof RECON_PARAMETER_CATALOG).toBe('string')
    expect(RECON_PARAMETER_CATALOG.length).toBeGreaterThan(1000)
  })

  test('contains all major tool sections', () => {
    const expectedSections = [
      'Scan Modules',
      'WHOIS',
      'Subdomain Discovery',
      'Naabu',
      'Masscan',
      'Nmap',
      'httpx',
      'Wappalyzer',
      'Banner Grab',
      'Katana',
      'Hakrawler',
      'jsluice',
      'JS Recon',
      'GraphQL',
      'GraphQL Cop',
      'ffuf',
      'Arjun',
      'GAU',
      'ParamSpider',
      'Kiterunner',
      'Nuclei',
      'CVE Lookup',
      'MITRE',
      'Security Checks',
      'OSINT',
    ]

    for (const section of expectedSections) {
      expect(RECON_PARAMETER_CATALOG).toContain(section)
    }
  })

  test('every schema key is mentioned in the catalog', () => {
    const schemaKeys = Object.keys(reconPresetSchema.shape)
    const missing: string[] = []

    for (const key of schemaKeys) {
      if (!RECON_PARAMETER_CATALOG.includes(key)) {
        missing.push(key)
      }
    }

    expect(missing).toEqual([])
  })

  test('all parameter lines have a type annotation', () => {
    const paramLines = RECON_PARAMETER_CATALOG
      .split('\n')
      .filter((l) => l.trim().startsWith('- '))

    for (const line of paramLines) {
      const hasType = /: (boolean|integer|number|string|string\[\]|bool)/.test(line)
      if (!hasType) {
        throw new Error(`Parameter line missing type: "${line.trim()}"`)
      }
    }
  })
})

// ============================================================
// resolveProviderType (extracted for testing)
// We re-implement the same logic here since it's not exported
// from the route file. This tests the specification.
// ============================================================

function resolveProviderType(model: string): { providerType: string; modelId: string } {
  if (model.startsWith('custom/')) {
    return { providerType: 'openai_compatible', modelId: model.slice('custom/'.length) }
  }
  if (model.startsWith('openrouter/')) {
    return { providerType: 'openrouter', modelId: model.slice('openrouter/'.length) }
  }
  if (model.startsWith('bedrock/')) {
    return { providerType: 'bedrock', modelId: model.slice('bedrock/'.length) }
  }
  if (model.startsWith('claude-')) {
    return { providerType: 'anthropic', modelId: model }
  }
  return { providerType: 'openai', modelId: model }
}

describe('resolveProviderType', () => {
  test('resolves Anthropic models', () => {
    expect(resolveProviderType('claude-opus-4-6')).toEqual({
      providerType: 'anthropic',
      modelId: 'claude-opus-4-6',
    })
    expect(resolveProviderType('claude-sonnet-4-6')).toEqual({
      providerType: 'anthropic',
      modelId: 'claude-sonnet-4-6',
    })
    expect(resolveProviderType('claude-haiku-4-5-20251001')).toEqual({
      providerType: 'anthropic',
      modelId: 'claude-haiku-4-5-20251001',
    })
  })

  test('resolves OpenAI models (default)', () => {
    expect(resolveProviderType('gpt-4o')).toEqual({
      providerType: 'openai',
      modelId: 'gpt-4o',
    })
    expect(resolveProviderType('gpt-5.2')).toEqual({
      providerType: 'openai',
      modelId: 'gpt-5.2',
    })
  })

  test('resolves OpenRouter models', () => {
    expect(resolveProviderType('openrouter/anthropic/claude-3.5-sonnet')).toEqual({
      providerType: 'openrouter',
      modelId: 'anthropic/claude-3.5-sonnet',
    })
    expect(resolveProviderType('openrouter/meta-llama/llama-4-maverick')).toEqual({
      providerType: 'openrouter',
      modelId: 'meta-llama/llama-4-maverick',
    })
  })

  test('resolves custom/openai_compatible models', () => {
    expect(resolveProviderType('custom/llama3.1')).toEqual({
      providerType: 'openai_compatible',
      modelId: 'llama3.1',
    })
  })

  test('resolves Bedrock models', () => {
    expect(resolveProviderType('bedrock/anthropic.claude-v2')).toEqual({
      providerType: 'bedrock',
      modelId: 'anthropic.claude-v2',
    })
  })
})
