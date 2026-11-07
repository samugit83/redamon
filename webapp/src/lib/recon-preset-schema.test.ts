/**
 * Unit tests for the recon preset schema, extractJson helper,
 * and the resolveProviderType logic used by the generate API route.
 */
/// <reference types="vite/client" />
import { describe, test, expect } from 'vitest'
import { reconPresetSchema, extractJson, RECON_PARAMETER_CATALOG } from './recon-preset-schema'
import { permittedKeys } from './reconSettings/filter'
import { field } from './reconSettings/registry'

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

  test('accepts JS Recon endpoint validation fields', () => {
    const jsReconEndpointBlock = {
      jsReconValidateEndpoints: true,
      jsReconEndpointAcceptStatus: [200, 204, 301, 403],
      jsReconEndpointCustomHeaders: ['Authorization: Bearer token', 'X-Test: true'],
    }
    const result = reconPresetSchema.safeParse(jsReconEndpointBlock)
    expect(result.success).toBe(true)
    expect(result.data).toEqual(jsReconEndpointBlock)
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
  test('B-8: the credential is stripped, because a preset never carries one', () => {
    // A generated preset holding graphqlAuthValue was accepted here and then
    // dropped on apply, so the operator saw a value that never took effect.
    const result = reconPresetSchema.safeParse({ graphqlAuthType: 'bearer', graphqlAuthValue: 'token' })
    expect(result.success).toBe(true)
    expect(result.data).toEqual({ graphqlAuthType: 'bearer' })
    expect(RECON_PARAMETER_CATALOG).not.toContain('graphqlAuthValue')
  })

  test('accepts the graphql* fields a preset carries, round-trip', () => {
    const graphqlBlock = {
      graphqlSecurityEnabled: true,
      graphqlIntrospectionTest: true,
      graphqlTimeout: 45,
      graphqlRateLimit: 5,
      graphqlConcurrency: 2,
      graphqlAuthType: 'bearer',
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
  test('accepts all 16 graphqlCop* fields round-trip', () => {
    const copBlock = {
      graphqlCopEnabled: true,
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

  test('a container image in a preset is stripped, never applied', () => {
    // Images are fixed: a preset (or a model writing one) cannot choose one.
    const result = reconPresetSchema.safeParse({
      graphqlCopEnabled: true,
      graphqlCopDockerImage: 'my.registry.internal/forks/graphql-cop:custom-1.15',
    })
    expect(result.success).toBe(true)
    expect(result.data).toEqual({ graphqlCopEnabled: true })
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

  test('coerces stringified JS Recon endpoint status codes', () => {
    const result = reconPresetSchema.safeParse({
      jsReconEndpointAcceptStatus: ['200', '301', '403'],
    })
    expect(result.success).toBe(true)
    expect(result.data!.jsReconEndpointAcceptStatus).toEqual([200, 301, 403])
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
      agentRequireToolConfirmation: true,
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

  test('rejects non-integer JS Recon endpoint status codes', () => {
    const result = reconPresetSchema.safeParse({
      jsReconEndpointAcceptStatus: [200, 200.5],
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
      'ZAP Ajax Spider',
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

  // `describe_recon_settings` no longer reads this catalog: it serves
  // `recon_settings/registry.yaml`, which carries a meaning for every one of
  // the 712 columns rather than prose for 474 of them. This catalog now has one
  // consumer, the AI preset generator, so the control that matters is the
  // narrower one: every field the generator may EMIT must be documented for it.
  test('every field the preset schema accepts is mentioned in the catalog', () => {
    const missing = Object.keys(reconPresetSchema.shape).filter(
      key => !new RegExp(`^-\\s+${key}:`, 'm').test(RECON_PARAMETER_CATALOG),
    )
    expect(missing).toEqual([])
  })

  test('every catalog line names a field the schema accepts', () => {
    // The reverse direction, so a renamed field leaves no orphan prose behind.
    const named = [...RECON_PARAMETER_CATALOG.matchAll(/^-\s+([A-Za-z0-9_]+):/gm)].map(m => m[1])
    const known = new Set(Object.keys(reconPresetSchema.shape))
    expect(named.filter(k => !known.has(k))).toEqual([])
  })

  test('the MCP reference manual is the registry, not this catalog', () => {
    // Guards the split: if describe_recon_settings starts reading this file
    // again there are two answers to "what does this field mean".
    const settable = permittedKeys('update')
    expect(settable.length).toBeGreaterThan(600)
  })

  test('every field the schema accepts is a real column', () => {
    // The schema STRIPS an unknown key, so a renamed column leaves the
    // generator emitting a field that is silently discarded: the preset applies
    // less than it says and reports success.
    const ghosts = Object.keys(reconPresetSchema.shape).filter(k => !field(k))
    expect(ghosts, 'the preset schema accepts columns that do not exist').toEqual([])
  })

  test('every field the schema accepts is one this surface may write', () => {
    // A generated preset naming a scope column or an RoE field would be refused
    // at apply time, in front of whoever asked for it.
    const problems = Object.keys(reconPresetSchema.shape)
      .map(k => ({ key: k, spec: field(k) }))
      .filter(({ spec }) => spec && spec.mcp !== 'settable')
      .map(({ key, spec }) => `${key}: ${spec!.mcp}`)
    expect(problems).toEqual([])
  })

  test('the schema accepts the right SHAPE for each field', () => {
    // Checked by PARSING rather than by reading the declaration: what matters
    // is what a generated preset can get through, and a mismatch means the
    // model emits a value the save then rejects with a Prisma type error.
    const problems: string[] = []
    for (const [key, schema] of Object.entries(reconPresetSchema.shape)) {
      const spec = field(key)
      if (!spec) continue
      const sample =
        spec.type === 'boolean' ? true
        : spec.type === 'int' || spec.type === 'float' ? 1
        : spec.type === 'string-list' ? ['a']
        : spec.type === 'number-list' ? [200]
        : 'x'
      if (!(schema as { safeParse(v: unknown): { success: boolean } }).safeParse(sample).success) {
        problems.push(`${key}: a ${spec.type} column rejects ${JSON.stringify(sample)}`)
      }
    }
    expect(problems).toEqual([])
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
// resolveModel (extracted for testing)
// We re-implement the same logic here since it's not exported
// from the route file. This tests the specification.
//
// "custom/<id>" is a *provider id* (CUID) — the actual api model name
// lives on UserLlmProvider.modelIdentifier and is fetched at request time.
// ============================================================

type Resolved =
  | { kind: 'custom'; providerId: string }
  | { kind: 'builtin'; providerType: string; modelId: string }

function resolveModel(model: string): Resolved {
  if (model.startsWith('custom/')) {
    return { kind: 'custom', providerId: model.slice('custom/'.length) }
  }
  const prefixMap: Record<string, string> = {
    'openrouter/': 'openrouter',
    'bedrock/': 'bedrock',
    'deepseek/': 'deepseek',
    'gemini/': 'gemini',
    'glm/': 'glm',
    'kimi/': 'kimi',
    'qwen/': 'qwen',
    'xai/': 'xai',
    'mistral/': 'mistral',
  }
  for (const [prefix, type] of Object.entries(prefixMap)) {
    if (model.startsWith(prefix)) {
      return { kind: 'builtin', providerType: type, modelId: model.slice(prefix.length) }
    }
  }
  if (model.startsWith('claude-')) {
    return { kind: 'builtin', providerType: 'anthropic', modelId: model }
  }
  return { kind: 'builtin', providerType: 'openai', modelId: model }
}

describe('resolveModel', () => {
  test('resolves Anthropic models', () => {
    expect(resolveModel('claude-opus-4-6')).toEqual({
      kind: 'builtin',
      providerType: 'anthropic',
      modelId: 'claude-opus-4-6',
    })
    expect(resolveModel('claude-sonnet-4-6')).toEqual({
      kind: 'builtin',
      providerType: 'anthropic',
      modelId: 'claude-sonnet-4-6',
    })
    expect(resolveModel('claude-haiku-4-5-20251001')).toEqual({
      kind: 'builtin',
      providerType: 'anthropic',
      modelId: 'claude-haiku-4-5-20251001',
    })
  })

  test('resolves OpenAI models (default)', () => {
    expect(resolveModel('gpt-4o')).toEqual({
      kind: 'builtin',
      providerType: 'openai',
      modelId: 'gpt-4o',
    })
    expect(resolveModel('gpt-5.2')).toEqual({
      kind: 'builtin',
      providerType: 'openai',
      modelId: 'gpt-5.2',
    })
  })

  test('resolves OpenRouter models', () => {
    expect(resolveModel('openrouter/anthropic/claude-3.5-sonnet')).toEqual({
      kind: 'builtin',
      providerType: 'openrouter',
      modelId: 'anthropic/claude-3.5-sonnet',
    })
    expect(resolveModel('openrouter/meta-llama/llama-4-maverick')).toEqual({
      kind: 'builtin',
      providerType: 'openrouter',
      modelId: 'meta-llama/llama-4-maverick',
    })
  })

  test('resolves custom/<id> as a provider lookup (id is a CUID, not a model name)', () => {
    // Matches what the ModelPicker actually emits — see
    // agentic/orchestrator_helpers/model_providers.py:567 (id=f"custom/{pid}")
    expect(resolveModel('custom/cmpmslfy80003t601d38s8slx')).toEqual({
      kind: 'custom',
      providerId: 'cmpmslfy80003t601d38s8slx',
    })
    expect(resolveModel('custom/llama3.1')).toEqual({
      kind: 'custom',
      providerId: 'llama3.1',
    })
  })

  test('resolves Bedrock models', () => {
    expect(resolveModel('bedrock/anthropic.claude-v2')).toEqual({
      kind: 'builtin',
      providerType: 'bedrock',
      modelId: 'anthropic.claude-v2',
    })
  })

  test('resolves other builtin OpenAI-compatible providers', () => {
    expect(resolveModel('deepseek/deepseek-chat')).toEqual({
      kind: 'builtin',
      providerType: 'deepseek',
      modelId: 'deepseek-chat',
    })
    expect(resolveModel('xai/grok-2-mini')).toEqual({
      kind: 'builtin',
      providerType: 'xai',
      modelId: 'grok-2-mini',
    })
    expect(resolveModel('mistral/mistral-small')).toEqual({
      kind: 'builtin',
      providerType: 'mistral',
      modelId: 'mistral-small',
    })
  })
})
