import { describe, expect, test } from 'vitest'
import { normalizeOpenApiSourceIds, validateOpenApiSettings } from './openapiSettings'

describe('validateOpenApiSettings', () => {
  test('accepts configured sources and origin-bound discovery headers', () => {
    expect(validateOpenApiSettings({
      openapiEnabled: true,
      openapiAutoDiscover: true,
      openapiTimeout: 10,
      openapiMaxDocuments: 50,
      openapiSources: [{
        id: 'source-primary',
        url: 'https://docs.example.test/openapi.yaml',
        headers: ['Authorization: Bearer secret'],
        serverOverride: 'https://api.example.test/v2',
        enabled: true,
      }],
      openapiDiscoveryHeaders: [{
        origin: 'https://docs.example.test',
        headers: ['X-API-Key: secret'],
      }],
    })).toBeNull()
  })

  test('allows a source to omit optional headers', () => {
    expect(validateOpenApiSettings({
      openapiSources: [{ url: 'https://docs.example.test/openapi.json' }],
    })).toBeNull()
  })

  test('adds stable ids only to sources that do not already have one', () => {
    let sequence = 0
    const sources = normalizeOpenApiSourceIds([
      { url: 'https://docs.example.test/one.json' },
      { id: 'source-existing', url: 'https://docs.example.test/two.json' },
    ], () => `source-${++sequence}`)

    expect(sources).toEqual([
      { id: 'source-1', url: 'https://docs.example.test/one.json' },
      { id: 'source-existing', url: 'https://docs.example.test/two.json' },
    ])
  })

  test.each([
    [{ openapiSources: 'https://docs.example.test/openapi.json' }, 'openapiSources must be an array'],
    [{ openapiSources: [{}] }, 'openapiSources[0].url must be an absolute HTTP(S) URL'],
    [{ openapiSources: [{ url: 'file:///tmp/openapi.yaml', headers: [] }] }, 'openapiSources[0].url must be an absolute HTTP(S) URL'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: 'Authorization: secret' }] }, 'openapiSources[0].headers must be an array of header lines'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: ['missing delimiter'] }] }, 'openapiSources[0].headers[0] must be a valid HTTP header line'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: [], serverOverride: '/v2' }] }, 'openapiSources[0].serverOverride must be an absolute HTTP(S) URL'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', serverOverride: 'https://api.example.test/v2?token=secret' }] }, 'openapiSources[0].serverOverride must be an absolute HTTP(S) URL without a query'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: ['Host: attacker.test'] }] }, 'openapiSources[0].headers[0] uses a forbidden HTTP header'],
    [{ openapiDiscoveryHeaders: [{ origin: 'https://docs.example.test', headers: ['Content-Length: 20'] }] }, 'openapiDiscoveryHeaders[0].headers[0] uses a forbidden HTTP header'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: [], enabled: 'yes' }] }, 'openapiSources[0].enabled must be a boolean'],
    [{ openapiSources: [{ id: '', url: 'https://docs.example.test/openapi.json' }] }, 'openapiSources[0].id must be a non-empty string of at most 128 characters'],
    [{ openapiSources: [{ id: 'a'.repeat(129), url: 'https://docs.example.test/openapi.json' }] }, 'openapiSources[0].id must be a non-empty string of at most 128 characters'],
    [{ openapiSources: [
      { id: 'source-1', url: 'https://docs.example.test/one.json' },
      { id: 'source-1', url: 'https://docs.example.test/two.json' },
    ] }, 'openapiSources[1].id must be unique'],
    [{ openapiDiscoveryHeaders: [{ origin: 'https://docs.example.test/path', headers: [] }] }, 'openapiDiscoveryHeaders[0].origin must contain only an HTTP(S) origin'],
    [{ openapiTimeout: 0 }, 'openapiTimeout must be an integer between 1 and 60'],
    [{ openapiMaxDocuments: 0 }, 'openapiMaxDocuments must be an integer between 1 and 200'],
  ])('rejects malformed OpenAPI settings without echoing credential values', (settings, expected) => {
    const error = validateOpenApiSettings(settings)
    expect(error).toBe(expected)
    expect(error).not.toContain('secret')
  })
})

test('validates project discovery paths and permits an empty list', () => {
  expect(validateOpenApiSettings({ openapiDiscoveryPaths: ['/api-docs/', '/custom/openapi.json'] })).toBeNull()
  expect(validateOpenApiSettings({ openapiDiscoveryPaths: [] })).toBeNull()
  for (const paths of [['//external.test/spec'], ['https://external.test/spec'], ['/bad?x=1'], ['/bad#x'], ['/bad\\path'], [''], Array(201).fill('/docs'), 'invalid']) {
    expect(validateOpenApiSettings({ openapiDiscoveryPaths: paths })).toContain('openapiDiscoveryPaths')
  }
})