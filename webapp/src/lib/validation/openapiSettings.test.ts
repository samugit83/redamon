import { describe, expect, test } from 'vitest'
import { normalizeOpenApiSourceIds, validateOpenApiSettings, stripLegacyOpenApiHeaders } from './openapiSettings'

describe('validateOpenApiSettings', () => {
  test('accepts configured sources', () => {
    expect(validateOpenApiSettings({
      openapiEnabled: true,
      openapiAutoDiscover: true,
      openapiTimeout: 10,
      openapiMaxDocuments: 50,
      openapiSources: [{
        id: 'source-primary',
        url: 'https://docs.example.test/openapi.yaml',
        serverOverride: 'https://api.example.test/v2',
        enabled: true,
      }],
    })).toBeNull()
  })

  test('allows a source to omit optional settings', () => {
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
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: [], serverOverride: '/v2' }] }, 'openapiSources[0].serverOverride must be an absolute HTTP(S) URL'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', serverOverride: 'https://api.example.test/v2?token=secret' }] }, 'openapiSources[0].serverOverride must be an absolute HTTP(S) URL without a query'],
    [{ openapiSources: [{ url: 'https://docs.example.test/openapi.json', headers: [], enabled: 'yes' }] }, 'openapiSources[0].enabled must be a boolean'],
    [{ openapiSources: [{ id: '', url: 'https://docs.example.test/openapi.json' }] }, 'openapiSources[0].id must be a non-empty string of at most 128 characters'],
    [{ openapiSources: [{ id: 'a'.repeat(129), url: 'https://docs.example.test/openapi.json' }] }, 'openapiSources[0].id must be a non-empty string of at most 128 characters'],
    [{ openapiSources: [
      { id: 'source-1', url: 'https://docs.example.test/one.json' },
      { id: 'source-1', url: 'https://docs.example.test/two.json' },
    ] }, 'openapiSources[1].id must be unique'],
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
test('strips legacy plaintext credentials without mutating the stored project', () => {
  const legacy = {
    name: 'Copy',
    openapiSources: [{ id: 'source-1', url: 'https://example.test/spec', enabled: true,
      serverOverride: 'https://example.test/api', headers: ['Authorization: old-source-secret'],
      unknown: { headers: ['nested-secret'] } }],
    openapiDiscoveryHeaders: [{ origin: 'https://example.test', headers: ['Cookie: old-discovery-secret'] }],
  }
  const clean = stripLegacyOpenApiHeaders(legacy)
  expect(clean).toEqual({ name: 'Copy', openapiSources: [{ id: 'source-1',
    url: 'https://example.test/spec', enabled: true, serverOverride: 'https://example.test/api' }] })
  expect(JSON.stringify(clean)).not.toContain('secret')
  expect(legacy.openapiSources[0].headers).toHaveLength(1)
})
