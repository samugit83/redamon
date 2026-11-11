/**
 * The per-source OpenAPI status as the form reads it. The hash must equal the
 * one recon writes (sha256 of the public URL, first 12 hex digits; the
 * expected values below were computed with Python's hashlib), or every row
 * would read "Not fetched yet".
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  NOT_FETCHED,
  documentInProjectScope,
  documentUrlHash,
  openApiStatusLabel,
  parseOpenApiSourceStatus,
  publicDocumentUrl,
  rowStatusLabel,
} from './openapiSourceStatus'

describe('the status recon writes', () => {
  test('is parsed by source id, ignoring malformed entries', () => {
    const parsed = parseOpenApiSourceStatus(['s1|1b2b05bdb639|ok|2026-10-19T00:00:00Z', 'broken', 7, 's2||x|y'])
    expect([...parsed.keys()]).toEqual(['s1'])
    expect(parsed.get('s1')).toEqual({ hash: '1b2b05bdb639', code: 'ok', at: '2026-10-19T00:00:00Z' })
    expect(parseOpenApiSourceStatus(null).size).toBe(0)
  })

  test('the five-segment form leads with the scan root; the newest status per source wins', () => {
    const parsed = parseOpenApiSourceStatus([
      'api.example.com|s1|aaaaaaaaaaaa|ok|2026-10-20T00:00:00Z',
      'example.com|s1|aaaaaaaaaaaa|http_404|2026-10-21T00:00:00Z',
      's2|bbbbbbbbbbbb|ok|2026-10-19T00:00:00Z',
    ])
    expect(parsed.get('s1')).toEqual({ hash: 'aaaaaaaaaaaa', code: 'http_404', at: '2026-10-21T00:00:00Z' })
    expect(parsed.get('s2')?.code).toBe('ok')
  })

  test.each([
    ['ok', 'Imported'], ['out_of_scope', 'Outside scope'], ['blocked_address', 'Internal address blocked'],
    ['http_401', 'HTTP 401'], ['invalid_document', 'Invalid document'], ['host_down', 'Host down'],
    ['transport_error', 'Unreachable'], ['limit_reached', 'Limit reached'], ['something_new', 'Unknown'],
  ])('%s reads %s', (code, label) => {
    expect(openApiStatusLabel(code)).toBe(label)
  })
})

describe('the URL hash matches recon', () => {
  test.each([
    ['https://API.example.com/openapi.json?token=fixture-secret#x', '1b2b05bdb639'],
    ['http://10.203.0.10:80/openapi.json', '21913abd810e'],
    ['https://api.example.com:8443/v1/spec.yaml', '30f9e45c91d2'],
  ])('%s', async (url, hash) => {
    expect(await documentUrlHash(url)).toBe(hash)
  })

  test('the query never reaches the hashed location', () => {
    expect(publicDocumentUrl('https://api.example.com/spec?token=x')).toBe('https://api.example.com/spec')
    expect(publicDocumentUrl('ftp://api.example.com/spec')).toBeNull()
  })
})

describe('a row shows its status only while its URL is the one fetched', () => {
  const statuses = parseOpenApiSourceStatus(['s1|1b2b05bdb639|blocked_address|t'])

  test('same URL: the status', () => {
    expect(rowStatusLabel({ id: 's1', url: 'x' }, statuses, '1b2b05bdb639')).toBe('Internal address blocked')
  })

  test('edited URL or never fetched: not fetched yet', () => {
    expect(rowStatusLabel({ id: 's1', url: 'x' }, statuses, 'ffffffffffff')).toBe(NOT_FETCHED)
    expect(rowStatusLabel({ id: 's2', url: 'x' }, statuses, '1b2b05bdb639')).toBe(NOT_FETCHED)
  })

  test('status unread or no hashing in this browser: unknown', () => {
    expect(rowStatusLabel({ id: 's1', url: 'x' }, null, '1b2b05bdb639')).toBeNull()
    expect(rowStatusLabel({ id: 's1', url: 'x' }, statuses, null)).toBeNull()
  })
})

// The hint must agree with recon's OpenAPI scope (recon/helpers/openapi/scope.py):
// a hint looser than recon promised documents that recon then refused. The
// prefix cases below are the ones recon/tests/test_openapi_scope.py pins.
describe('the advisory scope hint', () => {
  test('domain mode: every subdomain; the apex only through "."', () => {
    const project = { targetDomain: 'example.com' }
    expect(documentInProjectScope('https://docs.example.com/openapi.json', project)).toBe(true)
    expect(documentInProjectScope('https://example.com/openapi.json', project)).toBe(false)
    expect(documentInProjectScope('https://example.org/openapi.json', project)).toBe(false)
    expect(documentInProjectScope('https://example.com/openapi.json', { ...project, subdomainList: ['.'] })).toBe(true)
  })

  test('domain mode with a subdomain list: only the listed hosts', () => {
    const project = { targetDomain: 'example.com', subdomainList: ['api.', ''] }
    expect(documentInProjectScope('https://API.example.com./spec', project)).toBe(true)
    expect(documentInProjectScope('https://docs.example.com/spec', project)).toBe(false)
    expect(documentInProjectScope('https://child.api.example.com/spec', project)).toBe(false)
    expect(documentInProjectScope('https://example.com/spec', project)).toBe(false)
  })

  test.each([
    [['*'], false, true],
    [['*', '.'], true, true],
    [['*', 'api.'], false, true],
    [['.'], true, false],
    [['api.'], false, false],
  ])('batch group with prefixes %j: apex %s, other subdomain %s', (prefixes, apex, other) => {
    const project = { domainBatchMode: true, domainBatchGroups: [{ rootDomain: 'example.test', prefixes }] }
    expect(documentInProjectScope('https://example.test/spec', project)).toBe(apex)
    expect(documentInProjectScope('https://other.example.test/spec', project)).toBe(other)
    expect(documentInProjectScope('https://api.example.test/spec', project)).toBe(other || prefixes.includes('api.'))
    expect(documentInProjectScope('https://outside.test/spec', project)).toBe(false)
  })

  test('batch: any group admits it, grouped from the hostnames being edited', () => {
    const project = {
      domainBatchMode: true,
      domainBatchHosts: ['www.one.test', 'api.one.test', '*.two.test'],
      // Stale: saved before the list above was edited. The list wins.
      domainBatchGroups: [{ rootDomain: 'one.test', prefixes: ['*'] }],
    }
    expect(documentInProjectScope('https://api.one.test/spec', project)).toBe(true)
    expect(documentInProjectScope('https://docs.one.test/spec', project)).toBe(false)
    expect(documentInProjectScope('https://one.test/spec', project)).toBe(false)
    expect(documentInProjectScope('https://docs.two.test/spec', project)).toBe(true)
    expect(documentInProjectScope('https://three.test/spec', project)).toBe(false)
  })

  test('a target below its org: everything under the target, nothing beside it', () => {
    const project = { targetDomain: 'api.example.com', subdomainList: [] as string[] }
    expect(documentInProjectScope('https://v1.api.example.com/spec', project)).toBe(true)
    expect(documentInProjectScope('https://www.example.com/spec', project)).toBe(false)
    expect(documentInProjectScope('https://api.example.com/spec', project)).toBe(false)
  })

  test('batch: hosts group by registrable domain, so a host under a multi-label suffix keeps its own scope', () => {
    const project = { domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk', '*.other.co.uk'] }
    expect(documentInProjectScope('https://www.acme.co.uk/spec', project)).toBe(true)
    expect(documentInProjectScope('https://api.acme.co.uk/spec', project)).toBe(false)
    expect(documentInProjectScope('https://api.other.co.uk/spec', project)).toBe(true)
  })

  test('a Rules of Engagement exclusion is outside, matched as recon matches it', () => {
    const project = {
      targetDomain: 'example.com',
      roeExcludedHosts: ['Billing.Example.com.', '*.corp.example.com'],
    }
    expect(documentInProjectScope('https://billing.example.com/spec', project)).toBe(false)
    expect(documentInProjectScope('https://eu.billing.example.com/spec', project)).toBe(false)
    expect(documentInProjectScope('https://corp.example.com/spec', project)).toBe(true)
    expect(documentInProjectScope('https://api.corp.example.com/spec', project)).toBe(false)
    expect(documentInProjectScope('https://notbilling.example.com/spec', project)).toBe(true)
    const ips = { ipMode: true, targetIps: ['10.203.0.0/24'], roeExcludedHosts: ['10.203.0.128/25'] }
    expect(documentInProjectScope('http://10.203.0.10/spec', ips)).toBe(true)
    expect(documentInProjectScope('http://10.203.0.200/spec', ips)).toBe(false)
  })

  test('IP mode: inside a target IP or CIDR; a name is outside', () => {
    const project = { ipMode: true, targetIps: ['10.203.0.0/24', '198.51.100.7'] }
    expect(documentInProjectScope('http://10.203.0.10/openapi.json', project)).toBe(true)
    expect(documentInProjectScope('http://198.51.100.7:8080/spec', project)).toBe(true)
    expect(documentInProjectScope('http://10.204.0.1/spec', project)).toBe(false)
    expect(documentInProjectScope('http://docs.example.com/spec', project)).toBe(false)
  })

  test('IP mode with a hostname policy: a name the policy can scan is decided at run time (P4)', () => {
    const m4 = { ipMode: true, targetIps: ['10.203.0.0/24'], ipHostnameMode: 'record_filter',
      ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'] }
    // recon fetches it only if the run selects it (every address a target).
    expect(documentInProjectScope('https://docs.example.com/spec', m4)).toBeNull()
    expect(documentInProjectScope('https://old.example.com/spec', m4)).toBe(false)
    expect(documentInProjectScope('https://docs.example.org/spec', m4)).toBe(false)
    expect(documentInProjectScope('https://docs.example.com/spec', { ...m4, ipHostnameExclude: ['**.x'] })).toBe(false)
    expect(documentInProjectScope('https://docs.example.com/spec', { ...m4, roeExcludedHosts: ['example.com'] }))
      .toBe(false)
    const m1 = { ipMode: true, targetIps: ['10.203.0.0/24'], ipHostnameMode: 'scan_all' }
    expect(documentInProjectScope('https://anything.example.org/spec', m1)).toBeNull()
    for (const mode of ['record_only', 'ip_only', undefined]) {
      expect(documentInProjectScope('https://docs.example.com/spec', { ...m4, ipHostnameMode: mode })).toBe(false)
    }
    // Addresses keep their own verdict.
    expect(documentInProjectScope('http://10.203.0.10/spec', m4)).toBe(true)
  })

  test('cannot tell: no verdict', () => {
    expect(documentInProjectScope('not a url', { targetDomain: 'example.com' })).toBeNull()
    expect(documentInProjectScope('https://x.example.com/', {})).toBeNull()
    expect(documentInProjectScope('https://[2001:db8::1]/spec', { ipMode: true, targetIps: ['2001:db8::/32'] })).toBeNull()
  })
})
