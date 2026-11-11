import { describe, test, expect } from 'vitest'
import {
  admitsPartialHost, discoveryDomains, graphDomainOf, graphHostInScope, graphScopeParams, ipModeRefusal,
  ipTargetMatcher, partialScopeFields, resolveProjectRoots,
} from './partialReconScope'

const PID = 'p1'

describe('resolveProjectRoots', () => {
  test('a batch offers its scope-group scan roots, derived from the host list', () => {
    const scope = resolveProjectRoots({
      domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk', '*.example.com', 'v1.example.com'],
      // A stale legacy record grouped under the bare suffix must not be offered.
      domainBatchGroups: [{ rootDomain: 'co.uk', prefixes: ['www.acme.'] }],
    }, PID)
    expect(scope.roots).toEqual(['acme.co.uk', 'example.com'])
    expect(scope.wildcardRoots).toEqual(['example.com'])
  })

  test('a single domain keeps the stored spelling of its target', () => {
    expect(resolveProjectRoots({ targetDomain: 'Alpha.test', subdomainList: [] }, PID).roots).toEqual(['Alpha.test'])
  })

  test('a single-domain target the scope refuses offers no root', () => {
    expect(resolveProjectRoots({ targetDomain: 'co.uk', subdomainList: [] }, PID).roots).toEqual([])
  })

  test('without the host list it falls back to the legacy record', () => {
    const scope = resolveProjectRoots({
      domainBatchMode: true, domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['*'] }],
    }, PID)
    expect(scope.roots).toEqual(['example.com'])
    expect(scope.groups).toEqual([])
  })

  test('IP mode offers the synthetic root', () => {
    expect(resolveProjectRoots({ ipMode: true }, PID).roots).toEqual(['ip-targets.p1'])
  })
})

describe('discoveryDomains', () => {
  test('only an ENUMERATE group is offered to SubdomainDiscovery', () => {
    const scope = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['*.a.com', 'www.b.com'] }, PID)
    expect(discoveryDomains(scope, ['a.com', 'b.com'])).toEqual(['a.com'])
  })

  test('an EXACT single-domain project no longer enumerates', () => {
    const exact = resolveProjectRoots({ targetDomain: 'example.com', subdomainList: ['www.'] }, PID)
    expect(discoveryDomains(exact, ['example.com'])).toEqual([])
    const enumerate = resolveProjectRoots({ targetDomain: 'example.com', subdomainList: ['.'] }, PID)
    expect(discoveryDomains(enumerate, ['example.com'])).toEqual(['example.com'])
  })
})

describe('admitsPartialHost (§4.6 partial user-typed rule)', () => {
  const scope = resolveProjectRoots({
    domainBatchMode: true, domainBatchHosts: ['www.example.com', 'example.com'],
  }, PID)

  test('ENUMERATE admits strict subdomains, the root only with Root on', () => {
    const enumOnly = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['*.example.org'] }, PID)
    expect(admitsPartialHost(enumOnly, 'x.example.org')).toBe(true)
    expect(admitsPartialHost(enumOnly, 'example.org')).toBe(false)
  })

  test('EXACT admits its listed hosts and its root with Root on, nothing else', () => {
    expect(admitsPartialHost(scope, 'WWW.example.com')).toBe(true)
    expect(admitsPartialHost(scope, 'example.com')).toBe(true)
    expect(admitsPartialHost(scope, 'mail.example.com')).toBe(false)
  })
})

describe('partialScopeFields', () => {
  test('a graph Domain that is no scan root is stale', () => {
    const scope = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk'] }, PID)
    const fields = partialScopeFields(scope, [
      { name: 'co.uk', hasData: true }, { name: 'acme.co.uk', hasData: false },
    ])
    expect(fields.domains).toEqual(['acme.co.uk'])
    expect(fields.stale_domains).toEqual(['co.uk'])
    expect(fields.empty_domains).toEqual(['acme.co.uk'])
  })
})

describe('the graph scope test (§4.6 partial-recon graph targets)', () => {
  const single = resolveProjectRoots({ targetDomain: 'api.example.com', subdomainList: [] }, PID)

  test('a deep single-domain root hangs off its org Domain', () => {
    expect(graphDomainOf(single, 'api.example.com')).toBe('example.com')
    const fields = partialScopeFields(single, [{ name: 'example.com', hasData: true }])
    expect(fields.domains).toEqual(['api.example.com'])
    expect(fields.stale_domains).toEqual([])
    expect(fields.empty_domains).toEqual([])
  })

  test('an enumerated root admits its strict subdomains, the root only with Root on', () => {
    const params = graphScopeParams(single, ['api.example.com'])
    expect(graphHostInScope(params, 'v1.api.example.com')).toBe(true)
    expect(graphHostInScope(params, 'api.example.com')).toBe(false)
    expect(graphHostInScope(params, 'www.example.com')).toBe(false)
  })

  test('the longest scan root decides, and only selected roots count', () => {
    const scope = resolveProjectRoots({
      domainBatchMode: true, domainBatchHosts: ['*.example.com', 'shop.example.org', 'example.org'],
    }, PID)
    const params = graphScopeParams(scope, ['example.org'])
    expect(graphHostInScope(params, 'shop.example.org')).toBe(true)
    expect(graphHostInScope(params, 'example.org')).toBe(true)
    expect(graphHostInScope(params, 'mail.example.org')).toBe(false)  // EXACT: listed only
    expect(graphHostInScope(params, 'www.example.com')).toBe(false)   // not a selected root
  })

  test("a removed scan root's hosts are not in scope (§4.11.7)", () => {
    // Before: *.example.com and the org; after the edit only www.example.com
    // is listed, so the old enumerated hosts still hang off Domain(example.com).
    const scope = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['www.example.com'] }, PID)
    const params = graphScopeParams(scope, ['example.com'])
    expect(graphHostInScope(params, 'www.example.com')).toBe(true)
    expect(graphHostInScope(params, 'old.example.com')).toBe(false)
    expect(discoveryDomains(scope, ['example.com'])).toEqual([])
  })
})

describe('IP mode (B-19..B-22)', () => {
  const ipScope = resolveProjectRoots({ ipMode: true }, PID)

  test('SubdomainDiscovery is offered no root: the synthetic root is the project id', () => {
    expect(discoveryDomains(ipScope, ['ip-targets.p1'])).toEqual([])
  })

  test('the name-only tools are refused in IP mode only', () => {
    for (const tool of ['SubdomainDiscovery', 'Urlscan', 'OriginDiscovery']) {
      expect(ipModeRefusal(tool, true)).toMatch(/./)
      expect(ipModeRefusal(tool, false)).toBeNull()
    }
    expect(ipModeRefusal('Httpx', true)).toBeNull()
    expect(ipModeRefusal(null, true)).toBeNull()
  })

  const targets = ipTargetMatcher(['203.0.113.0/30', '203.0.113.9', '2001:db8::1', '2001:db8:1::/127',
    '198.51.100.5/31', '192.0.2.0/24/7', 'not-an-ip', '203.0.113.300'])

  test.each([
    ['203.0.113.1', true], ['203.0.113.2', true], ['203.0.113.9', true],
    // network and broadcast addresses of a /30 are no hosts, as in Python's hosts()
    ['203.0.113.0', false], ['203.0.113.3', false],
    ['198.51.100.4', true], ['198.51.100.5', true],
    ['2001:DB8:0:0:0:0:0:1', true], ['[2001:db8::1]', true], ['2001:db8:1::', true], ['2001:db8:1::1', true],
    ['2001:db8::2', false], ['::ffff:203.0.113.1', false], ['198.51.100.7', false],
    ['203.0.113.01', false], ['www.example.com', false], ['', false], ['1:2:3:4:5:6:7:8:9', false],
  ])('%s is a target: %s', (address, expected) => {
    expect(targets.has(address)).toBe(expected)
  })

  test('a label stands for its own target address only', () => {
    expect(targets.isLabel('203-0-113-2')).toBe(true)
    expect(targets.isLabel('2001-db8--1')).toBe(true)
    expect(targets.isLabel('203-0-113-3')).toBe(false)
    expect(targets.isLabel('198-51-100-7')).toBe(false)
    expect(targets.isLabel('www.example.com')).toBe(false)
    expect(targets.isLabel('203-0-113-2.ip-targets.p1')).toBe(false)
    expect(targets.isLabel('mail01')).toBe(false)
  })

  test('a typed address or CIDR must lie wholly inside the targets', () => {
    expect(targets.outside('203.0.113.9')).toBeNull()
    expect(targets.outside('203.0.113.9/32')).toBeNull()
    expect(targets.outside('198.51.100.4/31')).toBeNull()
    expect(targets.outside('2001:db8:1::/127')).toBeNull()
    expect(targets.outside('203.0.113.0/30')).toBeNull()
    expect(targets.outside('198.51.100.7')).toMatch(/not one of this project's target IPs/)
    expect(targets.outside('203.0.113.0/29')).toMatch(/4 of the 6 addresses in 203\.0\.113\.0\/29/)
    expect(targets.outside('2001:db8::/126')).toMatch(/2 of the 3 addresses/)
    expect(targets.outside('nonsense')).toMatch(/not an address or CIDR/)
    expect(targets.outside('203.0.113.0/40')).toMatch(/not an address or CIDR/)
  })
})
