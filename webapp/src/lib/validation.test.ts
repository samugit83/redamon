import { describe, test, expect } from 'vitest'
import {
  REGEX_IPV4, REGEX_IPV6, REGEX_CIDR_V4, REGEX_CIDR_V6,
  REGEX_DOMAIN, REGEX_SUBDOMAIN_PREFIX, REGEX_PORT, REGEX_STATUS_CODE,
  REGEX_HTTP_HEADER, REGEX_GITHUB_TOKEN, REGEX_GITHUB_REPO, REGEX_GITHUB_ORG,
  REGEX_GIT_BRANCH, REGEX_URL_PATH,
  isValidIpv4, isValidIpOrCidr, isValidDomain, isValidSubdomainPrefix,
  isValidPortList, isValidStatusCodeList, isValidHeaderList, isValidTopPorts,
  validateProjectForm,
} from './validation'

// === IPv4 ===
describe('REGEX_IPV4', () => {
  test.each([
    '0.0.0.0', '1.2.3.4', '192.168.1.1', '255.255.255.255', '10.0.0.1',
  ])('accepts valid: %s', (ip) => expect(REGEX_IPV4.test(ip)).toBe(true))

  test.each([
    '256.1.1.1', '1.2.3.256', '1.2.3', '1.2.3.4.5', 'abc.def.ghi.jkl',
    '', '192.168.1.1/24', ' 1.2.3.4',
  ])('rejects invalid: %s', (ip) => expect(REGEX_IPV4.test(ip)).toBe(false))
})

// === IPv6 ===
describe('REGEX_IPV6', () => {
  test.each([
    '2001:db8::1', 'fe80::1', '::1', '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
  ])('accepts valid: %s', (ip) => expect(REGEX_IPV6.test(ip)).toBe(true))

  test.each([
    '192.168.1.1', 'not-an-ip', '',
  ])('rejects invalid: %s', (ip) => expect(REGEX_IPV6.test(ip)).toBe(false))
})

// === CIDR v4 ===
describe('REGEX_CIDR_V4', () => {
  test.each([
    '10.0.0.0/24', '192.168.1.0/28', '172.16.0.0/25', '10.0.0.1/32',
  ])('accepts valid: %s', (cidr) => expect(REGEX_CIDR_V4.test(cidr)).toBe(true))

  test.each([
    '10.0.0.0/23', '10.0.0.0/8', '10.0.0.0/33', '10.0.0.0',
    '256.0.0.0/24', 'abc/24',
  ])('rejects invalid: %s', (cidr) => expect(REGEX_CIDR_V4.test(cidr)).toBe(false))
})

// === CIDR v6 ===
describe('REGEX_CIDR_V6', () => {
  test.each([
    '2001:db8::/104', '2001:db8::/120', '2001:db8::1/128',
  ])('accepts valid: %s', (cidr) => expect(REGEX_CIDR_V6.test(cidr)).toBe(true))

  test.each([
    '2001:db8::/64', '2001:db8::/103', '2001:db8::/129',
  ])('rejects invalid: %s', (cidr) => expect(REGEX_CIDR_V6.test(cidr)).toBe(false))
})

// === isValidIpOrCidr ===
describe('isValidIpOrCidr', () => {
  test('accepts IPv4', () => expect(isValidIpOrCidr('192.168.1.1')).toBe(true))
  test('accepts IPv6', () => expect(isValidIpOrCidr('2001:db8::1')).toBe(true))
  test('accepts CIDR v4', () => expect(isValidIpOrCidr('10.0.0.0/24')).toBe(true))
  test('accepts CIDR v6', () => expect(isValidIpOrCidr('2001:db8::/120')).toBe(true))
  test('trims whitespace', () => expect(isValidIpOrCidr(' 10.0.0.1 ')).toBe(true))
  test('rejects garbage', () => expect(isValidIpOrCidr('not-an-ip')).toBe(false))
  test('rejects empty', () => expect(isValidIpOrCidr('')).toBe(false))
})

// === Domain ===
describe('REGEX_DOMAIN', () => {
  test.each([
    'example.com', 'sub.example.com', 'a-b.example.co.uk', 'test123.org',
  ])('accepts valid: %s', (d) => expect(REGEX_DOMAIN.test(d)).toBe(true))

  test.each([
    'localhost', '-example.com', 'example-.com', '.example.com',
    'example.c', '', 'example..com',
  ])('rejects invalid: %s', (d) => expect(REGEX_DOMAIN.test(d)).toBe(false))
})

// === Subdomain prefix ===
describe('REGEX_SUBDOMAIN_PREFIX', () => {
  test.each(['www', 'api', 'a', 'test-host', 'a1b2'])
    ('accepts valid: %s', (p) => expect(REGEX_SUBDOMAIN_PREFIX.test(p)).toBe(true))

  test.each(['-start', 'end-', '', 'a'.repeat(64)])
    ('rejects invalid: %s', (p) => expect(REGEX_SUBDOMAIN_PREFIX.test(p)).toBe(false))
})

// === Ports ===
describe('REGEX_PORT', () => {
  test.each(['1', '80', '443', '8080', '65535'])
    ('accepts valid: %s', (p) => expect(REGEX_PORT.test(p)).toBe(true))

  test.each(['0', '65536', '99999', '', 'abc'])
    ('rejects invalid: %s', (p) => expect(REGEX_PORT.test(p)).toBe(false))
})

describe('isValidPortList', () => {
  test('accepts comma-separated ports', () => expect(isValidPortList('80,443,8080')).toBe(true))
  test('accepts port ranges', () => expect(isValidPortList('80,8080-8090')).toBe(true))
  test('accepts empty', () => expect(isValidPortList('')).toBe(true))
  test('rejects invalid port', () => expect(isValidPortList('80,99999')).toBe(false))
  test('rejects reversed range', () => expect(isValidPortList('8090-8080')).toBe(false))
})

// === Status codes ===
describe('isValidStatusCodeList', () => {
  test('accepts valid codes', () => expect(isValidStatusCodeList('200, 301, 404')).toBe(true))
  test('accepts empty', () => expect(isValidStatusCodeList('')).toBe(true))
  test('rejects 600', () => expect(isValidStatusCodeList('200,600')).toBe(false))
  test('rejects 99', () => expect(isValidStatusCodeList('99')).toBe(false))
})

// === HTTP headers ===
describe('isValidHeaderList', () => {
  test('accepts valid headers', () => expect(isValidHeaderList(['X-Custom: value', 'Authorization: Bearer token'])).toBe(true))
  test('accepts empty entries', () => expect(isValidHeaderList(['', '  '])).toBe(true))
  test('rejects malformed', () => expect(isValidHeaderList(['no-colon-here'])).toBe(false))
})

// === GitHub ===
describe('REGEX_GITHUB_TOKEN', () => {
  test('accepts ghp_ token', () => expect(REGEX_GITHUB_TOKEN.test('ghp_' + 'a'.repeat(36))).toBe(true))
  test('accepts github_pat_ token', () => expect(REGEX_GITHUB_TOKEN.test('github_pat_' + 'a'.repeat(82))).toBe(true))
  test('rejects short token', () => expect(REGEX_GITHUB_TOKEN.test('ghp_short')).toBe(false))
  test('rejects random string', () => expect(REGEX_GITHUB_TOKEN.test('notavalidtoken')).toBe(false))
})

describe('REGEX_GITHUB_REPO', () => {
  test('accepts owner/repo', () => expect(REGEX_GITHUB_REPO.test('owner/repo')).toBe(true))
  test('accepts dots and dashes', () => expect(REGEX_GITHUB_REPO.test('my-org/my.repo')).toBe(true))
  test('rejects no slash', () => expect(REGEX_GITHUB_REPO.test('justrepo')).toBe(false))
})

describe('REGEX_GITHUB_ORG', () => {
  test('accepts org', () => expect(REGEX_GITHUB_ORG.test('my-org')).toBe(true))
  test('rejects leading dash', () => expect(REGEX_GITHUB_ORG.test('-org')).toBe(false))
})

// === Other regexes ===
describe('REGEX_GIT_BRANCH', () => {
  test('accepts main', () => expect(REGEX_GIT_BRANCH.test('main')).toBe(true))
  test('accepts feature/branch', () => expect(REGEX_GIT_BRANCH.test('feature/branch-name')).toBe(true))
  test('rejects spaces', () => expect(REGEX_GIT_BRANCH.test('my branch')).toBe(false))
})

describe('REGEX_URL_PATH', () => {
  test('accepts /path', () => expect(REGEX_URL_PATH.test('/api/v1')).toBe(true))
  test('rejects no leading slash', () => expect(REGEX_URL_PATH.test('api/v1')).toBe(false))
})

describe('isValidTopPorts', () => {
  test('accepts 100', () => expect(isValidTopPorts('100')).toBe(true))
  test('accepts 1000', () => expect(isValidTopPorts('1000')).toBe(true))
  test('accepts full', () => expect(isValidTopPorts('full')).toBe(true))
  test('accepts custom number', () => expect(isValidTopPorts('500')).toBe(true))
  test('rejects 0', () => expect(isValidTopPorts('0')).toBe(false))
  test('rejects text', () => expect(isValidTopPorts('abc')).toBe(false))
})

// === validateProjectForm ===
describe('validateProjectForm', () => {
  const baseData = {
    name: 'Test',
    ipMode: false,
    targetDomain: 'example.com',
    targetIps: [],
    subdomainList: [],
  }

  test('accepts valid domain-mode form', () => {
    expect(validateProjectForm(baseData)).toEqual([])
  })

  test('rejects invalid domain', () => {
    const errors = validateProjectForm({ ...baseData, targetDomain: 'not valid!' })
    expect(errors.some(e => e.field === 'targetDomain')).toBe(true)
  })

  test('accepts valid IP-mode form', () => {
    const data = { ...baseData, ipMode: true, targetDomain: '', targetIps: ['192.168.1.1', '10.0.0.0/24'] }
    expect(validateProjectForm(data)).toEqual([])
  })

  test('rejects IP mode with no IPs', () => {
    const data = { ...baseData, ipMode: true, targetDomain: '', targetIps: [] }
    const errors = validateProjectForm(data)
    expect(errors.some(e => e.field === 'targetIps')).toBe(true)
  })

  test('rejects IP mode with invalid IP', () => {
    const data = { ...baseData, ipMode: true, targetIps: ['999.999.999.999'] }
    const errors = validateProjectForm(data)
    expect(errors.some(e => e.field === 'targetIps')).toBe(true)
  })

  test('validates naabu ports', () => {
    const errors = validateProjectForm({ ...baseData, naabuCustomPorts: '80,99999' })
    expect(errors.some(e => e.field === 'naabuCustomPorts')).toBe(true)
  })

  test('validates httpx headers', () => {
    const errors = validateProjectForm({ ...baseData, httpxCustomHeaders: ['bad header'] })
    expect(errors.some(e => e.field === 'httpxCustomHeaders')).toBe(true)
  })

  test('validates httpx status codes', () => {
    const errors = validateProjectForm({ ...baseData, httpxMatchCodes: ['999'] })
    expect(errors.some(e => e.field === 'httpxMatchCodes')).toBe(true)
  })

  test('validates agent lhost', () => {
    const errors = validateProjectForm({ ...baseData, agentLhost: 'not-an-ip' })
    expect(errors.some(e => e.field === 'agentLhost')).toBe(true)
  })

  test('skips empty optional fields', () => {
    const data = {
      ...baseData,
      agentLhost: '',
      naabuCustomPorts: '',
      cypherfixGithubToken: '',
    }
    expect(validateProjectForm(data)).toEqual([])
  })
})
