import { describe, test, expect } from 'vitest'
import { resolveScopeGroups } from '@/lib/scopeGroups'
import type { GraphNode } from '../types'
import { domainScopeRoots, scanRootBadge } from './scopeRootsForNode'
import { buildNodeContext } from './buildNodeContext'

const groups = resolveScopeGroups({
  domainBatchMode: true,
  domainBatchHosts: ['*.api.example.com', 'api.example.com', 'www.example.com', '*.other.test'],
}).groups

const node = (type: string, name: string, properties: Record<string, unknown> = {}): GraphNode =>
  ({ id: name, type, name, properties })

describe('the scan roots under a Domain (§4.11.7)', () => {
  test('current groups of that org, removed roots apart', () => {
    const d = node('Domain', 'example.com', { recon_coverage_roots: ['api.example.com', 'shop.example.com'] })
    expect(domainScopeRoots(d, groups)).toEqual({
      current: ['*.api.example.com (enumerated, +root)', 'example.com: www (listed)'],
      removed: ['shop.example.com'],
    })
  })

  test('a saved version lists the stored roots without a split', () => {
    const d = node('Domain', 'example.com', { recon_coverage_roots: ['api.example.com'] })
    expect(domainScopeRoots(d, undefined)).toEqual({ current: ['api.example.com'], removed: [] })
  })

  test('an IP-mode project\'s org Domain lists no scan roots (design §6.1, unchanged)', () => {
    // It carries ip_hostname_org, no ip_mode and no recon_coverage_roots (the IP
    // path writes its coverage record on the mock root), and an IP-mode project
    // has no scope groups: the drawer counts its scanned hostnames instead.
    const org = node('Domain', 'example.com', { ip_hostname_org: true })
    expect(domainScopeRoots(org, [])).toBeNull()
    expect(domainScopeRoots(org, undefined)).toBeNull()
  })

  test('an old graph with nothing to say shows nothing', () => {
    expect(domainScopeRoots(node('Domain', 'unrelated.test'), groups)).toBeNull()
    expect(domainScopeRoots(node('Domain', 'ip-targets.p1', { ip_mode: true }), groups)).toBeNull()
  })
})

describe('the scan-root badge of a Subdomain', () => {
  test('mode and Root of a current scan root', () => {
    expect(scanRootBadge(node('Subdomain', 'api.example.com', { is_scan_root: true }), groups))
      .toBe('Scan root (enumerate, +root)')
  })

  test('a removed scan root says so', () => {
    expect(scanRootBadge(node('Subdomain', 'shop.example.com', { is_scan_root: true }), groups))
      .toBe('former scan root (removed)')
  })

  test('no badge for an ordinary host', () => {
    expect(scanRootBadge(node('Subdomain', 'www.example.com'), groups)).toBeNull()
  })
})

describe('the LLM context states the scope from the groups', () => {
  test('one line per group instead of a bare target', () => {
    const text = buildNodeContext(node('Subdomain', 'www.example.com'), null,
      { projectName: 'p', targetDomain: '', scopeGroups: groups })
    expect(text).toContain('- *.api.example.com (enumerated, +root)')
    expect(text).toContain('- example.com: www (listed)')
    expect(text).not.toContain('Target:')
  })
})
