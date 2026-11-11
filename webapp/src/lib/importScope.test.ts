import { describe, test, expect } from 'vitest'
import { Prisma } from '@prisma/client'
import { normalizeImportedScope } from './importScope'

describe('normalizeImportedScope', () => {
  test('a single-domain government target is refused, in every mode the guardrail covers', () => {
    const res = normalizeImportedScope({ targetDomain: 'agency.gov.uk', subdomainList: [] })
    expect(res.status).toBe(403)
    expect(res.error).toContain('agency.gov.uk')
  })

  test('a batch host under a government name is refused, naming it', () => {
    const res = normalizeImportedScope({
      domainBatchMode: true, domainBatchHosts: ['www.example.com', 'www.isa.org.jm'],
    })
    expect(res.status).toBe(403)
    expect(res.error).toContain('www.isa.org.jm')
  })

  test('IP mode and batch mode at once is refused', () => {
    const res = normalizeImportedScope({ ipMode: true, domainBatchMode: true, domainBatchHosts: ['a.example.com'] })
    expect(res.status).toBe(400)
  })

  test("the bundle's groups are never copied: they are re-derived from the hosts", () => {
    const fields: Record<string, unknown> = {
      domainBatchMode: true,
      domainBatchHosts: ['www.example.com'],
      domainBatchGroups: [{ rootDomain: 'attacker-chosen.com', prefixes: ['*'], hosts: ['*.attacker-chosen.com'], wildcard: true }],
    }
    expect(normalizeImportedScope(fields).error).toBeUndefined()
    expect(fields.domainBatchGroups).toEqual([
      { rootDomain: 'example.com', prefixes: ['www.'], hosts: ['www.example.com'], wildcard: false },
    ])
  })

  test('a host the current rules refuse is dropped with a warning', () => {
    const fields: Record<string, unknown> = {
      domainBatchMode: true, domainBatchHosts: ['www.example.com', 'not a host'],
    }
    const res = normalizeImportedScope(fields)
    expect(res.error).toBeUndefined()
    expect(res.warnings.join(' ')).toContain('not a host')
    expect(fields.domainBatchHosts).toEqual(['www.example.com'])
  })

  test('nothing surviving is a refusal', () => {
    const res = normalizeImportedScope({ domainBatchMode: true, domainBatchHosts: ['not a host'] })
    expect(res.status).toBe(400)
  })

  test('a non-batch bundle keeps no batch scope', () => {
    const fields: Record<string, unknown> = {
      targetDomain: '*.example.com',
      domainBatchHosts: ['*.attacker-chosen.com'],
      domainBatchGroups: [{ rootDomain: 'attacker-chosen.com', prefixes: ['*'] }],
    }
    expect(normalizeImportedScope(fields).error).toBeUndefined()
    expect(fields.domainBatchGroups).toBe(Prisma.DbNull)
    expect(fields.domainBatchHosts).toEqual([])
    expect(fields.targetDomain).toBe('example.com')
  })

  test('IP mode is not hard-blocked', () => {
    const fields: Record<string, unknown> = { ipMode: true, targetIps: ['192.0.2.10'] }
    expect(normalizeImportedScope(fields).error).toBeUndefined()
  })
})

describe('normalizeImportedScope: a single-domain bundle', () => {
  test('a target that is a public suffix refuses the import', () => {
    const res = normalizeImportedScope({ targetDomain: 'co.uk', subdomainList: [] })
    expect(res.status).toBe(400)
    expect(res.error).toContain('public suffix')
  })

  test('the target is stored normalised and lower-cased', () => {
    const fields: Record<string, unknown> = { targetDomain: 'HTTPS://Api.Example.COM/', subdomainList: [] }
    expect(normalizeImportedScope(fields).error).toBeUndefined()
    expect(fields.targetDomain).toBe('api.example.com')
  })

  test('a refused prefix is dropped with a warning; the rest imports', () => {
    const fields: Record<string, unknown> = { targetDomain: 'example.com', subdomainList: ['www.', '*', 'eu.api.'] }
    const res = normalizeImportedScope(fields)
    expect(res.error).toBeUndefined()
    expect(fields.subdomainList).toEqual(['www.', 'eu.api.'])
    expect(res.warnings.join(' ')).toContain('*')
  })
})

describe('normalizeImportedScope: the hostname policy (Hostnames on target IPs)', () => {
  const IP = { ipMode: true, targetIps: ['203.0.113.10'] }

  test('an IP bundle whose include entry is hard-blocked is refused, naming it', () => {
    const res = normalizeImportedScope({
      ...IP, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', '*.agency.gov.uk'],
    })
    expect(res.status).toBe(403)
    expect(res.error).toContain('agency.gov.uk')
  })

  test('an IP bundle with a clean policy keeps it', () => {
    const fields: Record<string, unknown> = { ...IP, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }
    expect(normalizeImportedScope(fields)).toEqual({ warnings: [] })
    expect(fields.ipHostnameMode).toBe('record_filter')
  })

  test('a domain bundle carrying a policy imports without it, with a warning', () => {
    const fields: Record<string, unknown> = {
      targetDomain: 'example.com', subdomainList: [],
      ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true, ipHostnameInclude: ['*.example.com'],
    }
    const res = normalizeImportedScope(fields)
    expect(res.error).toBeUndefined()
    expect(fields).toMatchObject({
      ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnameScanAllConfirmed: false,
    })
    expect(res.warnings.join(' ')).toContain('only to IP-mode projects')
  })

  test('a domain bundle at the defaults, or without the columns, gets no warning', () => {
    expect(normalizeImportedScope({ targetDomain: 'example.com', ipHostnameMode: 'ip_only' }).warnings).toEqual([])
    expect(normalizeImportedScope({ targetDomain: 'example.com' }).warnings).toEqual([])
  })
})
