import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { isPrivateOrLocalIp, classifyIpTargets, inSandboxAddressPool, sandboxPoolTargets, SANDBOX_ADDRESS_POOL } from './ip-target-utils'

describe('isPrivateOrLocalIp', () => {
  test('detects RFC1918 IPv4 ranges', () => {
    expect(isPrivateOrLocalIp('10.0.0.1')).toBe(true)
    expect(isPrivateOrLocalIp('10.255.255.255')).toBe(true)
    expect(isPrivateOrLocalIp('172.16.5.4')).toBe(true)
    expect(isPrivateOrLocalIp('172.31.0.1')).toBe(true)
    expect(isPrivateOrLocalIp('192.168.1.10')).toBe(true)
  })

  test('detects loopback, link-local and CGNAT', () => {
    expect(isPrivateOrLocalIp('127.0.0.1')).toBe(true)
    expect(isPrivateOrLocalIp('169.254.1.1')).toBe(true)
    expect(isPrivateOrLocalIp('100.64.0.1')).toBe(true)
  })

  test('treats public IPv4 as not private', () => {
    expect(isPrivateOrLocalIp('8.8.8.8')).toBe(false)
    expect(isPrivateOrLocalIp('1.1.1.1')).toBe(false)
    expect(isPrivateOrLocalIp('172.32.0.1')).toBe(false) // just outside 172.16/12
    expect(isPrivateOrLocalIp('192.169.1.1')).toBe(false) // not 192.168
    expect(isPrivateOrLocalIp('100.128.0.1')).toBe(false) // just outside CGNAT
  })

  test('classifies CIDR by its network address', () => {
    expect(isPrivateOrLocalIp('192.168.0.0/24')).toBe(true)
    expect(isPrivateOrLocalIp('10.0.0.0/8')).toBe(true)
    expect(isPrivateOrLocalIp('203.0.113.0/24')).toBe(false)
  })

  test('detects private IPv6 (ULA, link-local, loopback)', () => {
    expect(isPrivateOrLocalIp('::1')).toBe(true)
    expect(isPrivateOrLocalIp('fc00::1')).toBe(true)
    expect(isPrivateOrLocalIp('fd12:3456::1')).toBe(true)
    expect(isPrivateOrLocalIp('fe80::1')).toBe(true)
  })

  test('treats public IPv6 as not private', () => {
    expect(isPrivateOrLocalIp('2001:4860:4860::8888')).toBe(false)
  })

  test('handles whitespace and empty input safely', () => {
    expect(isPrivateOrLocalIp('  192.168.1.1  ')).toBe(true)
    expect(isPrivateOrLocalIp('')).toBe(false)
    expect(isPrivateOrLocalIp('not-an-ip')).toBe(false)
  })
})

describe('classifyIpTargets', () => {
  test('empty for no targets', () => {
    expect(classifyIpTargets([])).toBe('empty')
    expect(classifyIpTargets(null)).toBe('empty')
    expect(classifyIpTargets(undefined)).toBe('empty')
    expect(classifyIpTargets(['   ', ''])).toBe('empty')
  })

  test('private when all entries are private', () => {
    expect(classifyIpTargets(['192.168.1.1', '10.0.0.0/24'])).toBe('private')
  })

  test('public when all entries are public', () => {
    expect(classifyIpTargets(['8.8.8.8', '1.1.1.1'])).toBe('public')
  })

  test('mixed when private and public are combined', () => {
    expect(classifyIpTargets(['192.168.1.1', '8.8.8.8'])).toBe('mixed')
  })
})

describe('the Kali sandbox address pool (G-05: recon on the host network reaches every sandbox bridge)', () => {
  test('equals SUBNET_POOL in both Python contract copies', () => {
    const repo = path.resolve(__dirname, '../../..')
    for (const copy of ['agentic/sandbox_contract.py', 'recon_orchestrator/sandbox_contract.py']) {
      const source = readFileSync(path.join(repo, copy), 'utf8')
      expect([copy, /^SUBNET_POOL = "([^"]+)"$/m.exec(source)?.[1]]).toEqual([copy, SANDBOX_ADDRESS_POOL])
    }
  })

  test('an address inside it, a CIDR that overlaps it from either side, and an IPv4-mapped address are in it', () => {
    for (const entry of ['10.214.0.0', '10.214.0.4', ' 10.214.255.255 ', '10.214.7.0/24', '10.214.0.0/16', '10.208.0.0/12',
      '10.0.0.0/8', '0.0.0.0/0', '::ffff:10.214.1.2', '::FFFF:10.214.1.0/120']) {
      expect([entry, inSandboxAddressPool(entry)]).toEqual([entry, true])
    }
  })

  test('neighbours, public and IPv6 addresses, and what does not parse are not', () => {
    for (const entry of ['10.213.255.255', '10.215.0.0', '10.213.0.0/24', '10.215.0.0/16', '8.8.8.8', '2001:db8::1',
      'fe80::1', '', 'not-an-ip', '10.214.0.1/33', '10.214.0.1/x', '10.214.0', '10.214.0.256']) {
      expect([entry, inSandboxAddressPool(entry)]).toEqual([entry, false])
    }
  })

  test('sandboxPoolTargets keeps only the entries in it', () => {
    expect(sandboxPoolTargets(['8.8.8.8', '10.214.2.9', '10.0.0.0/8'])).toEqual(['10.214.2.9', '10.0.0.0/8'])
    expect(sandboxPoolTargets(null)).toEqual([])
  })
})
