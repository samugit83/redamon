import { describe, test, expect } from 'vitest'
import { isPrivateOrLocalIp, classifyIpTargets } from './ip-target-utils'

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
