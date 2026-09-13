import { describe, test, expect } from 'vitest'
import {
  deriveProfileFromMaterial,
  materialIsEmpty,
  summarizeMaterial,
  mergeMaterial,
  defaultRecordingScope,
} from './recordingSession'

describe('deriveProfileFromMaterial', () => {
  test('cookie → cookie mode', () => {
    expect(deriveProfileFromMaterial({ cookie: 'sid=a' }))
      .toEqual({ authType: 'cookie', authValue: 'sid=a', authHeaderName: '', extraHeaders: {} })
  })

  test('lone bearer → bearer mode, prefix stripped', () => {
    expect(deriveProfileFromMaterial({ authorization: 'Bearer XYZ' }))
      .toMatchObject({ authType: 'bearer', authValue: 'XYZ' })
  })

  test('cookie + bearer keeps both (bearer as extra)', () => {
    const d = deriveProfileFromMaterial({ cookie: 'sid=a', authorization: 'Bearer XYZ' })
    expect(d.authType).toBe('cookie')
    expect(d.extraHeaders).toEqual({ Authorization: 'Bearer XYZ' })
  })

  test('non-bearer authorization → extra header, extras-only', () => {
    const d = deriveProfileFromMaterial({ authorization: 'Basic abc' })
    expect(d.authType).toBe('none')
    expect(d.extraHeaders).toEqual({ Authorization: 'Basic abc' })
  })

  test('csrf extra carried through', () => {
    const d = deriveProfileFromMaterial({ cookie: 'sid=a', extra: { 'X-CSRF-Token': 'c' } })
    expect(d.extraHeaders).toEqual({ 'X-CSRF-Token': 'c' })
  })
})

describe('materialIsEmpty', () => {
  test('true for nothing usable', () => {
    expect(materialIsEmpty(null)).toBe(true)
    expect(materialIsEmpty({})).toBe(true)
    expect(materialIsEmpty({ host: 'h' })).toBe(true)
  })
  test('false when a cookie/bearer/extra is present', () => {
    expect(materialIsEmpty({ cookie: 'sid=a' })).toBe(false)
    expect(materialIsEmpty({ authorization: 'Bearer x' })).toBe(false)
    expect(materialIsEmpty({ extra: { 'X-A': '1' } })).toBe(false)
  })
})

describe('summarizeMaterial', () => {
  test('masked, secret-free', () => {
    const s = summarizeMaterial({ cookie: 'sid=secret', authorization: 'Bearer secret', hosts: ['h'] })
    expect(JSON.stringify(s)).not.toContain('secret')
    expect(s).toMatchObject({ hasCookie: true, extraHeaderNames: ['Authorization'], hosts: ['h'] })
  })
})

describe('mergeMaterial', () => {
  test('same cookie name is refreshed; hosts accumulate', () => {
    const a = mergeMaterial(null, { cookie: 'sid=1', host: 'h1' })
    const b = mergeMaterial(a, { cookie: 'sid=2', extra: { 'X-A': '1' }, host: 'h2' })
    expect(b.cookie).toBe('sid=2')
    expect(b.extra).toEqual({ 'X-A': '1' })
    expect(b.hosts).toEqual(['h1', 'h2'])
  })

  test('a later unrelated cookie does NOT wipe the session cookie', () => {
    // Spool records arrive unordered and span hosts: a request to a static host
    // carrying only `theme=dark` used to replace the whole Cookie string and
    // silently discard the captured session.
    const a = mergeMaterial(null, { cookie: 'sid=secret-session', host: 'app.t' })
    const b = mergeMaterial(a, { cookie: 'theme=dark', host: 'static.t' })
    expect(b.cookie).toContain('sid=secret-session')
    expect(b.cookie).toContain('theme=dark')
  })

  test('cookies from several hosts are unioned by name', () => {
    const a = mergeMaterial(null, { cookie: 'a=1; b=2', host: 'h1' })
    const b = mergeMaterial(a, { cookie: 'b=9; c=3', host: 'h2' })
    const pairs = (b.cookie || '').split('; ').sort()
    expect(pairs).toEqual(['a=1', 'b=9', 'c=3'])
  })
})

describe('defaultRecordingScope', () => {
  test('domain + subdomains, RoE excluded', () => {
    const scope = defaultRecordingScope({
      targetDomain: 'target.test', subdomainList: ['app.', 'pay.', '.'],
      roeEnabled: true, roeExcludedHosts: ['pay.target.test'],
    })
    expect(scope).toContain('target.test')
    expect(scope).toContain('app.target.test')
    expect(scope).not.toContain('pay.target.test')
  })

  test('covers subdomains via the wildcard, so a login at app.* is recorded', () => {
    // Apex-only scope meant the proxy tagged nothing when the operator logged in
    // at a subdomain, and the modal then reported "no login detected".
    expect(defaultRecordingScope({ targetDomain: 'target.test' }))
      .toEqual(['target.test', '*.target.test'])
  })

  test('ip mode uses target IPs', () => {
    expect(defaultRecordingScope({ ipMode: true, targetIps: ['10.0.0.5'] })).toEqual(['10.0.0.5'])
  })

  test('empty project → empty scope (fail-safe)', () => {
    expect(defaultRecordingScope({})).toEqual([])
  })
})
