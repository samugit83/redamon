import { describe, test, expect, vi } from 'vitest'
import {
  deriveProfileFromMaterial,
  materialIsEmpty,
  summarizeMaterial,
  mergeMaterial,
  defaultRecordingScope,
  refreshActiveRecordingScope,
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
  test('listed subdomains record only those hosts (+ the root with "."), RoE excluded', () => {
    const scope = defaultRecordingScope({
      targetDomain: 'target.test', subdomainList: ['app.', 'pay.', '.'],
      roeExcludedHosts: ['pay.target.test'],
    })
    // A listed project never authorised *.target.test (§4.6 EXACT).
    expect(scope).toEqual(['app.target.test', 'target.test'])
  })

  test('an enumerated domain covers subdomains via the wildcard, so a login at app.* is recorded', () => {
    // Apex-only scope meant the proxy tagged nothing when the operator logged in
    // at a subdomain, and the modal then reported "no login detected".
    expect(defaultRecordingScope({ targetDomain: 'target.test' })).toEqual(['*.target.test'])
    expect(defaultRecordingScope({ targetDomain: 'target.test', subdomainList: ['.'] }))
      .toEqual(['*.target.test', 'target.test'])
  })

  test('a Domain batch records its groups (it recorded nothing before)', () => {
    expect(defaultRecordingScope({
      domainBatchMode: true, targetDomain: '',
      domainBatchHosts: ['*.example.org', 'example.org', 'www.acme.test'],
      roeExcludedHosts: ['example.org'],
    })).toEqual(['www.acme.test'])
    expect(defaultRecordingScope({
      domainBatchMode: true, domainBatchHosts: ['*.example.org', 'www.acme.test'],
    })).toEqual(['*.example.org', 'www.acme.test'])
  })

  test('a refused entry never widens the recording', () => {
    expect(defaultRecordingScope({ domainBatchMode: true, domainBatchHosts: ['*.github.io', 'www.example.com'] }))
      .toEqual(['www.example.com'])
  })

  test('ip mode uses target IPs', () => {
    expect(defaultRecordingScope({ ipMode: true, targetIps: ['10.0.0.5'] })).toEqual(['10.0.0.5'])
  })

  // D-22: the recording scope is the auth scope, and credentials never go to a
  // hostname scanned on the target IPs (it may move after the scan). The agent's
  // auth_scope_patterns and recon's default_scope_hosts pin the same rule.
  test.each(['ip_only', 'record_only', 'record_filter', 'scan_all'])(
    'ip mode records the target IPs only, whatever the hostname mode (%s)', mode => {
      expect(defaultRecordingScope({
        ipMode: true, targetIps: ['10.0.0.5', '192.0.2.0/24'], targetDomain: 'example.com',
        ipHostnameMode: mode, ipHostnameInclude: ['*.example.com'], ipHostnameScanAllConfirmed: true,
      })).toEqual(['10.0.0.5', '192.0.2.0/24'])
    })

  test('empty project → empty scope (fail-safe)', () => {
    expect(defaultRecordingScope({})).toEqual([])
  })

  // drift-map #20: the matcher was exact host or `.suffix` only, so a wildcard,
  // CIDR or IPv6 exclusion the scans enforce left the host in the recording.
  test('a wildcard, CIDR or IPv6 exclusion removes the hosts recon would refuse', () => {
    expect(defaultRecordingScope({
      targetDomain: 'target.test', subdomainList: ['app.', 'pay.', '.'],
      roeExcludedHosts: ['*.target.test'],
    })).toEqual(['target.test'])
    expect(defaultRecordingScope({
      ipMode: true, targetIps: ['10.0.0.5', '192.0.2.10'], roeExcludedHosts: ['10.0.0.0/24'],
    })).toEqual(['192.0.2.10'])
    expect(defaultRecordingScope({
      ipMode: true, targetIps: ['2001:db8::5'], roeExcludedHosts: ['2001:0DB8::/32'],
    })).toEqual([])
  })
})

describe('refreshActiveRecordingScope', () => {
  const project = { domainBatchMode: true, domainBatchHosts: ['*.example.com'] }
  const store = (session: { id: string } | null) => ({
    recordingSession: { findFirst: vi.fn().mockResolvedValue(session), update: vi.fn().mockResolvedValue({}) },
  })

  test('re-derives the active recording of that project', async () => {
    const db = store({ id: 'rec-1' })
    expect(await refreshActiveRecordingScope(db as never, 'p1', project)).toBe(true)
    expect(db.recordingSession.findFirst.mock.calls[0][0].where).toMatchObject({ projectId: 'p1', state: 'active' })
    expect(db.recordingSession.update).toHaveBeenCalledWith({
      where: { id: 'rec-1' }, data: { scopeHosts: ['*.example.com'] },
    })
  })

  test('no active recording, nothing written', async () => {
    const db = store(null)
    expect(await refreshActiveRecordingScope(db as never, 'p1', project)).toBe(false)
    expect(db.recordingSession.update).not.toHaveBeenCalled()
  })

  test('a failing store never throws into the caller', async () => {
    const db = store({ id: 'rec-1' })
    db.recordingSession.update.mockRejectedValue(new Error('db down'))
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await refreshActiveRecordingScope(db as never, 'p1', project)).toBe(false)
    err.mockRestore()
  })
})
