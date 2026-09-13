/** @vitest-environment node */
/**
 * Strategy row 1 (L1): the TypeScript restore-time cert_key must be byte-identical
 * to the Python writer's.
 *
 * graph_db/cert_key.build_cert_key (Python, scan-time) and deriveCertKey
 * (TypeScript, snapshot-restore-time) key the SAME Certificate node. If the two
 * surrogates diverge by one character, activating an old scan version restores a
 * certificate under a key no scanner will ever MERGE onto again: the project
 * silently carries two nodes for one certificate, and Recon Delta reports a
 * rotation that never happened.
 *
 * The expected values below are GOLDEN VECTORS produced by the Python
 * implementation. Do not "fix" them to match the TS output -- if they disagree,
 * one of the two implementations is wrong.
 *
 *   python3 -c "import cert_key; print(cert_key.build_cert_key(subject_cn='mail.acme.com', ...))"
 *
 * Run: npx vitest run src/lib/graphRestore.certKey.test.ts
 */
import { describe, test, expect } from 'vitest'
import { deriveCertKey } from './graphRestore'

describe('deriveCertKey — parity with graph_db/cert_key.build_cert_key', () => {
  test('surrogate over subject_cn|issuer|not_before|not_after matches Python', () => {
    expect(deriveCertKey({
      subject_cn: 'mail.acme.com',
      issuer: "CN=R3, O=Let's Encrypt",
      not_before: '2026-01-01T00:00:00Z',
      not_after: '2027-01-01T00:00:00Z',
    })).toBe('surrogate:f1e6af1f57bdef28f3a641586f13e89b')
  })

  test('empty subject CN (SAN-only cert) matches Python', () => {
    expect(deriveCertKey({
      subject_cn: '',
      issuer: 'CN=R3',
      not_before: '2026-01-01T00:00:00Z',
      not_after: '2027-01-01T00:00:00Z',
    })).toBe('surrogate:b8ccf6980180ee2421816692be83135d')
  })

  test('all fields absent matches Python (missing === empty string)', () => {
    // Python uses `x or ''`; TS must treat a MISSING key exactly like ''.
    expect(deriveCertKey({})).toBe('surrogate:98c4b7d37a4c63c3f69f7a0f794fb8a9')
  })

  test('partial fields match Python', () => {
    expect(deriveCertKey({ subject_cn: 'a.com' })).toBe('surrogate:5cd1df4b021aefa34c0ecbab16ba9258')
  })

  test('null and non-string values are treated as empty, like Python None', () => {
    expect(deriveCertKey({ subject_cn: null, issuer: undefined, not_before: 42, not_after: {} }))
      .toBe(deriveCertKey({}))
  })

  test('fingerprint wins and is lowercased, matching Python', () => {
    expect(deriveCertKey({ fingerprint_sha256: 'AABBCC' })).toBe('sha256:aabbcc')
  })

  test('a fingerprinted cert never falls through to the surrogate', () => {
    const withFp = deriveCertKey({ fingerprint_sha256: 'ff00', subject_cn: 'a.com' })
    expect(withFp).toBe('sha256:ff00')
    expect(withFp).not.toContain('surrogate')
  })

  test('legacy fingerprint spellings resolve to the same key as the canonical one', () => {
    // A pre-migration snapshot carries GVM's sha256_fingerprint or Censys's
    // fingerprint. All three must land on ONE node, or the migration duplicates.
    const canonical = deriveCertKey({ fingerprint_sha256: 'abc123' })
    expect(deriveCertKey({ sha256_fingerprint: 'abc123' })).toBe(canonical)
    expect(deriveCertKey({ fingerprint: 'abc123' })).toBe(canonical)
  })
})
