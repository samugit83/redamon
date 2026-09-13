/** @vitest-environment node */
import { describe, test, expect } from 'vitest'
import { signTag } from './redamonCtx'

describe('signTag — cross-compatible with redamon_ctx.py', () => {
  // Reference token produced by scanners/capture_proxy/redamon_ctx.py sign_tag
  // for this exact payload + key. If the canonicalization drifts, the ingest
  // worker's verify_tag will reject operator tags, so this must stay byte-exact.
  test('matches the Python reference token', () => {
    const tok = signTag(
      { source: 'operator', project_id: 'p1', user_id: 'u1', session_id: 'rec1' },
      'test-key-123',
    )
    expect(tok).toBe(
      'eyJwcm9qZWN0X2lkIjoicDEiLCJzZXNzaW9uX2lkIjoicmVjMSIsInNvdXJjZSI6Im9wZXJhdG9yIiwidXNlcl9pZCI6InUxIn0' +
      '.s0-lZ0Ha_J9TU_Y-7gseYxIlwz97MMne7OdVMYVTw94',
    )
  })

  test('drops null/undefined fields and is header-safe', () => {
    const tok = signTag(
      { source: 'operator', project_id: 'p1', user_id: 'u1', session_id: undefined },
      'k',
    )
    expect(tok).not.toContain('=')
    expect(tok.split('.')).toHaveLength(2)
    // No session_id in the body segment.
    const body = JSON.parse(Buffer.from(tok.split('.')[0], 'base64url').toString())
    expect(body).not.toHaveProperty('session_id')
    expect(Object.keys(body)).toEqual(['project_id', 'source', 'user_id'])
  })

  test('throws on empty key', () => {
    expect(() => signTag({ source: 'operator' }, '')).toThrow()
  })
})
