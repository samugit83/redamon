/**
 * An LLM provider's secrets in an API answer (HD-23, review of 1.6): the key fields and
 * every Extra Headers value are masked for any browser caller, an admin's read of another
 * account included; a save that sends a masked header value back keeps the stored one.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { maskProvider, restoreMaskedHeaders } from './llmProviderMask'

describe('maskProvider', () => {
  test('the keys and every header value are masked; configuration stays readable', () => {
    const out = maskProvider({
      id: 'p1', baseUrl: 'https://llm.example.com/v1', apiKey: 'sk-SECRET-1234',
      awsAccessKeyId: 'AKIA-SECRET-5678', awsSecretKey: '', awsBearerToken: 'bt-SECRET-9012',
      defaultHeaders: { Authorization: 'Bearer hdr-SECRET-3456', 'X-Org': 'acme', 'X-Short': 'abc' },
    })
    expect(out).toMatchObject({
      id: 'p1', baseUrl: 'https://llm.example.com/v1', apiKey: '••••••••1234',
      awsAccessKeyId: '••••••••5678', awsSecretKey: '', awsBearerToken: '••••••••9012',
      defaultHeaders: { Authorization: '••••••••3456', 'X-Org': '••••', 'X-Short': '••••' },
    })
    expect(JSON.stringify(out)).not.toMatch(/SECRET|acme/)
  })

  test('headers that are not an object of values are not returned', () => {
    expect(maskProvider({ apiKey: '', defaultHeaders: 'Bearer hdr-SECRET' }).defaultHeaders).toEqual({})
    expect(maskProvider({ apiKey: '', defaultHeaders: null }).defaultHeaders).toEqual({})
  })
})

describe('restoreMaskedHeaders', () => {
  test('a masked value keeps the stored one; a typed value wins; a mask with nothing stored is dropped', () => {
    expect(restoreMaskedHeaders(
      { Authorization: '••••••••3456', 'X-New': 'typed', 'X-Ghost': '••••' },
      { Authorization: 'Bearer hdr-SECRET-3456' },
    )).toEqual({ Authorization: 'Bearer hdr-SECRET-3456', 'X-New': 'typed' })
  })

  test('anything but an object passes through unchanged', () => {
    expect(restoreMaskedHeaders(undefined, { A: 'b' })).toBeUndefined()
    expect(restoreMaskedHeaders('raw', { A: 'b' })).toBe('raw')
  })
})
