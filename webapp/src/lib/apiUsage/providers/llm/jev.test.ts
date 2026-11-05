/**
 * TypeSafe AI (Jev) probe. No balance endpoint exists, so the probe lists
 * models (free) and then spends one tiny Noul to prove the account has credit.
 * Fixtures follow live answers from api.typesafe.ai; the key is fake.
 */
import { describe, test, expect } from 'vitest'
import { jevProbe, modelsRequest, pingRequest } from './jev'
import { res, runProbe } from '../../testUtils'

const KEY = 'apikey_' + '0'.repeat(36) + '_' + 'f'.repeat(64)

const MODELS = { models: [{ name: 'jev-latest', description: 'x' }, { name: 'jev-preview', description: 'y' }] }
const PING_OK = {
  model: 'jev-1.13.0',
  answers: { ping: { type: 'noul', noul: 0.67 } },
  usage: { input_tokens: 272, output_tokens: 20 },
}
const AUTH_ERROR = {
  detail: { error_type: 'authentication_error', message: 'Cannot authenticate with the server. Please check your API key and try again.' },
}
const BILLING_ERROR = { detail: { error_type: 'billing_error', message: 'Insufficient credit.' } }

describe('requests', () => {
  test('models: GET on the fixed origin, key as a Bearer header, never in the URL', () => {
    expect(modelsRequest(KEY)).toEqual({
      method: 'GET', url: 'https://api.typesafe.ai/v1/models', headers: { Authorization: `Bearer ${KEY}` },
    })
  })

  test('ping: one Noul on the pinned model', () => {
    const r = pingRequest(KEY)
    expect(r.method).toBe('POST')
    expect(r.url).toBe('https://api.typesafe.ai/v1/systemone')
    expect(r.url).not.toContain(KEY)
    const body = JSON.parse(r.body!)
    expect(body.model).toBe('jev-1.13.0')
    expect(Object.values(body.questions)).toEqual([{ type: 'noul', instructions: 'Is this a ping?' }])
  })
})

describe('run', () => {
  test('200 then 200: the key is valid and the account has credit', async () => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(200, MODELS), res(200, PING_OK)])
    expect(result.outcome).toBe('valid_no_usage')
    expect(requests.map(r => `${r.method} ${r.url}`)).toEqual([
      'GET https://api.typesafe.ai/v1/models',
      'POST https://api.typesafe.ai/v1/systemone',
    ])
  })

  test('401 on the listing: key rejected, with TypeSafe\'s own message, and nothing billed', async () => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(401, AUTH_ERROR)])
    expect(result.outcome).toBe('error')
    expect(result.error).toMatchObject({ kind: 'invalid_key', httpStatus: 401, providerCode: 'authentication_error' })
    expect(result.error!.message).toMatch(/Cannot authenticate/)
    expect(requests).toHaveLength(1)
  })

  test('403 (no key accepted at all) is a key problem too', async () => {
    const { result } = await runProbe(jevProbe, KEY, [res(403, { detail: { error_type: 'authentication_error', message: 'Must supply an API key!' } })])
    expect(result.error?.kind).toBe('invalid_key')
  })

  test('402 on the listing: quota used up, no billed call', async () => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(402, BILLING_ERROR)])
    expect(result.error).toMatchObject({ kind: 'quota_exhausted', httpStatus: 402, providerCode: 'billing_error' })
    expect(requests).toHaveLength(1)
  })

  test('402 on the ping: the key works but the account has no credit', async () => {
    const { result } = await runProbe(jevProbe, KEY, [res(200, MODELS), res(402, BILLING_ERROR)])
    expect(result.error).toMatchObject({ kind: 'quota_exhausted', httpStatus: 402 })
    expect(result.error!.message).toBe('Insufficient credit.')
  })

  test('402 without a body still reads as quota used up', async () => {
    const { result } = await runProbe(jevProbe, KEY, [res(200, MODELS), res(402)])
    expect(result.error).toMatchObject({ kind: 'quota_exhausted', message: 'The TypeSafe account has no credit left' })
  })

  test('a malformed listing is a shape error and nothing is billed', async () => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(200, { models: 'nope' })])
    expect(result.error?.kind).toBe('unexpected_response')
    expect(requests).toHaveLength(1)
  })

  test('a malformed ping answer is a shape error', async () => {
    const { result } = await runProbe(jevProbe, KEY, [res(200, MODELS), res(200, { answers: { ping: { type: 'noul' } } })])
    expect(result.error?.kind).toBe('unexpected_response')
  })

  test('429 and 529 map to rate limited and provider error', async () => {
    expect((await runProbe(jevProbe, KEY, [res(429, {})])).result.error?.kind).toBe('rate_limited')
    expect((await runProbe(jevProbe, KEY, [res(200, MODELS), res(529, {})])).result.error?.kind).toBe('provider_error')
  })
})
