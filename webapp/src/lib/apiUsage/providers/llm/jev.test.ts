import { describe, test, expect } from 'vitest'
import { jevProbe, modelsRequest } from './jev'
import { jevOpenrouterProbe } from './openrouter'
import { LLM_PROBES } from '../../registry'
import { res, runProbe } from '../../testUtils'

const KEY = 'synthetic-key'
const MODELS = { models: [{ name: 'jev-1.13.0' }] }

describe('free Jev usage probes', () => {
  test('direct Jev uses only fixed model-listing endpoint and does not claim billing access', async () => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(200, MODELS)])
    expect(result.outcome).toBe('valid_no_usage')
    expect(requests).toEqual([modelsRequest(KEY)])
    expect(requests[0]).toMatchObject({ method: 'GET', url: 'https://api.typesafe.ai/v1/models' })
    expect(result.notes?.join(' ')).toMatch(/decision access and remaining credit are not checked/)
    expect(jevProbe.costNote).toMatch(/Free/)
  })
  test.each([[401, 'invalid_key'], [403, 'invalid_key'], [402, 'quota_exhausted'], [429, 'rate_limited'], [529, 'provider_error']])('direct status %s is safely mapped', async (status, kind) => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(status as number, { detail: { error_type: 'synthetic_error', message: 'unsafe upstream target data' } })])
    expect(result.error?.kind).toBe(kind)
    expect(result.error?.message).not.toContain('unsafe upstream')
    expect(requests).toHaveLength(1)
  })
  test('malformed direct listing fails without inference', async () => {
    const { result, requests } = await runProbe(jevProbe, KEY, [res(200, { models: 'invalid' })])
    expect(result.error?.kind).toBe('unexpected_response')
    expect(requests).toHaveLength(1)
  })
  test('OpenRouter Jev uses free OpenRouter key metadata, never TypeSafe or systemone', async () => {
    expect(LLM_PROBES.jev_openrouter).toBe(jevOpenrouterProbe)
    const { result, requests } = await runProbe(jevOpenrouterProbe, KEY, [res(200, { data: { limit: 10, limit_remaining: 4, usage: 6 } })])
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({ method: 'GET', url: 'https://openrouter.ai/api/v1/key' })
    expect(result.outcome).toBe('usage')
    expect(result.meters[0]).toMatchObject({ limit: 10, remaining: 4, used: 6 })
    expect(result.notes?.join(' ')).toMatch(/Jev decision access is not checked/)
    expect(jevOpenrouterProbe.costNote).toMatch(/Free/)
  })
})
