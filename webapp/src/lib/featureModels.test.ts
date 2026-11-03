/**
 * Server helpers of Models by feature: the saved-model read, the PUT patch
 * validation, and the mapping of agent failures onto the shared codes.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockFindUnique = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { userSettings: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } },
}))

import {
  agentCodedError,
  agentFailureCode,
  featureModelErrorResponse,
  featureModelsMap,
  modelUsedMismatch,
  parseFeatureModelsPatch,
  readFeatureModel,
} from './featureModels'
import { AgentUnreachableError } from './agentFetch'

beforeEach(() => {
  mockFindUnique.mockReset()
})

describe('readFeatureModel', () => {
  test('reads the saved model with a narrow select', async () => {
    mockFindUnique.mockResolvedValue({ featureModels: { triage: 'claude-haiku-4-5' } })
    expect(await readFeatureModel('u1', 'triage')).toBe('claude-haiku-4-5')
    expect(mockFindUnique).toHaveBeenCalledWith({ where: { userId: 'u1' }, select: { featureModels: true } })
  })

  test('a user with no settings row has no model', async () => {
    mockFindUnique.mockResolvedValue(null)
    expect(await readFeatureModel('u1', 'triage')).toBe('')
  })

  test('a missing key is no model', async () => {
    mockFindUnique.mockResolvedValue({ featureModels: { codefix: 'gpt-5' } })
    expect(await readFeatureModel('u1', 'triage')).toBe('')
  })

  test('a non-string value is no model', async () => {
    for (const bad of [42, null, { id: 'x' }, ['gpt-5'], true]) {
      mockFindUnique.mockResolvedValue({ featureModels: { triage: bad } })
      expect(await readFeatureModel('u1', 'triage'), JSON.stringify(bad)).toBe('')
    }
  })

  test('a malformed column is no model', async () => {
    for (const bad of [null, 'triage', ['triage'], 7]) {
      mockFindUnique.mockResolvedValue({ featureModels: bad })
      expect(await readFeatureModel('u1', 'triage')).toBe('')
    }
  })
})

describe('featureModelsMap', () => {
  test('keeps string values only', () => {
    expect(featureModelsMap({ triage: 'a', codefix: 3, x: 'b' })).toEqual({ triage: 'a', x: 'b' })
    expect(featureModelsMap(null)).toEqual({})
    expect(featureModelsMap([])).toEqual({})
  })
})

describe('parseFeatureModelsPatch', () => {
  test('splits sets from removals', () => {
    expect(parseFeatureModelsPatch({ triage: 'claude-haiku-4-5', codefix: '' })).toEqual({
      set: { triage: 'claude-haiku-4-5' },
      removed: ['codefix'],
    })
  })

  test('refuses a non-object, an unknown key, a non-string, an over-long id and an excluded prefix', () => {
    const bad: unknown[] = [
      null, 'triage', ['triage'], 5,
      { graph_query: 'gpt-5' },
      { triage: 5 },
      { triage: null },
      { triage: 'x'.repeat(201) },
      { preset_generator: 'bedrock/anthropic.claude-3-5-sonnet' },
      { triage: 'gpt\u0000-5' },
    ]
    for (const raw of bad) {
      expect(parseFeatureModelsPatch(raw), JSON.stringify(raw)).toHaveProperty('error')
    }
  })

  test('one bad entry refuses the whole patch', () => {
    expect(parseFeatureModelsPatch({ triage: 'ok-model', nope: 'x' })).toHaveProperty('error')
  })

  test('200 characters is allowed', () => {
    expect(parseFeatureModelsPatch({ triage: 'x'.repeat(200) })).toEqual({ set: { triage: 'x'.repeat(200) }, removed: [] })
  })

  test('Agent in the Loop is refused for a core feature and for a plugin feature', () => {
    // A feature's model call has no chat run behind it, so no driver can answer.
    const core = parseFeatureModelsPatch({ triage: 'loop/mcp' })
    expect(core).toHaveProperty('error')
    expect((core as { error: string }).error).toMatch(/Agent in the Loop answers only inside a chat run/)
    const plugin = parseFeatureModelsPatch({ 'plugin:acme': 'loop/mcp' }, { pluginFeatureIds: new Set(['plugin:acme']) })
    expect(plugin).toHaveProperty('error')
    expect(parseFeatureModelsPatch({ 'plugin:acme': 'gpt-5' }, { pluginFeatureIds: new Set(['plugin:acme']) }))
      .toEqual({ set: { 'plugin:acme': 'gpt-5' }, removed: [] })
  })
})

describe('featureModelErrorResponse', () => {
  test('status from the table, the fixed message, the feature and the model', async () => {
    const res = featureModelErrorResponse('model_unavailable', 'roe_parse', { model: 'gpt-5' })
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Your model gpt-5 could not be used',
      code: 'model_unavailable',
      featureId: 'roe_parse',
      model: 'gpt-5',
    })
  })

  test('no model key when none is given; a custom error wins', async () => {
    const res = featureModelErrorResponse('model_required', 'triage', { error: 'Pick one' })
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'Pick one', code: 'model_required', featureId: 'triage' })
  })
})

describe('agentFailureCode', () => {
  test('the agentFetch timeout is agent_timeout', () => {
    const timeout = new DOMException('The operation was aborted due to timeout', 'TimeoutError')
    expect(agentFailureCode(new AgentUnreachableError(timeout))).toBe('agent_timeout')
  })

  test('a refused connection, a caller abort or anything else is agent_unreachable', () => {
    const refused = Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } })
    expect(agentFailureCode(new AgentUnreachableError(refused))).toBe('agent_unreachable')
    expect(agentFailureCode(new AgentUnreachableError(new DOMException('aborted', 'AbortError')))).toBe('agent_unreachable')
    expect(agentFailureCode(new Error('boom'))).toBe('agent_unreachable')
    expect(agentFailureCode(undefined)).toBe('agent_unreachable')
  })
})

describe('modelUsedMismatch', () => {
  test('matching echo is fine', () => {
    expect(modelUsedMismatch({ model_used: 'gpt-5', text: 'x' }, 'gpt-5')).toBe(false)
  })

  test('a missing, different or non-string echo is a mismatch', () => {
    expect(modelUsedMismatch({ text: 'x' }, 'gpt-5')).toBe(true)
    expect(modelUsedMismatch({ model_used: 'claude-opus-4-6' }, 'gpt-5')).toBe(true)
    expect(modelUsedMismatch({ model_used: 5 }, 'gpt-5')).toBe(true)
    expect(modelUsedMismatch(null, 'gpt-5')).toBe(true)
    expect(modelUsedMismatch('gpt-5', 'gpt-5')).toBe(true)
  })
})

describe('agentCodedError', () => {
  test('passes model_unavailable through with the fixed message, never the agent text', async () => {
    const res = agentCodedError(503, { code: 'model_unavailable', error: 'invalid x-api-key sk-ant-abc123' }, 'report_narratives', 'claude-opus-4-6')
    expect(res).not.toBeNull()
    expect(res!.status).toBe(503)
    const body = await res!.json()
    expect(body).toEqual({
      error: 'Your model claude-opus-4-6 could not be used',
      code: 'model_unavailable',
      featureId: 'report_narratives',
      model: 'claude-opus-4-6',
    })
    expect(JSON.stringify(body)).not.toContain('sk-ant')
  })

  test('passes providers_unreachable and agent_timeout through', async () => {
    const a = agentCodedError(503, { code: 'providers_unreachable' }, 'roe_parse', 'm')
    expect(a!.status).toBe(503)
    expect(await a!.json()).toMatchObject({ code: 'providers_unreachable', featureId: 'roe_parse' })
    const b = agentCodedError(504, { code: 'agent_timeout' }, 'roe_parse', 'm')
    expect(b!.status).toBe(504)
    expect(await b!.json()).toMatchObject({ code: 'agent_timeout' })
  })

  test('anything else is left to the route', () => {
    expect(agentCodedError(401, { detail: 'bad key' }, 'roe_parse', 'm')).toBeNull()
    expect(agentCodedError(429, { code: 'busy' }, 'roe_parse', 'm')).toBeNull()
    expect(agentCodedError(503, { code: 'agent_unreachable' }, 'roe_parse', 'm')).toBeNull()
    expect(agentCodedError(409, { code: 'model_required' }, 'roe_parse', 'm')).toBeNull()
    expect(agentCodedError(500, null, 'roe_parse', 'm')).toBeNull()
    expect(agentCodedError(200, { code: 'model_unavailable' }, 'roe_parse', 'm')).toBeNull()
  })
})
