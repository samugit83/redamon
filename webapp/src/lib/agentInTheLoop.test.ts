// @vitest-environment node
import { afterEach, describe, expect, it, test, vi } from 'vitest'
import {
  LOOP_MODEL_ID, LOOP_PREFIX, agentInTheLoopEnabled, excludeLoop, isLoopModel, projectModelProblem,
  profileOffered, rememberedDefaults,
} from './agentInTheLoop'
import { LLM_FEATURES, modelAllowedForFeature } from './llmFeatures'

describe('isLoopModel', () => {
  it('recognises loop ids', () => {
    expect(isLoopModel('loop/mcp')).toBe(true)
    expect(isLoopModel(' loop/x ')).toBe(true)
    expect(isLoopModel(LOOP_MODEL_ID)).toBe(true)
    expect(LOOP_MODEL_ID.startsWith(LOOP_PREFIX)).toBe(true)
  })

  it.each([null, undefined, '', '   ', 'looper', 'custom/loop', 'loop', 'LOOP/mcp',
    'claude-opus-4-6', 'openai_compat/loop/mcp', 42])('rejects %s', (value) => {
    expect(isLoopModel(value)).toBe(false)
  })
})

describe('agentInTheLoopEnabled', () => {
  afterEach(() => vi.unstubAllEnvs())

  it.each(['true', 'TRUE', '1', ' yes '])('is on for %s', (raw) => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', raw)
    expect(agentInTheLoopEnabled()).toBe(true)
  })

  it.each(['false', '0', '', 'off', 'enabled'])('is off for %s', (raw) => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', raw)
    expect(agentInTheLoopEnabled()).toBe(false)
  })

  it('is off when absent', () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', undefined as unknown as string)
    expect(agentInTheLoopEnabled()).toBe(false)
  })
})

describe('where a loop model may not go', () => {
  afterEach(() => vi.unstubAllEnvs())

  test('every non-agent picker filter drops it', () => {
    expect(excludeLoop('loop/mcp')).toBe(false)
    expect(excludeLoop('claude-opus-4-6')).toBe(true)
  })

  test('no core feature can run on it', () => {
    for (const f of LLM_FEATURES) expect(modelAllowedForFeature(f.id, 'loop/mcp'), f.id).toBe(false)
    expect(modelAllowedForFeature('triage', 'claude-opus-4-6')).toBe(true)
  })

  test('project writes: the pipeline model never, the agent model only while on', () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
    expect(projectModelProblem({ agentOpenaiModel: 'loop/mcp' })).toBeNull()
    expect(projectModelProblem({ aiPipelineModel: 'loop/mcp' })).toMatch(/recon runs outside any chat/)
    expect(projectModelProblem({ agentOpenaiModel: 'gpt-5', aiPipelineModel: 'gpt-5' })).toBeNull()
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    expect(projectModelProblem({ agentOpenaiModel: 'loop/mcp' })).toBe('Agent in the Loop is turned off on this deployment.')
    expect(projectModelProblem({})).toBeNull()
  })
})

describe('defaults and profiles', () => {
  test('a loop agent model is never remembered as the default; the pipeline model is', () => {
    expect(rememberedDefaults('loop/mcp', 'gpt-5')).toEqual({ defaultAiPipelineModel: 'gpt-5' })
    expect(rememberedDefaults('claude-opus-4-6', 'gpt-5'))
      .toEqual({ defaultAgentModel: 'claude-opus-4-6', defaultAiPipelineModel: 'gpt-5' })
    expect(rememberedDefaults('', 'gpt-5')).toBeNull()
    expect(rememberedDefaults('gpt-5', '')).toBeNull()
  })

  test('the loop profile is offered only while the switch is on', () => {
    expect(profileOffered('agent_in_the_loop', false)).toBe(false)
    expect(profileOffered('agent_in_the_loop', true)).toBe(true)
    expect(profileOffered('pentest', false)).toBe(true)
  })
})
