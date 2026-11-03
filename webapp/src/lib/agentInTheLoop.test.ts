// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LOOP_MODEL_ID, LOOP_PREFIX, agentInTheLoopEnabled, isLoopModel } from './agentInTheLoop'

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
