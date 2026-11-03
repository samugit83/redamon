/**
 * The webapp and the agent each hold a copy of the loop's identity: the model
 * prefix and id, the switch's accepted values, and the step contract version the
 * skill pack is written for. A copy that moves alone either routes `loop/mcp` to a
 * provider on one side or ships a skill that misreads the steps.
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { LOOP_MODEL_ID, LOOP_MODEL_LABEL, LOOP_PREFIX, agentInTheLoopEnabled } from './agentInTheLoop'
import { LOOP_CONTRACT_VERSION } from './mcp/loopSkill'

const LOOP_INIT_PY = join(__dirname, '../../../agentic/agent_in_the_loop/__init__.py')

function pythonConstant(src: string, name: string): string {
  const m = new RegExp(`^${name}\\s*=\\s*(.+)$`, 'm').exec(src)
  expect(m, `${name} not found in agent_in_the_loop/__init__.py`).toBeTruthy()
  return m![1].trim().replace(/^["']|["']$/g, '')
}

describe('the loop constants equal the agent\'s', () => {
  const available = existsSync(LOOP_INIT_PY)
  const src = available ? readFileSync(LOOP_INIT_PY, 'utf8') : ''

  afterEach(() => vi.unstubAllEnvs())

  test.skipIf(!available)('prefix, model id and label', () => {
    expect(LOOP_PREFIX).toBe(pythonConstant(src, 'LOOP_PREFIX'))
    expect(LOOP_MODEL_ID).toBe(pythonConstant(src, 'LOOP_MODEL_ID'))
    expect(LOOP_MODEL_LABEL).toBe(pythonConstant(src, 'LOOP_MODEL_LABEL'))
  })

  test.skipIf(!available)('the skill pack is written for the agent\'s contract version', () => {
    expect(String(LOOP_CONTRACT_VERSION)).toBe(pythonConstant(src, 'CONTRACT_VERSION'))
  })

  test.skipIf(!available)('the switch accepts the same values on both sides', () => {
    const m = /def loop_enabled\(\)[\s\S]*?in \(([^)]*)\)/.exec(src)
    expect(m, 'loop_enabled not found').toBeTruthy()
    const accepted = [...m![1].matchAll(/["']([^"']+)["']/g)].map(x => x[1])
    expect(accepted.length).toBeGreaterThan(0)
    for (const value of accepted) {
      vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', ` ${value.toUpperCase()} `)
      expect(agentInTheLoopEnabled(), value).toBe(true)
    }
    for (const value of ['false', '0', 'no', 'on', '']) {
      vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', value)
      expect(agentInTheLoopEnabled(), value).toBe(false)
    }
  })
})
