/**
 * The agent names the tools (its `_NAME_RE` in agentic/navigator/remote_tools.py filters the list
 * the webapp serves) and the webapp validates every trace event naming one. When the two patterns
 * differ, a tool the agent accepts runs but every one of its trace events is dropped here.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { validateAgentEvent } from './events'

const REMOTE_TOOLS_PY = join(__dirname, '../../../../agentic/navigator/remote_tools.py')

const toolEvent = (name: string, summary = 's') => ({ type: 'tool', route: 'graph', name, status: 'end', summary })
const webappAccepts = (name: string) => validateAgentEvent(toolEvent(name)) !== null

function agentNamePattern(src: string): RegExp {
  const m = /^_NAME_RE\s*=\s*re\.compile\(r"([^"]+)"\)/m.exec(src)
  expect(m, '_NAME_RE not found in remote_tools.py').toBeTruthy()
  return new RegExp(m![1])
}

const SAMPLES = [
  'run_cypher', 'wiki_toc', 'unknown_tool', 'scan_v2', 'a1', 'ab', 'a_', 'a'.repeat(60),
  'x', '', 'a'.repeat(61), '_private', '2fa_check', '9', 'Bad', 'run-cypher', 'wiki read', 'tool.x', 'été',
]

describe('the webapp accepts exactly the tool names the agent accepts', () => {
  const available = existsSync(REMOTE_TOOLS_PY)
  const src = available ? readFileSync(REMOTE_TOOLS_PY, 'utf8') : ''

  test.skipIf(!available)('each sample name gets the same answer on both sides', () => {
    const agent = agentNamePattern(src)
    for (const name of SAMPLES) {
      expect([name, webappAccepts(name)]).toEqual([name, agent.test(name)])
    }
  })

  test.skipIf(!available)('every tool the agent has a summary for keeps its trace events', () => {
    const block = /^SUMMARIES\s*=\s*\{([\s\S]*?)^\}/m.exec(src)
    expect(block, 'SUMMARIES not found in remote_tools.py').toBeTruthy()
    const names = [...block![1].matchAll(/^\s*"([^"]+)":/gm)].map(m => m[1])
    expect(names.length).toBeGreaterThan(0)
    for (const name of names) expect([name, webappAccepts(name)]).toEqual([name, true])
  })
})

// A valid name, so the summary cap is what drops it: a one-letter name fails the name check first.
test('a tool event with a valid name and a summary over the cap is dropped', () => {
  expect(validateAgentEvent(toolEvent('run_cypher', 's'.repeat(200)))).not.toBeNull()
  expect(validateAgentEvent(toolEvent('run_cypher', 's'.repeat(201)))).toBeNull()
})
