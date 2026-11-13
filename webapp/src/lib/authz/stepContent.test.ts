/**
 * stripStepContent (step 4.7, SH-30): a reader below R* gets each ChainStep's structure without its
 * content; the owner, a share with Raw data & files and break-glass get the nodes untouched; other
 * labels are never changed, and the input is never mutated (a cached graph serves the next reader).
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { STEP_CONTENT_PROPS, readsStepContent, stripStepContent } from './stepContent'
import type { ProjectAccess } from './projectAccess'

const access = (level: string, rawData: boolean, via = 'share') =>
  Object.freeze({ project: { id: 'P', userId: 'alice' }, level, toggles: Object.freeze({ rawData }), via }) as unknown as ProjectAccess

const step = () => ({
  id: '7', name: 'Step 2\nnmap', type: 'ChainStep',
  properties: {
    step_id: 's-1', chain_id: 'c-1', iteration: 2, phase: 'informational', tool_name: 'nmap', success: false, duration_ms: 12,
    agent_id: 'root', agent_name: 'root', user_id: 'alice', project_id: 'P',
    thought: 'scan the host', reasoning: 'ports first', output_summary: '22/tcp open', output_analysis: 'ssh exposed',
    tool_args_summary: 'nmap -p- --script-args creds=admin:hunter2 host', error_message: 'stderr: denied',
  },
})
const finding = () => ({ id: '8', name: 'Finding', type: 'ChainFinding', properties: { title: 'open ssh', severity: 'low', thought: 'kept: not a step' } })

describe('stripStepContent', () => {
  test('a read share without Raw data: ChainStep keeps its structure, loses every content property', () => {
    const nodes = [step(), finding()]
    const out = stripStepContent(nodes, access('read', false))
    for (const key of STEP_CONTENT_PROPS) expect(out[0].properties).not.toHaveProperty(key)
    expect(out[0].properties).toEqual({
      step_id: 's-1', chain_id: 'c-1', iteration: 2, phase: 'informational', tool_name: 'nmap', success: false, duration_ms: 12,
      agent_id: 'root', agent_name: 'root', user_id: 'alice', project_id: 'P',
    })
    expect(out[0]).toMatchObject({ id: '7', name: 'Step 2\nnmap', type: 'ChainStep' })
    expect(out[1]).toEqual(finding())
  })

  test('the content list is the four the agent writes plus the command line and the error', () => {
    expect([...STEP_CONTENT_PROPS].sort()).toEqual(['error_message', 'output_analysis', 'output_summary', 'reasoning', 'thought', 'tool_args_summary'])
  })

  test('the input is never mutated', () => {
    const nodes = [step()]
    stripStepContent(nodes, access('read', false))
    expect(nodes[0]).toEqual(step())
  })

  test.each([
    ['the owner', access('owner', true, 'owner')],
    ['a share with Raw data & files', access('read', true)],
    ['break-glass', access('read', true, 'break_glass')],
  ])('%s: the same array, untouched', (_who, a) => {
    const nodes = [step(), finding()]
    expect(stripStepContent(nodes, a)).toBe(nodes)
    expect(readsStepContent(a)).toBe(true)
  })

  test.each([
    ['oversight', access('read', false, 'oversight')],
    ['no decided access', null],
    ['an unknown kind of access', access('reader', true)],
  ])('%s: stripped (fails closed)', (_who, a) => {
    const out = stripStepContent([step()], a)
    expect(out[0].properties).not.toHaveProperty('thought')
    expect(readsStepContent(a)).toBe(false)
  })
})
