/**
 * What the drawer shows for each Agent in the Loop status (master plan T6, T19, T21).
 */
import { describe, test, expect } from 'vitest'
import type { LoopStatusPayload } from '@/lib/websocket-types'
import { LOOP_ACT_AS, LOOP_FIRST_USE, answeredViaLine, loopDisplay } from './loopStatus'

const base = (over: Partial<LoopStatusPayload> = {}): LoopStatusPayload => ({
  state: 'thinking', detail: {}, driver: { connected: true, lastSeenSeconds: 3 },
  openSteps: 0, sinceSeconds: 1, ...over,
})
const openStep = { stepId: 'a'.repeat(32), state: 'open', purpose: 'think', iteration: 4 }

describe('loopDisplay', () => {
  test('no status: nothing, no chip', () => {
    expect(loopDisplay(null)).toEqual({ statusWord: null, chip: false, notices: [] })
  })

  test('an open step with a connected driver: waiting, no notice', () => {
    const d = loopDisplay(base({ step: openStep, openSteps: 1 }))
    expect(d).toEqual({ statusWord: 'Waiting for your agent…', chip: true, notices: [] })
  })

  test('an open step with no driver: the first-use notice with links, then back once it connects', () => {
    const off = loopDisplay(base({ step: openStep, driver: { connected: false, lastSeenSeconds: null } }))
    expect(off.statusWord).toBe('Waiting for your agent…')
    expect(off.notices).toEqual([{ tone: 'info', text: LOOP_FIRST_USE, links: true }])
    const on = loopDisplay(base({ step: openStep, driver: { connected: true, lastSeenSeconds: 1 } }))
    expect(on.notices).toEqual([])
  })

  test('a claimed step names the purpose and the iteration', () => {
    const d = loopDisplay(base({ step: { ...openStep, state: 'claimed' } }))
    expect(d.statusWord).toBe('Your agent is answering · next action · iteration 4')
    const g = loopDisplay(base({ step: { stepId: 'b'.repeat(32), state: 'claimed', purpose: 'scope_guardrail' } }))
    expect(g.statusWord).toBe('Your agent is answering · scope check')
  })

  test('a running tool with no step', () => {
    expect(loopDisplay(base({ state: 'running_tool', detail: { tool: 'execute_nmap' } })).statusWord)
      .toBe('RedAmon is running execute_nmap')
  })

  test('awaiting a person: nothing new, the approval UI is already on screen', () => {
    expect(loopDisplay(base({ state: 'awaiting_human', detail: { kind: 'approval' } })))
      .toEqual({ statusWord: null, chip: true, notices: [] })
  })

  test.each([
    ['loop_step_declined', { reason: 'out of scope host' }, 'Your agent declined this step: out of scope host'],
    ['loop_step_declined', {}, 'Your agent declined this step.'],
    ['loop_step_not_answered', {}, 'Your agent did not answer in time. The run ended.'],
    ['loop_no_driver', {}, 'No agent answered within 5 minutes. Start your agent and send the message again.'],
  ])('error %s', (code, extra, text) => {
    const d = loopDisplay(base({ state: 'error', detail: { code, ...extra } }))
    expect(d.notices.map(n => n.text)).toEqual([text])
    expect(d.statusWord).toBeNull()
  })

  test('finished or stopped clears the word', () => {
    for (const state of ['finished', 'stopped']) {
      expect(loopDisplay(base({ state, step: openStep })).statusWord).toBeNull()
    }
  })

  test('under act-as the notice says whose agent answers', () => {
    const d = loopDisplay(base({ step: openStep }), { actingAs: true })
    expect(d.notices.map(n => n.text)).toContain(LOOP_ACT_AS)
    expect(loopDisplay(base({ step: openStep })).notices).toEqual([])
  })
})

describe('answeredViaLine', () => {
  test('name and prefix, either alone, or nothing', () => {
    expect(answeredViaLine({ token_prefix: 'rdmn_mcp_ab12cd34', token_name: 'laptop' }))
      .toBe('answered via laptop (rdmn_mcp_ab12cd34…)')
    expect(answeredViaLine({ token_name: 'laptop' })).toBe('answered via laptop')
    expect(answeredViaLine({ token_prefix: 'rdmn_mcp_ab12cd34' })).toBe('answered via rdmn_mcp_ab12cd34…')
    expect(answeredViaLine({})).toBeNull()
    expect(answeredViaLine(null)).toBeNull()
  })
})
