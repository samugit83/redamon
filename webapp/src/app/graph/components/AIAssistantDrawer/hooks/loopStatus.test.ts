/**
 * What the drawer shows for each Agent in the Loop status (master plan T6, T19, T21).
 */
import { describe, test, expect } from 'vitest'
import type { LoopStatusPayload } from '@/lib/websocket-types'
import {
  LOOP_ACT_AS, LOOP_FIRST_USE, LOOP_RESUME_HINT, answeredViaLine, loopDisplay, loopEndsAt, stampLoopStatus,
} from './loopStatus'

const base = (over: Partial<LoopStatusPayload> = {}): LoopStatusPayload => ({
  state: 'thinking', detail: {}, driver: { connected: true, lastSeenSeconds: 3 },
  openSteps: 0, sinceSeconds: 1, ...over,
})
const openStep = { stepId: 'a'.repeat(32), state: 'open', purpose: 'think', iteration: 4 }

describe('loopDisplay', () => {
  test('no status: nothing, no chip', () => {
    expect(loopDisplay(null)).toEqual({ statusWord: null, chip: false, unattended: false, notices: [] })
  })

  test('an open step with a connected driver: waiting, no notice', () => {
    const d = loopDisplay(base({ step: openStep, openSteps: 1 }))
    expect(d).toEqual({ statusWord: 'Waiting for your agent…', chip: true, unattended: false, notices: [] })
  })

  test('an open step with no driver: the first-use notice with links, then back once it connects', () => {
    const off = loopDisplay(base({ step: openStep, driver: { connected: false, lastSeenSeconds: null } }))
    expect(off.statusWord).toBe('Waiting for your agent…')
    expect(off.notices).toEqual([{ tone: 'info', text: LOOP_FIRST_USE, links: true }])
    const on = loopDisplay(base({ step: openStep, driver: { connected: true, lastSeenSeconds: 1 } }))
    expect(on.notices).toEqual([])
  })

  test('an agent that served the chat and went quiet: a warning with the clock time the run ends', () => {
    const receivedAtMs = Date.UTC(2026, 10, 7, 12, 0, 0)
    const status = stampLoopStatus(base({
      step: openStep, driver: { connected: false, lastSeenSeconds: 91 }, noDriverEndsInSeconds: 1709,
    }), receivedAtMs)!
    const clock = new Date(receivedAtMs + 1709 * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const d = loopDisplay(status)
    expect(d.statusWord).toBe('Waiting for your agent…')
    expect(d.notices).toEqual([{
      tone: 'warning',
      text: `Your agent stopped responding. Unless it calls RedAmon again, this run ends at ${clock}.`,
    }])
  })

  test('a quiet agent with no countdown from an older agent still warns', () => {
    const d = loopDisplay(base({ step: openStep, driver: { connected: false, lastSeenSeconds: 200 } }))
    expect(d.notices.map(n => n.text))
      .toEqual(['Your agent stopped responding. Unless it calls RedAmon again, this run ends soon.'])
  })

  test('no agent yet: the first-use notice, then when the run ends', () => {
    const status = stampLoopStatus(base({
      step: openStep, driver: { connected: false, lastSeenSeconds: null }, noDriverEndsInSeconds: 1800,
    }), 0)!
    const d = loopDisplay(status)
    expect(d.notices[0]).toEqual({ tone: 'info', text: LOOP_FIRST_USE, links: true })
    expect(d.notices[1]).toEqual({ tone: 'info', text: `Unless an agent connects, this run ends ${loopEndsAt(status)}.` })
  })

  test('loopEndsAt: a clock time once stamped, minutes without, nothing without a countdown', () => {
    expect(loopEndsAt(base({ noDriverEndsInSeconds: 1500 }))).toBe('in about 25 min')
    expect(loopEndsAt(base({ noDriverEndsInSeconds: 10 }))).toBe('in about 1 min')
    expect(loopEndsAt(stampLoopStatus(base({ noDriverEndsInSeconds: 60 }), 0)!)).toMatch(/^at \S/)
    expect(loopEndsAt(base())).toBeNull()
    expect(loopEndsAt(base({ noDriverEndsInSeconds: -1 }))).toBeNull()
  })

  test('stampLoopStatus keeps the frame and adds when it arrived; null stays null', () => {
    const frame = base({ step: openStep })
    expect(stampLoopStatus(frame, 42)).toEqual({ ...frame, receivedAtMs: 42 })
    expect(stampLoopStatus(null, 42)).toBeNull()
    expect(stampLoopStatus(undefined, 42)).toBeNull()
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
      .toEqual({ statusWord: null, chip: true, unattended: false, notices: [] })
  })

  test.each([
    ['loop_step_declined', { reason: 'out of scope host' }, 'Your agent declined this step: out of scope host'],
    ['loop_step_declined', {}, 'Your agent declined this step.'],
    ['loop_step_not_answered', {}, `Your agent did not answer in time, so the run ended. ${LOOP_RESUME_HINT}`],
    ['loop_no_driver', {}, `No agent called RedAmon in time, so the run ended. ${LOOP_RESUME_HINT}`],
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

  test('tool confirmation off marks the run unattended, in every state', () => {
    for (const state of ['thinking', 'running_tool', 'awaiting_human', 'error', 'finished', 'stopped']) {
      expect(loopDisplay(base({ state, toolConfirmation: false })).unattended).toBe(true)
      expect(loopDisplay(base({ state, toolConfirmation: true })).unattended).toBe(false)
    }
  })

  test('an agent that does not send toolConfirmation is not marked', () => {
    expect(loopDisplay(base({ step: openStep })).unattended).toBe(false)
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
