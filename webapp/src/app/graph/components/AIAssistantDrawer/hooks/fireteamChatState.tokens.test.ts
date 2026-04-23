/**
 * Unit tests for token accumulation in the Fireteam reducer.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/hooks/fireteamChatState.tokens.test.ts
 *
 * Covers the invariants that make the per-member "in X · out Y" header
 * and the cumulative session counter accurate:
 *   - handleFireteamDeployed initializes input/output counters to 0
 *   - handleFireteamThinking ADDS per-turn deltas onto the member state
 *   - handleFireteamMemberCompleted prefers the backend-authoritative
 *     split totals, falling back to the accumulated values if absent
 */

import { describe, test, expect } from 'vitest'
import {
  handleFireteamDeployed,
  handleFireteamThinking,
  handleFireteamMemberCompleted,
} from './fireteamChatState'
import type { ChatItem, FireteamItem } from '../types'
import type {
  FireteamDeployedPayload,
  FireteamThinkingPayload,
  FireteamMemberCompletedPayload,
} from '@/lib/websocket-types'

function deployPayload(): FireteamDeployedPayload {
  return {
    fireteam_id: 'fteam-1',
    iteration: 1,
    plan_rationale: 'r',
    member_count: 2,
    members: [
      { member_id: 'm-1', name: 'Web',  task: 't1', skills: [], max_iterations: 20 },
      { member_id: 'm-2', name: 'Auth', task: 't2', skills: [], max_iterations: 20 },
    ],
  }
}

function getMember(items: ChatItem[], mid: string) {
  const ft = items.find(i => i.type === 'fireteam') as FireteamItem
  const member = ft.members.find(m => m.member_id === mid)!
  return { ft, member }
}

describe('handleFireteamDeployed', () => {
  test('seeds per-member token counters to 0', () => {
    const items = handleFireteamDeployed([], deployPayload())
    const { member } = getMember(items, 'm-1')
    expect(member.tokens_used).toBe(0)
    expect(member.input_tokens_used).toBe(0)
    expect(member.output_tokens_used).toBe(0)
  })
})

describe('handleFireteamThinking', () => {
  const base = handleFireteamDeployed([], deployPayload())

  function thinkingEvt(mid: string, inTok: number, outTok: number, iter = 1): FireteamThinkingPayload {
    return {
      fireteam_id: 'fteam-1',
      member_id: mid,
      name: 'x',
      iteration: iter,
      phase: 'informational',
      thought: 't', reasoning: 'r',
      input_tokens: inTok,
      output_tokens: outTok,
    }
  }

  test('accumulates deltas on the target member only', () => {
    const after = handleFireteamThinking(base, thinkingEvt('m-1', 4200, 150))
    const { member: m1 } = getMember(after, 'm-1')
    const { member: m2 } = getMember(after, 'm-2')
    expect(m1.input_tokens_used).toBe(4200)
    expect(m1.output_tokens_used).toBe(150)
    expect(m1.tokens_used).toBe(4350)
    expect(m2.input_tokens_used).toBe(0)
    expect(m2.output_tokens_used).toBe(0)
  })

  test('sums across multiple thinking events on the same member', () => {
    let items = base
    items = handleFireteamThinking(items, thinkingEvt('m-1', 1000, 40, 1))
    items = handleFireteamThinking(items, thinkingEvt('m-1', 1100, 55, 2))
    items = handleFireteamThinking(items, thinkingEvt('m-1', 900,  30, 3))
    const { member } = getMember(items, 'm-1')
    expect(member.input_tokens_used).toBe(3000)
    expect(member.output_tokens_used).toBe(125)
    expect(member.tokens_used).toBe(3125)
    expect(member.latest_iteration).toBe(3)
  })

  test('missing token fields on payload leave counters unchanged', () => {
    const after = handleFireteamThinking(base, {
      fireteam_id: 'fteam-1', member_id: 'm-1', name: 'x',
      iteration: 1, phase: 'informational', thought: 't', reasoning: 'r',
    } as FireteamThinkingPayload)
    const { member } = getMember(after, 'm-1')
    expect(member.input_tokens_used).toBe(0)
    expect(member.output_tokens_used).toBe(0)
    // But latest_iteration still updates so the sub-step counter works.
    expect(member.latest_iteration).toBe(1)
  })

  test('negative payload values are clamped to 0', () => {
    const after = handleFireteamThinking(base, thinkingEvt('m-1', -5, -10))
    const { member } = getMember(after, 'm-1')
    expect(member.input_tokens_used).toBe(0)
    expect(member.output_tokens_used).toBe(0)
  })

  test('ignores unknown fireteam id', () => {
    const after = handleFireteamThinking(base, {
      ...thinkingEvt('m-1', 100, 10),
      fireteam_id: 'fteam-unknown',
    })
    // Base state unchanged.
    const { member } = getMember(after, 'm-1')
    expect(member.input_tokens_used).toBe(0)
  })
})

describe('handleFireteamMemberCompleted', () => {
  function completedEvt(overrides: Partial<FireteamMemberCompletedPayload> = {}): FireteamMemberCompletedPayload {
    return {
      fireteam_id: 'fteam-1',
      member_id: 'm-1',
      name: 'Web',
      status: 'success',
      iterations_used: 3,
      tokens_used: 0,
      findings_count: 1,
      wall_clock_seconds: 1.2,
      ...overrides,
    }
  }

  test('backend authoritative split tokens override accumulated totals', () => {
    let items = handleFireteamDeployed([], deployPayload())
    // Simulate one streamed thinking that under-counted.
    items = handleFireteamThinking(items, {
      fireteam_id: 'fteam-1', member_id: 'm-1', name: 'x',
      iteration: 1, phase: 'informational', thought: 't', reasoning: 'r',
      input_tokens: 500, output_tokens: 20,
    })
    // Member completes with authoritative totals that differ.
    items = handleFireteamMemberCompleted(items, completedEvt({
      tokens_used: 5100,
      input_tokens_used: 5000,
      output_tokens_used: 100,
    }))
    const { member } = getMember(items, 'm-1')
    expect(member.input_tokens_used).toBe(5000)
    expect(member.output_tokens_used).toBe(100)
    expect(member.tokens_used).toBe(5100)
    expect(member.status).toBe('success')
  })

  test('falls back to accumulated thinking deltas when backend reports 0/undefined', () => {
    let items = handleFireteamDeployed([], deployPayload())
    items = handleFireteamThinking(items, {
      fireteam_id: 'fteam-1', member_id: 'm-1', name: 'x',
      iteration: 1, phase: 'informational', thought: 't', reasoning: 'r',
      input_tokens: 1234, output_tokens: 56,
    })
    items = handleFireteamMemberCompleted(items, completedEvt({
      tokens_used: 0,  // stale/legacy backend
      // input_tokens_used / output_tokens_used intentionally omitted
    }))
    const { member } = getMember(items, 'm-1')
    expect(member.input_tokens_used).toBe(1234)
    expect(member.output_tokens_used).toBe(56)
    expect(member.tokens_used).toBe(1290)
  })

  test('leaves siblings unaffected on completion', () => {
    let items = handleFireteamDeployed([], deployPayload())
    items = handleFireteamThinking(items, {
      fireteam_id: 'fteam-1', member_id: 'm-2', name: 'x',
      iteration: 1, phase: 'informational', thought: 't', reasoning: 'r',
      input_tokens: 999, output_tokens: 42,
    })
    items = handleFireteamMemberCompleted(items, completedEvt({
      member_id: 'm-1',
      tokens_used: 100, input_tokens_used: 90, output_tokens_used: 10,
    }))
    const { member: m2 } = getMember(items, 'm-2')
    expect(m2.input_tokens_used).toBe(999)
    expect(m2.output_tokens_used).toBe(42)
    expect(m2.status).toBe('running')
  })
})
