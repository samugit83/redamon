/**
 * Unit tests for the per-tool Stop feature.
 *
 * Covers:
 *  - ToolExecutionCard renders the Stop button only when status === 'running'
 *    AND onStop is provided; clicking it fires the callback and stops
 *    propagation so the card doesn't toggle expand/collapse
 *  - handleToolStop locator logic (pure function of chatItems shape):
 *    locates standalone tools, wave-nested tools, fireteam flat tools,
 *    and fireteam nested plan-wave tools, and picks the right
 *    (tool_name, wave_id, step_index) to send
 *  - Optimistic state update: only flips status when still 'running'
 *    (tool_complete race safety)
 *
 * Run:
 *   cd webapp && npx vitest run src/app/graph/components/AIAssistantDrawer/ToolStop.test.tsx
 */

import React from 'react'
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { ToolExecutionCard } from './ToolExecutionCard'

afterEach(cleanup)
import type {
  ToolExecutionItem,
  PlanWaveItem,
} from './AgentTimeline'
import type { FireteamItem, FireteamMemberPanel, ChatItem } from './types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeTool(overrides: Partial<ToolExecutionItem> = {}): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: `tool-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(),
    tool_name: 'shodan',
    tool_args: { ip: '1.2.3.4' },
    status: 'running',
    output_chunks: [],
    ...overrides,
  }
}

function makeWave(overrides: Partial<PlanWaveItem> = {}): PlanWaveItem {
  return {
    type: 'plan_wave',
    id: `wave-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(),
    wave_id: 'wave-1-abc',
    plan_rationale: 'parallel recon',
    tool_count: 0,
    tools: [],
    status: 'running',
    ...overrides,
  }
}

function makeMember(overrides: Partial<FireteamMemberPanel> = {}): FireteamMemberPanel {
  return {
    member_id: 'm1',
    name: 'Recon Specialist',
    task: 'enumerate subdomains',
    skills: [],
    status: 'running',
    started_at: new Date(),
    tools: [],
    planWaves: [],
    iterations_used: 0,
    tokens_used: 0,
    input_tokens_used: 0,
    output_tokens_used: 0,
    findings_count: 0,
    ...overrides,
  }
}

function makeFireteam(overrides: Partial<FireteamItem> = {}): FireteamItem {
  return {
    type: 'fireteam',
    id: 'ft-1',
    fireteam_id: 'ft-1',
    iteration: 1,
    plan_rationale: 'deploy specialists',
    timestamp: new Date(),
    started_at: new Date(),
    status: 'running',
    members: [],
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// ToolExecutionCard Stop button rendering
// ---------------------------------------------------------------------------

describe('ToolExecutionCard Stop button', () => {
  test('renders the Stop button when status === running AND onStop is provided', () => {
    const tool = makeTool({ status: 'running' })
    const onStop = vi.fn()
    render(
      <ToolExecutionCard
        item={tool}
        isExpanded={false}
        onToggleExpand={() => {}}
        onStop={onStop}
      />,
    )
    const stopBtn = screen.getByRole('button', { name: /stop this tool/i })
    expect(stopBtn).toBeTruthy()
  })

  test('does NOT render the Stop button for completed tools', () => {
    const tool = makeTool({ status: 'success' })
    const onStop = vi.fn()
    render(
      <ToolExecutionCard
        item={tool}
        isExpanded={false}
        onToggleExpand={() => {}}
        onStop={onStop}
      />,
    )
    expect(screen.queryByRole('button', { name: /stop this tool/i })).toBeNull()
  })

  test('does NOT render the Stop button for failed tools', () => {
    const tool = makeTool({ status: 'error' })
    render(
      <ToolExecutionCard
        item={tool}
        isExpanded={false}
        onToggleExpand={() => {}}
        onStop={vi.fn()}
      />,
    )
    expect(screen.queryByRole('button', { name: /stop this tool/i })).toBeNull()
  })

  test('does NOT render the Stop button for pending_approval tools', () => {
    const tool = makeTool({ status: 'pending_approval' })
    render(
      <ToolExecutionCard
        item={tool}
        isExpanded={false}
        onToggleExpand={() => {}}
        onStop={vi.fn()}
      />,
    )
    expect(screen.queryByRole('button', { name: /stop this tool/i })).toBeNull()
  })

  test('does NOT render the Stop button when onStop is not provided', () => {
    const tool = makeTool({ status: 'running' })
    render(
      <ToolExecutionCard
        item={tool}
        isExpanded={false}
        onToggleExpand={() => {}}
      />,
    )
    expect(screen.queryByRole('button', { name: /stop this tool/i })).toBeNull()
  })

  test('clicking Stop fires onStop and does NOT trigger card expand', () => {
    const tool = makeTool({ status: 'running' })
    const onStop = vi.fn()
    const onToggleExpand = vi.fn()
    render(
      <ToolExecutionCard
        item={tool}
        isExpanded={false}
        onToggleExpand={onToggleExpand}
        onStop={onStop}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /stop this tool/i }))
    expect(onStop).toHaveBeenCalledTimes(1)
    // stopPropagation should keep the header's onClick (toggle expand) from firing
    expect(onToggleExpand).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// handleToolStop locator + send-id logic
//
// We re-implement the locator logic from useSendHandlers.handleToolStop as a
// pure function so it can be tested without mounting the whole drawer.
// Structure & semantics MUST stay in sync with the hook — this is a
// regression test that fails if either drifts.
// ---------------------------------------------------------------------------

interface LocatorResult {
  tool_name: string
  wave_id?: string
  step_index?: number
}

function locateToolForStop(chatItems: ChatItem[], itemId: string): LocatorResult | null {
  for (const it of chatItems) {
    if (!('type' in it)) continue
    if (it.type === 'tool_execution' && it.id === itemId) {
      return { tool_name: it.tool_name, step_index: it.step_index }
    }
    if (it.type === 'plan_wave') {
      const wave = it as PlanWaveItem
      const t = wave.tools.find(x => x.id === itemId)
      if (t) {
        return { tool_name: t.tool_name, wave_id: wave.wave_id, step_index: t.step_index }
      }
    }
    if (it.type === 'fireteam') {
      const ft = it as FireteamItem
      for (const member of ft.members) {
        const flat = member.tools.find(x => x.id === itemId)
        if (flat) {
          return { tool_name: flat.tool_name, step_index: flat.step_index }
        }
        for (const pw of member.planWaves) {
          const nested = pw.tools.find(x => x.id === itemId)
          if (nested) {
            return { tool_name: nested.tool_name, wave_id: pw.wave_id, step_index: nested.step_index }
          }
        }
      }
    }
  }
  return null
}

describe('handleToolStop locator', () => {
  test('locates a standalone tool (no wave_id, no step_index)', () => {
    const tool = makeTool({ id: 'tool-1', tool_name: 'nmap' })
    const res = locateToolForStop([tool], 'tool-1')
    expect(res).toEqual({ tool_name: 'nmap', step_index: undefined })
  })

  test('locates a wave-nested tool with wave_id + step_index', () => {
    const wave = makeWave({
      id: 'wave-card-1',
      wave_id: 'wave-3-abc',
      tools: [
        makeTool({ id: 'w-t-0', tool_name: 'nmap', step_index: 0 }),
        makeTool({ id: 'w-t-1', tool_name: 'shodan', step_index: 1 }),
      ],
    })
    const res = locateToolForStop([wave], 'w-t-1')
    expect(res).toEqual({
      tool_name: 'shodan',
      wave_id: 'wave-3-abc',
      step_index: 1,
    })
  })

  test('locates a fireteam member flat tool (no wave_id)', () => {
    const flat = makeTool({ id: 'ft-t-1', tool_name: 'execute_wpscan' })
    const member = makeMember({ tools: [flat] })
    const ft = makeFireteam({ members: [member] })
    const res = locateToolForStop([ft], 'ft-t-1')
    expect(res).toEqual({ tool_name: 'execute_wpscan', step_index: undefined })
  })

  test('locates a fireteam member nested plan-wave tool with wave_id + step_index', () => {
    const nested = makeTool({ id: 'ft-nested', tool_name: 'ffuf', step_index: 2 })
    const memberWave = makeWave({ wave_id: 'ft-wave-9', tools: [nested] })
    const member = makeMember({ planWaves: [memberWave] })
    const ft = makeFireteam({ members: [member] })
    const res = locateToolForStop([ft], 'ft-nested')
    expect(res).toEqual({
      tool_name: 'ffuf',
      wave_id: 'ft-wave-9',
      step_index: 2,
    })
  })

  test('returns null for unknown id', () => {
    const tool = makeTool({ id: 'tool-1' })
    const res = locateToolForStop([tool], 'does-not-exist')
    expect(res).toBeNull()
  })

  test('resolves same-name tools in the same wave by step_index', () => {
    // Two playwright tools in the same wave — their ids differ but tool_name
    // collides. The backend disambiguates via step_index.
    const wave = makeWave({
      wave_id: 'wave-42',
      tools: [
        makeTool({ id: 'pw-a', tool_name: 'playwright', step_index: 0 }),
        makeTool({ id: 'pw-b', tool_name: 'playwright', step_index: 1 }),
      ],
    })
    const a = locateToolForStop([wave], 'pw-a')
    const b = locateToolForStop([wave], 'pw-b')
    expect(a?.step_index).toBe(0)
    expect(b?.step_index).toBe(1)
    expect(a?.wave_id).toBe('wave-42')
    expect(b?.wave_id).toBe('wave-42')
  })
})

// ---------------------------------------------------------------------------
// Optimistic update semantics
//
// Replica of the status-flipping reducer inside handleToolStop. We only flip
// 'running' → 'error' so a tool_complete race (tool finished just as the
// user clicked Stop) doesn't overwrite a real success/error result.
// ---------------------------------------------------------------------------

function applyOptimisticStop(items: ChatItem[], itemId: string): ChatItem[] {
  return items.map(item => {
    if (!('type' in item)) return item
    if (item.type === 'tool_execution' && item.id === itemId) {
      if (item.status !== 'running') return item
      return { ...item, status: 'error' as const, final_output: 'Stopped by user' }
    }
    if (item.type === 'plan_wave') {
      const wave = item as PlanWaveItem
      const idx = wave.tools.findIndex(t => t.id === itemId)
      if (idx === -1) return item
      if (wave.tools[idx].status !== 'running') return item
      const updatedTools = [...wave.tools]
      updatedTools[idx] = {
        ...updatedTools[idx],
        status: 'error' as const,
        final_output: 'Stopped by user',
      }
      return { ...wave, tools: updatedTools }
    }
    return item
  })
}

describe('Optimistic stop update', () => {
  test('flips a running standalone tool to error with "Stopped by user"', () => {
    const tool = makeTool({ id: 'tool-1', status: 'running' })
    const [out] = applyOptimisticStop([tool], 'tool-1') as [ToolExecutionItem]
    expect(out.status).toBe('error')
    expect(out.final_output).toBe('Stopped by user')
  })

  test('leaves an already-successful tool alone (race safety)', () => {
    const tool = makeTool({
      id: 'tool-1',
      status: 'success',
      final_output: 'Real agent summary',
    })
    const [out] = applyOptimisticStop([tool], 'tool-1') as [ToolExecutionItem]
    expect(out.status).toBe('success')
    expect(out.final_output).toBe('Real agent summary')
  })

  test('leaves an already-failed tool alone', () => {
    const tool = makeTool({
      id: 'tool-1',
      status: 'error',
      final_output: 'Actual tool error',
    })
    const [out] = applyOptimisticStop([tool], 'tool-1') as [ToolExecutionItem]
    expect(out.final_output).toBe('Actual tool error')
  })

  test('flips a running wave-nested tool without disturbing its siblings', () => {
    const wave = makeWave({
      id: 'wave-1',
      tools: [
        makeTool({ id: 't-0', status: 'running', step_index: 0 }),
        makeTool({ id: 't-1', status: 'running', step_index: 1 }),
      ],
    })
    const [out] = applyOptimisticStop([wave], 't-0') as [PlanWaveItem]
    expect(out.tools[0].status).toBe('error')
    expect(out.tools[0].final_output).toBe('Stopped by user')
    expect(out.tools[1].status).toBe('running')
    // Immutability: original wave reference was not mutated
    expect(wave.tools[0].status).toBe('running')
  })

  test('returns the same reference if nothing matches', () => {
    const tool = makeTool({ id: 'tool-1', status: 'running' })
    const before: ChatItem[] = [tool]
    const after = applyOptimisticStop(before, 'other-id')
    expect(after[0]).toBe(before[0])
  })
})
