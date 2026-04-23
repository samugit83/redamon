/**
 * Pure state reducers for Fireteam events.
 *
 * Each handler accepts the current chatItems list and a WS payload, and
 * returns an updated chatItems list. They never throw — orphaned events
 * (e.g. a member_completed arriving after its fireteam was already closed)
 * log a warning and return the list unchanged.
 */

import type {
  FireteamDeployedPayload,
  FireteamMemberStartedPayload,
  FireteamThinkingPayload,
  FireteamToolStartPayload,
  FireteamToolOutputChunkPayload,
  FireteamToolCompletePayload,
  FireteamPlanStartPayload,
  FireteamPlanCompletePayload,
  FireteamMemberCompletedPayload,
  FireteamCompletedPayload,
  FireteamMemberStatus,
} from '@/lib/websocket-types'
import type { ChatItem, FireteamItem, FireteamMemberPanel } from '../types'
import type { ToolExecutionItem, PlanWaveItem } from '../AgentTimeline'

function findOpenFireteamIndex(items: ChatItem[], fireteam_id: string): number {
  for (let i = items.length - 1; i >= 0; i--) {
    const it = items[i]
    if (it.type === 'fireteam' && it.fireteam_id === fireteam_id) return i
  }
  return -1
}

// Monotonic counter to guarantee unique ids across tool events that fire in
// the same millisecond — e.g. a plan wave of 3 `execute_ffuf` calls kicks
// FIRETEAM_TOOL_START events so close together that Date.now() collides and
// React emits "two children with the same key" warnings.
let _toolEventCounter = 0
function _nextToolEventSeq(): number {
  _toolEventCounter = (_toolEventCounter + 1) % Number.MAX_SAFE_INTEGER
  return _toolEventCounter
}

function withFireteam(
  items: ChatItem[],
  idx: number,
  updater: (ft: FireteamItem) => FireteamItem,
): ChatItem[] {
  const ft = items[idx] as FireteamItem
  const next = updater(ft)
  return [...items.slice(0, idx), next, ...items.slice(idx + 1)]
}

function updateMember(
  fireteam: FireteamItem,
  member_id: string,
  updater: (m: FireteamMemberPanel) => FireteamMemberPanel,
): FireteamItem {
  const idx = fireteam.members.findIndex(m => m.member_id === member_id)
  if (idx < 0) {
    console.warn(`[fireteam] unknown member_id=${member_id} in fireteam=${fireteam.fireteam_id}`)
    return fireteam
  }
  const member = updater(fireteam.members[idx])
  return {
    ...fireteam,
    members: [
      ...fireteam.members.slice(0, idx),
      member,
      ...fireteam.members.slice(idx + 1),
    ],
  }
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

export function handleFireteamDeployed(
  items: ChatItem[],
  p: FireteamDeployedPayload,
): ChatItem[] {
  const now = new Date()
  const ft: FireteamItem = {
    type: 'fireteam',
    id: p.fireteam_id,
    fireteam_id: p.fireteam_id,
    iteration: p.iteration,
    plan_rationale: p.plan_rationale,
    timestamp: now,
    started_at: now,
    status: 'running',
    members: p.members.map(m => ({
      member_id: m.member_id,
      name: m.name,
      task: m.task,
      skills: m.skills ?? [],
      status: 'running' as FireteamMemberStatus,
      started_at: now,
      tools: [],
      planWaves: [],
      iterations_used: 0,
      tokens_used: 0,
      input_tokens_used: 0,
      output_tokens_used: 0,
      findings_count: 0,
      max_iterations: m.max_iterations,
    })),
  }
  return [...items, ft]
}

export function handleFireteamMemberStarted(
  items: ChatItem[],
  p: FireteamMemberStartedPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) {
    console.warn(`[fireteam] member_started for unknown fireteam=${p.fireteam_id}`)
    return items
  }
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => ({
      ...m,
      status: 'running',
      started_at: new Date(),
    })),
  )
}

export function handleFireteamThinking(
  items: ChatItem[],
  p: FireteamThinkingPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  // Store the most recent thought; truncate to keep UI compact. Also track
  // the live iteration number so the member card can show "iter 3" while
  // it's still running (iterations_used only lands at member_completed).
  const snippet = (p.thought || p.reasoning || '').slice(0, 240)
  const inDelta = Math.max(0, Number(p.input_tokens || 0))
  const outDelta = Math.max(0, Number(p.output_tokens || 0))
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => ({
      ...m,
      latest_thought: snippet,
      latest_iteration: p.iteration,
      input_tokens_used: (m.input_tokens_used ?? 0) + inDelta,
      output_tokens_used: (m.output_tokens_used ?? 0) + outDelta,
      tokens_used: (m.tokens_used ?? 0) + inDelta + outDelta,
    })),
  )
}

export function handleFireteamToolStart(
  items: ChatItem[],
  p: FireteamToolStartPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) {
    console.warn(`[fireteam] tool_start for unknown fireteam=${p.fireteam_id}`)
    return items
  }
  const toolItem: ToolExecutionItem = {
    type: 'tool_execution',
    id: `ft-${p.fireteam_id}-${p.member_id}-${p.tool_name}-${Date.now()}-${_nextToolEventSeq()}`,
    timestamp: new Date(),
    tool_name: p.tool_name,
    tool_args: p.tool_args ?? {},
    status: 'running',
    output_chunks: [],
    step_index: p.step_index ?? undefined,
  }
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => {
      // If the tool is part of a nested plan wave, append to that wave;
      // otherwise treat as a standalone member-level tool.
      if (p.wave_id && m.planWaves.length > 0) {
        const wi = m.planWaves.findIndex(w => w.wave_id === p.wave_id)
        if (wi >= 0) {
          const updatedWave: PlanWaveItem = {
            ...m.planWaves[wi],
            tools: [...m.planWaves[wi].tools, toolItem],
          }
          return {
            ...m,
            planWaves: [
              ...m.planWaves.slice(0, wi),
              updatedWave,
              ...m.planWaves.slice(wi + 1),
            ],
          }
        }
      }
      return { ...m, tools: [...m.tools, toolItem] }
    }),
  )
}

export function handleFireteamToolOutputChunk(
  items: ChatItem[],
  p: FireteamToolOutputChunkPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => {
      // Append to the last running tool with matching name, checking both
      // top-level tools and nested plan waves.
      const appendChunk = (t: ToolExecutionItem): ToolExecutionItem => ({
        ...t,
        output_chunks: [...t.output_chunks, p.chunk],
      })
      for (let ti = m.tools.length - 1; ti >= 0; ti--) {
        if (m.tools[ti].tool_name === p.tool_name && m.tools[ti].status === 'running') {
          return {
            ...m,
            tools: [
              ...m.tools.slice(0, ti),
              appendChunk(m.tools[ti]),
              ...m.tools.slice(ti + 1),
            ],
          }
        }
      }
      for (let wi = m.planWaves.length - 1; wi >= 0; wi--) {
        const wave = m.planWaves[wi]
        for (let ti = wave.tools.length - 1; ti >= 0; ti--) {
          if (wave.tools[ti].tool_name === p.tool_name && wave.tools[ti].status === 'running') {
            const updatedWave: PlanWaveItem = {
              ...wave,
              tools: [
                ...wave.tools.slice(0, ti),
                appendChunk(wave.tools[ti]),
                ...wave.tools.slice(ti + 1),
              ],
            }
            return {
              ...m,
              planWaves: [
                ...m.planWaves.slice(0, wi),
                updatedWave,
                ...m.planWaves.slice(wi + 1),
              ],
            }
          }
        }
      }
      return m
    }),
  )
}

export function handleFireteamToolComplete(
  items: ChatItem[],
  p: FireteamToolCompletePayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => {
      const patch = (t: ToolExecutionItem): ToolExecutionItem => {
        // Prefer the backend-reported duration_ms when it's a real positive
        // number. When the backend hasn't timed the tool (some code paths
        // still default to 0 / undefined), fall back to the client-side
        // elapsed between tool_start's `t.timestamp` and now. Without this
        // fallback completed tool cards rendered "0s" even though the UI
        // showed a climbing timer while running.
        const backendMs = typeof p.duration_ms === 'number' && p.duration_ms > 0
          ? p.duration_ms
          : undefined
        const fallbackMs = Math.max(0, Date.now() - t.timestamp.getTime())
        return {
          ...t,
          status: p.success ? 'success' : 'error',
          duration: backendMs ?? fallbackMs,
          final_output: p.output_excerpt,
        }
      }

      // If the backend told us which wave this tool belongs to, route the
      // complete event there first. Fixes a tool-name-collision bug where
      // an iter-1 standalone playwright that was already running made the
      // reducer mispatch an iter-2 plan-wave playwright completion to the
      // wrong slot, leaving the plan-wave tool stuck in 'running'.
      if (p.wave_id) {
        for (let wi = m.planWaves.length - 1; wi >= 0; wi--) {
          const wave = m.planWaves[wi]
          if (wave.wave_id !== p.wave_id) continue
          // Prefer step_index match if available, otherwise last running match by name.
          let ti = -1
          if (p.step_index != null) {
            ti = wave.tools.findIndex(
              t => t.step_index === p.step_index && t.status === 'running',
            )
          }
          if (ti < 0) {
            const r = [...wave.tools].reverse().findIndex(
              t => t.tool_name === p.tool_name && t.status === 'running',
            )
            if (r >= 0) ti = wave.tools.length - 1 - r
          }
          if (ti >= 0) {
            const nextTools = wave.tools.slice()
            nextTools[ti] = patch(nextTools[ti])
            const nextWaves = m.planWaves.slice()
            nextWaves[wi] = { ...wave, tools: nextTools }
            return { ...m, planWaves: nextWaves }
          }
        }
        // wave_id given but not found; fall through to generic matching as a
        // last resort so we don't silently drop the event.
      }

      // Standalone (or wave_id absent): patch the most recent top-level
      // running tool with matching name.
      const reverseIdx = [...m.tools].reverse().findIndex(
        t => t.tool_name === p.tool_name && t.status === 'running',
      )
      if (reverseIdx >= 0) {
        const ti = m.tools.length - 1 - reverseIdx
        const nextTools = m.tools.slice()
        nextTools[ti] = patch(nextTools[ti])
        return { ...m, tools: nextTools }
      }
      // Final fallback: any running tool with that name in any wave.
      for (let wi = m.planWaves.length - 1; wi >= 0; wi--) {
        const wave = m.planWaves[wi]
        const r = [...wave.tools].reverse().findIndex(
          t => t.tool_name === p.tool_name && t.status === 'running',
        )
        if (r >= 0) {
          const ti = wave.tools.length - 1 - r
          const nextTools = wave.tools.slice()
          nextTools[ti] = patch(nextTools[ti])
          const nextWaves = m.planWaves.slice()
          nextWaves[wi] = { ...wave, tools: nextTools }
          return { ...m, planWaves: nextWaves }
        }
      }
      return m
    }),
  )
}

export function handleFireteamPlanStart(
  items: ChatItem[],
  p: FireteamPlanStartPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  const plan: PlanWaveItem = {
    type: 'plan_wave',
    id: `ft-${p.fireteam_id}-${p.member_id}-${p.wave_id}`,
    timestamp: new Date(),
    wave_id: p.wave_id,
    plan_rationale: p.plan_rationale,
    tool_count: p.tools.length,
    tools: [],
    status: 'running',
  }
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => ({
      ...m,
      planWaves: [...m.planWaves, plan],
    })),
  )
}

export function handleFireteamPlanComplete(
  items: ChatItem[],
  p: FireteamPlanCompletePayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => {
      const wi = m.planWaves.findIndex(w => w.wave_id === p.wave_id)
      if (wi < 0) return m
      const status: PlanWaveItem['status'] =
        p.failed === 0 ? 'success' : p.successful === 0 ? 'error' : 'partial'
      const updated: PlanWaveItem = { ...m.planWaves[wi], status }
      return {
        ...m,
        planWaves: [
          ...m.planWaves.slice(0, wi),
          updated,
          ...m.planWaves.slice(wi + 1),
        ],
      }
    }),
  )
}

export function handleFireteamMemberCompleted(
  items: ChatItem[],
  p: FireteamMemberCompletedPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  return withFireteam(items, idx, ft =>
    updateMember(ft, p.member_id, m => {
      const authIn = Math.max(0, Number(p.input_tokens_used ?? 0))
      const authOut = Math.max(0, Number(p.output_tokens_used ?? 0))
      const authTotal = Math.max(0, Number(p.tokens_used ?? 0))
      // Prefer the authoritative backend totals if non-zero; fall back to the
      // per-turn accumulation we maintained via FIRETEAM_THINKING events.
      const finalIn = authIn > 0 ? authIn : (m.input_tokens_used ?? 0)
      const finalOut = authOut > 0 ? authOut : (m.output_tokens_used ?? 0)
      const finalTotal =
        authTotal > 0 ? authTotal : finalIn + finalOut || (m.tokens_used ?? 0)
      return {
        ...m,
        status: p.status,
        completed_at: new Date(),
        iterations_used: p.iterations_used,
        tokens_used: finalTotal,
        input_tokens_used: finalIn,
        output_tokens_used: finalOut,
        findings_count: p.findings_count,
        completion_reason: undefined,
        error_message: p.error_message ?? undefined,
      }
    }),
  )
}

export function handleFireteamCompleted(
  items: ChatItem[],
  p: FireteamCompletedPayload,
): ChatItem[] {
  const idx = findOpenFireteamIndex(items, p.fireteam_id)
  if (idx < 0) return items
  return withFireteam(items, idx, ft => {
    const counts = p.status_counts ?? {}
    // Determine overall status: any timeout -> timeout, any error-only -> failed, else completed
    const timeoutN = counts.timeout ?? 0
    const successN = counts.success ?? 0
    const errorN = counts.error ?? 0
    const cancelledN = counts.cancelled ?? 0
    let status: FireteamItem['status'] = 'completed'
    if (cancelledN > 0 && successN === 0) status = 'cancelled'
    else if (timeoutN > 0) status = 'timeout'
    else if (errorN === p.total) status = 'failed'

    // Cascade a terminal status down to any members / tools / plan waves
    // that were still showing `running`. On cancel/timeout the backend
    // kills member tasks mid-tool and never emits per-member tool_complete
    // or member_completed for them — so without this cascade the UI shows
    // a cancelled fireteam header with members and tools still spinning.
    const cascadeMemberStatus: FireteamMemberPanel['status'] =
      status === 'cancelled' ? 'cancelled'
      : status === 'timeout' ? 'timeout'
      : status === 'failed' ? 'error'
      : 'success'
    const cascadeLeafStatus: 'error' | 'success' =
      status === 'completed' ? 'success' : 'error'
    const cascadeLabel =
      status === 'cancelled' ? 'Cancelled by operator'
      : status === 'timeout' ? 'Wave timeout'
      : status === 'failed' ? 'Wave failed'
      : null

    const cascadedMembers = ft.members.map(m => {
      const flipTool = (t: ToolExecutionItem): ToolExecutionItem =>
        t.status === 'running' || t.status === 'pending_approval'
          ? {
              ...t,
              status: cascadeLeafStatus,
              final_output: t.final_output ?? cascadeLabel ?? undefined,
              duration: t.duration ?? Math.max(0, Date.now() - t.timestamp.getTime()),
            }
          : t
      const nextTools = m.tools.map(flipTool)
      const nextWaves = m.planWaves.map(w => {
        if (w.status !== 'running' && w.status !== 'pending_approval') return w
        const tools = w.tools.map(flipTool)
        const wStatus: PlanWaveItem['status'] =
          cascadeLeafStatus === 'success' ? 'success' : 'error'
        return {
          ...w,
          tools,
          status: wStatus,
          interpretation: w.interpretation ?? cascadeLabel ?? undefined,
        }
      })
      const memberStillRunning = m.status === 'running' || m.status === 'needs_confirmation'
      return {
        ...m,
        tools: nextTools,
        planWaves: nextWaves,
        status: memberStillRunning ? cascadeMemberStatus : m.status,
        completed_at: m.completed_at ?? new Date(),
        completion_reason: m.completion_reason ?? cascadeLabel ?? undefined,
      }
    })

    return {
      ...ft,
      members: cascadedMembers,
      status,
      completed_at: new Date(),
      status_counts: counts,
      wall_clock_seconds: p.wall_clock_seconds,
    }
  })
}
