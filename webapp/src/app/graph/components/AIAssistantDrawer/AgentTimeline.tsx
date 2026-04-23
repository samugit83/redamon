/**
 * Agent Timeline Component
 *
 * Beautiful, interactive timeline showing agent's thinking process and tool executions.
 * Inspired by Claude Code's execution timeline UI.
 */

'use client'

import { useState } from 'react'
import styles from './AgentTimeline.module.css'
import { ThinkingCard } from './ThinkingCard'
import { ToolExecutionCard } from './ToolExecutionCard'
import { PlanWaveCard } from './PlanWaveCard'
import { DeepThinkCard } from './DeepThinkCard'
import { FireteamCard } from './FireteamCard'
import type { TodoItem } from '@/lib/websocket-types'

export interface ThinkingItem {
  type: 'thinking'
  id: string
  timestamp: Date
  thought: string
  reasoning: string
  action: string
  tool_name?: string
  tool_args?: Record<string, unknown>
  phase_transition?: Record<string, unknown>
  user_question?: Record<string, unknown>
  updated_todo_list: TodoItem[]
  input_tokens?: number
  output_tokens?: number
}

export interface ToolExecutionItem {
  type: 'tool_execution'
  id: string
  timestamp: Date
  tool_name: string
  tool_args: Record<string, unknown>
  status: 'running' | 'success' | 'error' | 'pending_approval'
  output_chunks: string[]
  final_output?: string
  duration?: number
  actionable_findings?: string[]
  recommended_next_steps?: string[]
  step_index?: number  // Disambiguates same-name tools within a wave
}

export interface PlanWaveItem {
  type: 'plan_wave'
  id: string
  timestamp: Date
  wave_id: string
  plan_rationale: string
  tool_count: number
  tools: ToolExecutionItem[]
  status: 'running' | 'success' | 'partial' | 'error' | 'pending_approval'
  interpretation?: string
  actionable_findings?: string[]
  recommended_next_steps?: string[]
  // Set when this pending-approval wave was created from a fireteam member's
  // escalated tool/plan. On approve, the backend does NOT continue this wave
  // (it redeploys a single-member fireteam instead) — so the UI must drop
  // this stale card rather than wait for plan/tool events that will never
  // arrive. See FIRETEAM.md §7.3.
  isFireteamEscalation?: boolean
}

export interface DeepThinkItem {
  type: 'deep_think'
  id: string
  timestamp: Date
  trigger_reason: string
  analysis: string
  iteration: number
  phase: string
}

// ---------------------------------------------------------------------------
// Fireteam (multi-agent) UI state
// ---------------------------------------------------------------------------

export type FireteamMemberStatus =
  | 'running'
  | 'success'
  | 'partial'
  | 'timeout'
  | 'needs_confirmation'
  | 'cancelled'
  | 'error'

export interface FireteamMemberPanel {
  member_id: string
  name: string
  task: string
  skills: string[]
  status: FireteamMemberStatus
  started_at: Date
  completed_at?: Date
  // Tool events scoped to this member (reuses existing ToolExecutionItem).
  tools: ToolExecutionItem[]
  // Nested plan waves (plan_tools fanned out inside the member).
  planWaves: PlanWaveItem[]
  iterations_used: number
  tokens_used: number
  input_tokens_used: number
  output_tokens_used: number
  findings_count: number
  completion_reason?: string
  error_message?: string
  // Latest thinking snippet from FIRETEAM_THINKING events. Shown as a subtle
  // italic line under the member header so operators know the member is
  // actively reasoning between tool calls.
  latest_thought?: string
  // Live sub-step counter fed by FIRETEAM_THINKING events. `iterations_used`
  // only lands at member_completed, so we use this to show "sub-step 3/25"
  // while the member is still running.
  latest_iteration?: number
  // Max iterations (sub-steps) the member is allowed. Populated from the
  // FireteamMemberInfo payload at fireteam_deployed time.
  max_iterations?: number
}

export interface FireteamItem {
  type: 'fireteam'
  id: string              // equals fireteam_id
  fireteam_id: string
  iteration: number
  plan_rationale: string
  timestamp: Date
  started_at: Date
  completed_at?: Date
  status: 'running' | 'completed' | 'timeout' | 'cancelled' | 'failed'
  members: FireteamMemberPanel[]
  status_counts?: Record<string, number>
  wall_clock_seconds?: number
}

export type TimelineItem =
  | ThinkingItem
  | ToolExecutionItem
  | PlanWaveItem
  | DeepThinkItem
  | FireteamItem

export interface AgentTimelineProps {
  items: TimelineItem[]
  isStreaming: boolean
  onItemExpand?: (itemId: string) => void
  missingApiKeys?: Set<string>
  onAddApiKey?: (toolId: string) => void
  onToolConfirmation?: (itemId: string, decision: 'approve' | 'reject') => void
  toolConfirmationDisabled?: boolean
  /** Cancel a single running tool card. Receives the tool's item.id. */
  onToolStop?: (itemId: string) => void
}

export function AgentTimeline({ items, isStreaming, onItemExpand, missingApiKeys, onAddApiKey, onToolConfirmation, toolConfirmationDisabled, onToolStop }: AgentTimelineProps) {
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set())

  const toggleExpand = (itemId: string) => {
    setExpandedItems(prev => {
      const newSet = new Set(prev)
      if (newSet.has(itemId)) {
        newSet.delete(itemId)
      } else {
        newSet.add(itemId)
      }
      return newSet
    })
    onItemExpand?.(itemId)
  }

  if (items.length === 0) {
    return null
  }

  return (
    <div className={styles.timelineItems}>
      {items.map((item, index) => {
        const isExpanded = expandedItems.has(item.id)
        const isLast = index === items.length - 1
        const isLastAndStreaming = isLast && isStreaming

        return (
          <div
            key={item.id}
            className={`${styles.timelineItemWrapper} ${isLastAndStreaming ? styles.streaming : ''}`}
          >
            {/* Timeline connector line */}
            {!isLast && <div className={styles.timelineConnector} />}

            {/* Render appropriate card based on type */}
            {item.type === 'thinking' ? (
              <ThinkingCard
                item={item}
                isExpanded={isExpanded}
                onToggleExpand={() => toggleExpand(item.id)}
              />
            ) : item.type === 'deep_think' ? (
              <DeepThinkCard
                item={item}
                isExpanded={isExpanded}
                onToggleExpand={() => toggleExpand(item.id)}
              />
            ) : item.type === 'plan_wave' ? (
              <PlanWaveCard
                item={item}
                isExpanded={isExpanded}
                onToggleExpand={() => toggleExpand(item.id)}
                missingApiKeys={missingApiKeys}
                onAddApiKey={onAddApiKey}
                onApprove={item.status === 'pending_approval' ? () => onToolConfirmation?.(item.id, 'approve') : undefined}
                onReject={item.status === 'pending_approval' ? () => onToolConfirmation?.(item.id, 'reject') : undefined}
                confirmationDisabled={toolConfirmationDisabled}
                onToolStop={onToolStop}
              />
            ) : item.type === 'fireteam' ? (
              <FireteamCard
                item={item}
                missingApiKeys={missingApiKeys}
                onAddApiKey={onAddApiKey}
                onToolConfirmation={onToolConfirmation}
                toolConfirmationDisabled={toolConfirmationDisabled}
                onToolStop={onToolStop}
              />
            ) : (
              <ToolExecutionCard
                item={item}
                isExpanded={isExpanded}
                onToggleExpand={() => toggleExpand(item.id)}
                missingApiKey={missingApiKeys?.has(item.tool_name)}
                onAddApiKey={onAddApiKey ? () => onAddApiKey(item.tool_name) : undefined}
                onApprove={item.status === 'pending_approval' ? () => onToolConfirmation?.(item.id, 'approve') : undefined}
                onReject={item.status === 'pending_approval' ? () => onToolConfirmation?.(item.id, 'reject') : undefined}
                confirmationDisabled={toolConfirmationDisabled}
                onStop={onToolStop ? () => onToolStop(item.id) : undefined}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
