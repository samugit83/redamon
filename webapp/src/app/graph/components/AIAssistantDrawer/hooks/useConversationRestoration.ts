import { useState, useCallback, useEffect } from 'react'
import type { Conversation } from '@/hooks/useConversations'
import type { TodoItem } from '@/lib/websocket-types'
import type { ChatItem, Message, FileDownloadItem, Phase } from '../types'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem, FireteamItem } from '../AgentTimeline'
import type { ActiveSkill } from './useSendHandlers'

interface ConversationRestorationDeps {
  // From useConversations
  loadConversation: (id: string) => Promise<any>
  deleteConversation: (id: string) => Promise<void>
  fetchConversations: () => Promise<void>
  // Props
  onSwitchSession?: (sessionId: string) => void
  onRefetchGraph?: () => void
  projectId: string
  userId: string
  // From useChatState
  setChatItems: React.Dispatch<React.SetStateAction<ChatItem[]>>
  setCurrentPhase: (v: Phase) => void
  setAttackPathType: (v: string) => void
  setIterationCount: (v: number) => void
  setIsLoading: (v: boolean) => void
  setIsStopped: (v: boolean) => void
  setTodoList: (v: TodoItem[]) => void
  isRestoringConversation: React.MutableRefObject<boolean>
  shouldAutoScroll: React.MutableRefObject<boolean>
  // From useInteractionState
  setAwaitingApproval: (v: boolean) => void
  setApprovalRequest: (v: any) => void
  setAwaitingQuestion: (v: boolean) => void
  setQuestionRequest: (v: any) => void
  setAwaitingToolConfirmation: (v: boolean) => void
  setToolConfirmationRequest: (v: any) => void
  awaitingApprovalRef: React.MutableRefObject<boolean>
  awaitingQuestionRef: React.MutableRefObject<boolean>
  awaitingToolConfirmationRef: React.MutableRefObject<boolean>
  pendingApprovalToolId: React.MutableRefObject<string | null>
  pendingApprovalWaveId: React.MutableRefObject<string | null>
  // Active skill
  setActiveSkill: (v: ActiveSkill | null) => void
  updateConvMeta: (updates: Record<string, any>) => Promise<void>
  // Main component
  handleNewChat: () => void
}

export function useConversationRestoration(deps: ConversationRestorationDeps) {
  const {
    loadConversation, deleteConversation, fetchConversations,
    onSwitchSession, onRefetchGraph,
    projectId, userId,
    setChatItems, setCurrentPhase, setAttackPathType, setIterationCount,
    setIsLoading, setIsStopped, setTodoList,
    isRestoringConversation, shouldAutoScroll,
    setAwaitingApproval, setApprovalRequest,
    setAwaitingQuestion, setQuestionRequest,
    setAwaitingToolConfirmation, setToolConfirmationRequest,
    awaitingApprovalRef, awaitingQuestionRef, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    setActiveSkill, updateConvMeta,
    handleNewChat,
  } = deps

  const [conversationId, setConversationId] = useState<string | null>(null)
  const [showHistory, setShowHistory] = useState(false)

  // Fetch + auto-refresh conversations when history panel opens
  useEffect(() => {
    if (showHistory && projectId && userId) {
      fetchConversations()
      const interval = setInterval(fetchConversations, 5000)
      return () => clearInterval(interval)
    }
  }, [showHistory, projectId, userId, fetchConversations])

  const handleSelectConversation = useCallback(async (conv: Conversation) => {
    const full = await loadConversation(conv.id)
    if (!full) return

    let lastTodoList: TodoItem[] = []
    let lastApprovalRequest: any = null
    let lastQuestionRequest: any = null
    let lastToolConfirmationRequest: any = null
    let lastRenderedPhase: string = ''
    let lastAttackPathType: string = ''
    let hasWorkAfterApproval = false
    let hasWorkAfterQuestion = false
    let hasWorkAfterToolConfirmation = false

    // --- Proper tool_start ↔ tool_complete pairing ---
    const duplicateStartIds = new Set<string>()
    const duplicateCompleteIds = new Set<string>()
    {
      const recentStarts = new Map<string, number>()
      const recentCompletes = new Map<string, number>()
      for (const msg of full.messages) {
        const d = msg.data as any
        const t = new Date(msg.createdAt).getTime()
        if (msg.type === 'tool_start' && !d?.wave_id) {
          const fp = `${d?.tool_name || ''}::${JSON.stringify(d?.tool_args || {})}`
          const prev = recentStarts.get(fp)
          if (prev && t - prev < 60000) {
            duplicateStartIds.add(msg.id)
          } else {
            recentStarts.set(fp, t)
          }
        }
        if (msg.type === 'tool_complete' && !d?.wave_id) {
          const fp = `${d?.tool_name || ''}::${(d?.raw_output || '').slice(0, 500)}`
          const prev = recentCompletes.get(fp)
          if (prev && t - prev < 60000) {
            duplicateCompleteIds.add(msg.id)
          } else {
            recentCompletes.set(fp, t)
          }
        }
      }
    }

    const standaloneStartsByName = new Map<string, { id: string; createdAt: string }[]>()
    const standaloneCompletesByName = new Map<string, { id: string; createdAt: string }[]>()
    for (const msg of full.messages) {
      const d = msg.data as any
      if (msg.type === 'tool_start' && !d?.wave_id && !duplicateStartIds.has(msg.id)) {
        const name = d?.tool_name || ''
        if (!standaloneStartsByName.has(name)) standaloneStartsByName.set(name, [])
        standaloneStartsByName.get(name)!.push({ id: msg.id, createdAt: msg.createdAt })
      }
      if (msg.type === 'tool_complete' && !d?.wave_id && !duplicateCompleteIds.has(msg.id)) {
        const name = d?.tool_name || ''
        if (!standaloneCompletesByName.has(name)) standaloneCompletesByName.set(name, [])
        standaloneCompletesByName.get(name)!.push({ id: msg.id, createdAt: msg.createdAt })
      }
    }

    const consumedStartIds = new Set<string>()
    const completeToStartTime = new Map<string, Date>()
    for (const [name, completes] of standaloneCompletesByName) {
      const starts = standaloneStartsByName.get(name) || []
      for (let i = 0; i < completes.length && i < starts.length; i++) {
        consumedStartIds.add(starts[i].id)
        completeToStartTime.set(completes[i].id, new Date(starts[i].createdAt))
      }
    }

    const seenThinkingKeys = new Set<string>()
    const seenRunningToolKeys = new Set<string>()

    const restored: ChatItem[] = full.messages.map((msg: { id: string; type: string; data: unknown; createdAt: string }) => {
      const data = msg.data as any

      if (msg.type === 'thinking' || msg.type === 'tool_start' || msg.type === 'tool_complete') {
        if (lastApprovalRequest) hasWorkAfterApproval = true
        if (lastQuestionRequest) hasWorkAfterQuestion = true
        if (lastToolConfirmationRequest) hasWorkAfterToolConfirmation = true
      }

      if (msg.type === 'thinking') {
        const key = (data.thought || '').slice(0, 200)
        if (seenThinkingKeys.has(key)) return null
        seenThinkingKeys.add(key)
      }

      if (msg.type === 'user_message' || msg.type === 'assistant_message') {
        const restoredTier = data.response_tier || (data.task_complete ? 'full_report' : undefined)
        return {
          type: 'message',
          id: msg.id,
          role: msg.type === 'user_message' ? 'user' : 'assistant',
          content: data.content || '',
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
          isGuidance: data.isGuidance || false,
          isReport: restoredTier === 'full_report' || (!data.response_tier && (data.isReport || data.task_complete || false)),
          responseTier: restoredTier,
          error: data.error || null,
        } as Message
      } else if (msg.type === 'thinking') {
        // Drop deploy_fireteam thinks: their rationale is already surfaced
        // on the FireteamCard as plan_rationale, so keeping a standalone
        // ThinkingItem would duplicate the same text on the chat timeline
        // (once before the card, once inside). This was the source of the
        // "two identical thoughts, one at top, one at bottom" confusion on
        // session restore — especially for waves whose fireteam row never
        // persisted (cancelled before the deploy POST landed), which left
        // an orphaned thinking with no card to anchor to.
        if (data.action === 'deploy_fireteam') return null
        return {
          type: 'thinking',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          thought: data.thought || '',
          reasoning: data.reasoning || '',
          action: 'thinking',
          updated_todo_list: [],
          input_tokens: Math.max(0, Number(data.input_tokens || 0)),
          output_tokens: Math.max(0, Number(data.output_tokens || 0)),
        } as ThinkingItem
      } else if (msg.type === 'tool_start') {
        if (data.wave_id) return null
        if (duplicateStartIds.has(msg.id)) return null
        if (consumedStartIds.has(msg.id)) return null
        const runKey = `${data.tool_name || ''}::${JSON.stringify(data.tool_args || {})}`
        if (seenRunningToolKeys.has(runKey)) return null
        seenRunningToolKeys.add(runKey)
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: 'running',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_complete') {
        if (data.wave_id) return null
        if (duplicateCompleteIds.has(msg.id)) return null
        const rawOutput = data.raw_output || ''
        const startTime = completeToStartTime.get(msg.id)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: data.success ? 'success' : 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
        } as ToolExecutionItem
      } else if (msg.type === 'error') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: data.message,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'task_complete') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: data.message || '',
          phase: data.final_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'guidance') {
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: data.content || '',
          isGuidance: true,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'file_ready') {
        return {
          type: 'file_download',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          filepath: data.filepath || '',
          filename: data.filename || '',
          description: data.description || '',
          source: data.source || '',
        } as FileDownloadItem
      } else if (msg.type === 'todo_update') {
        lastTodoList = data.todo_list || []
        return null
      } else if (msg.type === 'phase_update') {
        if (data.attack_path_type) lastAttackPathType = data.attack_path_type
        const phase = data.current_phase || 'unknown'
        if (phase !== lastRenderedPhase) {
          lastRenderedPhase = phase
          return {
            type: 'message',
            id: msg.id,
            role: 'assistant',
            content: `**Phase:** ${phase}` + (data.iteration_count ? ` — Step ${data.iteration_count}` : ''),
            phase,
            timestamp: new Date(msg.createdAt),
          } as Message
        }
        return null
      } else if (msg.type === 'approval_request') {
        lastApprovalRequest = data
        hasWorkAfterApproval = false
        const parts = [`**Phase Transition Request:** ${data.from_phase || '?'} → ${data.to_phase || '?'}`]
        if (data.reason) parts.push(`\n**Reason:** ${data.reason}`)
        if (data.planned_actions?.length) parts.push(`\n**Planned Actions:**\n${data.planned_actions.map((a: string) => `- ${a}`).join('\n')}`)
        if (data.risks?.length) parts.push(`\n**Risks:**\n${data.risks.map((r: string) => `- ${r}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: parts.join('\n'),
          phase: data.from_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'approval_response') {
        lastApprovalRequest = null
        hasWorkAfterApproval = true
        const label = data.decision === 'approve'
          ? 'Approved phase transition'
          : data.decision === 'modify'
          ? `Modified: ${data.modification || ''}`
          : 'Aborted phase transition'
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: label,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'question_request') {
        lastQuestionRequest = data
        hasWorkAfterQuestion = false
        const qParts = [`**Agent Question:** ${data.question || ''}`]
        if (data.context) qParts.push(`\n> ${data.context}`)
        if (data.options?.length) qParts.push(`\n**Options:**\n${data.options.map((o: string) => `- ${o}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: qParts.join('\n'),
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'answer_response') {
        lastQuestionRequest = null
        hasWorkAfterQuestion = true
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: `Answer: ${data.answer || ''}`,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'tool_confirmation_request') {
        lastToolConfirmationRequest = data
        hasWorkAfterToolConfirmation = false
        const confMode = data.mode || 'single'
        const confTools = data.tools || []
        if (confMode === 'plan') {
          return {
            type: 'plan_wave',
            id: msg.id,
            timestamp: new Date(msg.createdAt),
            wave_id: '',
            plan_rationale: data.reasoning || '',
            tool_count: confTools.length,
            tools: confTools.map((t: any, idx: number) => ({
              type: 'tool_execution' as const,
              id: `${msg.id}-tool-${idx}`,
              timestamp: new Date(msg.createdAt),
              tool_name: t.tool_name || '',
              tool_args: t.tool_args || {},
              status: 'pending_approval' as const,
              output_chunks: [],
            })),
            status: 'pending_approval',
          } as PlanWaveItem
        }
        const tool = confTools[0] || {}
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: tool.tool_name || '',
          tool_args: tool.tool_args || {},
          status: 'pending_approval',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_confirmation_response') {
        lastToolConfirmationRequest = null
        hasWorkAfterToolConfirmation = true
        return { _toolConfResponse: true, decision: data.decision } as any
      } else if (msg.type === 'plan_start') {
        return { _planStartLink: true, wave_id: data.wave_id || '', msg_id: msg.id, timestamp: new Date(msg.createdAt), plan_rationale: data.plan_rationale || '', tool_count: data.tool_count || 0 } as any
      } else if (msg.type === 'deep_think') {
        return {
          type: 'deep_think',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          trigger_reason: data.trigger_reason || '',
          analysis: data.analysis || '',
          iteration: data.iteration || 0,
          phase: data.phase || '',
        } as DeepThinkItem
      } else if (msg.type === 'plan_complete') {
        return null
      }
      return null
    }).filter((item: ChatItem | null): item is ChatItem => item !== null)

    // Post-pass: apply tool_confirmation_response decisions
    {
      const markers: number[] = []
      for (let i = 0; i < restored.length; i++) {
        const item = restored[i] as any
        if (item._toolConfResponse) {
          markers.push(i)
          for (let j = i - 1; j >= 0; j--) {
            const prev = restored[j] as any
            if (prev.status === 'pending_approval' && (prev.type === 'tool_execution' || prev.type === 'plan_wave')) {
              if (item.decision === 'approve') {
                if (prev.type === 'plan_wave') {
                  restored[j] = { ...prev, status: 'running', tools: [] }
                } else {
                  restored.splice(j, 1)
                  for (let m = 0; m < markers.length; m++) {
                    if (markers[m] > j) markers[m]--
                  }
                  i--
                }
              } else {
                restored[j] = { ...prev, status: 'error', final_output: 'Rejected by user' }
              }
              break
            }
          }
        }
      }
      for (let k = markers.length - 1; k >= 0; k--) {
        restored.splice(markers[k], 1)
      }
    }

    // Post-pass: link plan_start markers to existing PlanWaveItems
    {
      const planStartMarkers: number[] = []
      for (let i = 0; i < restored.length; i++) {
        const item = restored[i] as any
        if (item._planStartLink) {
          planStartMarkers.push(i)
          let linked = false
          for (let j = i - 1; j >= 0; j--) {
            const prev = restored[j] as any
            if (prev.type === 'plan_wave' && prev.wave_id === '') {
              restored[j] = {
                ...prev,
                wave_id: item.wave_id,
                plan_rationale: item.plan_rationale || prev.plan_rationale,
                tool_count: item.tool_count || prev.tool_count,
                status: prev.status === 'pending_approval' ? 'pending_approval' : 'running',
              }
              linked = true
              break
            }
          }
          if (!linked) {
            restored[i] = {
              type: 'plan_wave',
              id: item.msg_id,
              timestamp: item.timestamp,
              wave_id: item.wave_id,
              plan_rationale: item.plan_rationale,
              tool_count: item.tool_count,
              tools: [],
              status: 'running',
            } as PlanWaveItem
            continue
          }
        }
      }
      for (let k = planStartMarkers.length - 1; k >= 0; k--) {
        if ((restored[planStartMarkers[k]] as any)._planStartLink) {
          restored.splice(planStartMarkers[k], 1)
        }
      }
    }

    // Post-pass: nest wave tool_complete items
    const waveToolStartTimes = new Map<string, Date>()
    for (const msg of full.messages) {
      if (msg.type === 'tool_start' && (msg.data as any)?.wave_id) {
        const d = msg.data as any
        const si = d.step_index ?? ''
        waveToolStartTimes.set(`${d.wave_id}:${d.tool_name}:${si}`, new Date(msg.createdAt))
      }
    }

    const waveToolCompletes = full.messages.filter(
      (m: any) => m.type === 'tool_complete' && (m.data as any)?.wave_id
    )
    for (const msg of waveToolCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        const rawOutput = data.raw_output || ''
        const si = data.step_index ?? ''
        const startTime = waveToolStartTimes.get(`${data.wave_id}:${data.tool_name}:${si}`)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        const newTools = [...wave.tools, {
          type: 'tool_execution' as const,
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: (data.success ? 'success' : 'error') as 'success' | 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
          step_index: data.step_index,
        }]
        restored[waveIdx] = { ...wave, tools: newTools, tool_count: Math.max(wave.tool_count, newTools.length) }
      }
    }

    // Apply plan_complete statuses
    const planCompletes = full.messages.filter((m: any) => m.type === 'plan_complete')
    for (const msg of planCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        let status: PlanWaveItem['status'] = 'success'
        if (data.failed === data.total_steps) status = 'error'
        else if (data.failed > 0) status = 'partial'
        restored[waveIdx] = { ...wave, status }
      }
    }

    // Apply plan_analysis data
    const planAnalyses = full.messages.filter((m: any) => m.type === 'plan_analysis')
    for (const msg of planAnalyses) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        restored[waveIdx] = {
          ...wave,
          interpretation: data.interpretation || '',
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
        }
      }
    }

    // Fetch fireteams for this session and append as FireteamItem[].
    // We do this in parallel with the message restore: the fireteams API
    // gives us a snapshot of all deployments and their members so the UI
    // can rebuild per-member panels on resume without replaying every
    // streaming event.
    try {
      const ftRes = await fetch(`/api/conversations/by-session/${conv.sessionId}/fireteams`)
      if (ftRes.ok) {
        const { fireteams } = await ftRes.json()
        if (Array.isArray(fireteams) && fireteams.length > 0) {
          for (const f of fireteams) {
            const startedAt = f.startedAt ? new Date(f.startedAt) : new Date()
            const completedAt = f.completedAt ? new Date(f.completedAt) : undefined
            const waveStatus: FireteamItem['status'] = ((): any => {
              const s = f.status || 'running'
              return ['running', 'completed', 'timeout', 'cancelled', 'failed'].includes(s) ? s : 'completed'
            })()
            // If the wave is terminal, any DB-recorded member that's still
            // `running` is stale (the per-member PATCH may have failed, or
            // the row predates the backend fix that patches members on
            // cancel). Cascade the wave's terminal status down so the UI
            // doesn't show specialists "RUNNING" under a CANCELLED header.
            const isTerminal = waveStatus !== 'running'
            const cascadeMemberStatus =
              waveStatus === 'cancelled' ? 'cancelled'
              : waveStatus === 'timeout' ? 'timeout'
              : waveStatus === 'failed' ? 'error'
              : 'success'
            restored.push({
              type: 'fireteam',
              id: f.fireteamIdKey,
              fireteam_id: f.fireteamIdKey,
              iteration: f.iteration ?? 0,
              plan_rationale: f.planRationale ?? '',
              timestamp: startedAt,
              started_at: startedAt,
              completed_at: completedAt,
              status: waveStatus,
              status_counts: f.statusCounts ?? undefined,
              wall_clock_seconds: f.wallClockSeconds ?? undefined,
              members: (f.members ?? []).map((m: any) => {
                const rawStatus = m.status
                const memberStatus = isTerminal
                  && (rawStatus === 'running' || rawStatus === 'needs_confirmation' || !rawStatus)
                  ? cascadeMemberStatus
                  : rawStatus
                return {
                  member_id: m.memberIdKey,
                  name: m.name,
                  task: m.task ?? '',
                  skills: m.skills ?? [],
                  status: memberStatus,
                  started_at: m.startedAt ? new Date(m.startedAt) : startedAt,
                  completed_at: m.completedAt
                    ? new Date(m.completedAt)
                    : (isTerminal ? (completedAt ?? new Date()) : undefined),
                  tools: [],
                  planWaves: [],
                  iterations_used: m.iterationsUsed ?? 0,
                  tokens_used: m.tokensUsed ?? 0,
                  input_tokens_used: 0,
                  output_tokens_used: 0,
                  findings_count: m.findingsCount ?? 0,
                  completion_reason: m.completionReason
                    ?? (memberStatus !== rawStatus ? `wave_${waveStatus}` : undefined),
                  error_message: m.errorMessage ?? undefined,
                }
              }),
            } as any)
          }
        }
      }
    } catch (e) {
      console.warn('[fireteam] restore fetch failed:', e)
    }

    // ---- Replay fireteam-scoped ChatMessage rows into member panels ----
    //
    // Each streamed event (tool_start/complete, plan_start/complete, thinking,
    // awaiting_confirmation) was persisted with memberIdKey + fireteamIdKey on
    // the ChatMessage row. The fireteams fetch above rebuilds member
    // headers + final counts; this pass replays the per-member events so the
    // card shows its tool history, plan waves, latest thought, and live
    // sub-step counter just like during the live run.
    try {
      const ftIndex = new Map<string, number>()
      for (let i = 0; i < restored.length; i++) {
        const it = restored[i] as any
        if (it && it.type === 'fireteam') ftIndex.set(it.fireteam_id, i)
      }
      const mutate = (ftId: string | null | undefined, mId: string | null | undefined, fn: (m: any) => any) => {
        if (!ftId || !mId) return
        const idx = ftIndex.get(ftId)
        if (idx === undefined) return
        const ft = restored[idx] as any
        const mIdx = ft.members.findIndex((m: any) => m.member_id === mId)
        if (mIdx < 0) return
        ft.members[mIdx] = fn(ft.members[mIdx])
      }

      for (const msg of full.messages as any[]) {
        const ftId = msg.fireteamIdKey
        const mId = msg.memberIdKey
        if (!ftId || !mId) continue
        const d = msg.data || {}
        const ts = new Date(msg.createdAt)
        switch (msg.type) {
          case 'fireteam_thinking': {
            const inDelta = Math.max(0, Number(d.input_tokens || 0))
            const outDelta = Math.max(0, Number(d.output_tokens || 0))
            mutate(ftId, mId, m => ({
              ...m,
              latest_thought: (d.thought || d.reasoning || '').slice(0, 240),
              latest_iteration: d.iteration ?? m.latest_iteration,
              input_tokens_used: (m.input_tokens_used ?? 0) + inDelta,
              output_tokens_used: (m.output_tokens_used ?? 0) + outDelta,
            }))
            break
          }
          case 'fireteam_plan_start': {
            const planId = `ft-restore-plan-${ftId}-${mId}-${d.wave_id || msg.id}`
            mutate(ftId, mId, m => ({
              ...m,
              planWaves: [
                ...m.planWaves,
                {
                  type: 'plan_wave' as const,
                  id: planId,
                  timestamp: ts,
                  wave_id: d.wave_id || '',
                  plan_rationale: d.plan_rationale || '',
                  tool_count: (d.tools || []).length,
                  tools: [],
                  status: 'running' as const,
                },
              ],
            }))
            break
          }
          case 'fireteam_plan_complete': {
            mutate(ftId, mId, m => {
              const idx = m.planWaves.findIndex((w: any) => w.wave_id === d.wave_id)
              if (idx < 0) return m
              const failed = d.failed ?? 0
              const successful = d.successful ?? 0
              const total = d.total ?? (failed + successful)
              let status: 'success' | 'error' | 'partial' = 'success'
              if (failed === total && total > 0) status = 'error'
              else if (failed > 0) status = 'partial'
              const nextWaves = m.planWaves.slice()
              nextWaves[idx] = { ...nextWaves[idx], status }
              return { ...m, planWaves: nextWaves }
            })
            break
          }
          case 'fireteam_tool_start': {
            const newTool = {
              type: 'tool_execution' as const,
              id: `ft-restore-tool-${msg.id}`,
              timestamp: ts,
              tool_name: d.tool_name || '',
              tool_args: d.tool_args || {},
              status: 'running' as const,
              output_chunks: [] as string[],
              step_index: d.step_index ?? undefined,
            }
            mutate(ftId, mId, m => {
              if (d.wave_id) {
                const idx = m.planWaves.findIndex((w: any) => w.wave_id === d.wave_id)
                if (idx >= 0) {
                  const nextWaves = m.planWaves.slice()
                  nextWaves[idx] = { ...nextWaves[idx], tools: [...nextWaves[idx].tools, newTool] }
                  return { ...m, planWaves: nextWaves }
                }
              }
              return { ...m, tools: [...m.tools, newTool] }
            })
            break
          }
          case 'fireteam_tool_complete': {
            mutate(ftId, mId, m => {
              const patch = (t: any) => ({
                ...t,
                status: d.success ? 'success' : 'error',
                duration: d.duration_ms,
                final_output: d.output_excerpt,
              })
              // Nested in plan wave?
              if (d.wave_id) {
                const wi = m.planWaves.findIndex((w: any) => w.wave_id === d.wave_id)
                if (wi >= 0) {
                  const wave = m.planWaves[wi]
                  for (let ti = wave.tools.length - 1; ti >= 0; ti--) {
                    if (wave.tools[ti].tool_name === d.tool_name && wave.tools[ti].status === 'running') {
                      const nextTools = wave.tools.slice()
                      nextTools[ti] = patch(nextTools[ti])
                      const nextWaves = m.planWaves.slice()
                      nextWaves[wi] = { ...wave, tools: nextTools }
                      return { ...m, planWaves: nextWaves }
                    }
                  }
                }
              }
              // Otherwise mutate a standalone member tool.
              for (let ti = m.tools.length - 1; ti >= 0; ti--) {
                if (m.tools[ti].tool_name === d.tool_name && m.tools[ti].status === 'running') {
                  const nextTools = m.tools.slice()
                  nextTools[ti] = patch(nextTools[ti])
                  return { ...m, tools: nextTools }
                }
              }
              return m
            })
            break
          }
          case 'fireteam_member_awaiting_confirmation': {
            // Render a persistent "pending approval" card inside the member
            // panel so operators who reconnect still see the pending request.
            // Once resumed post-decision, the subsequent tool_start events
            // replace the card with real tool cards.
            const pendingId = `ft-restore-await-${msg.id}`
            mutate(ftId, mId, m => ({
              ...m,
              status: 'needs_confirmation',
              planWaves: [
                ...m.planWaves,
                {
                  type: 'plan_wave' as const,
                  id: pendingId,
                  timestamp: ts,
                  wave_id: '',
                  plan_rationale: d.reasoning || '',
                  tool_count: (d.tools || []).length,
                  tools: (d.tools || []).map((t: any, idx: number) => ({
                    type: 'tool_execution' as const,
                    id: `${pendingId}-${idx}`,
                    timestamp: ts,
                    tool_name: t.tool_name || '',
                    tool_args: t.tool_args || {},
                    status: 'pending_approval' as const,
                    output_chunks: [] as string[],
                  })),
                  status: 'pending_approval' as const,
                  isFireteamEscalation: true,
                },
              ],
            }))
            break
          }
        }
      }
    } catch (e) {
      console.warn('[fireteam] per-member replay failed:', e)
    }

    // Final cascade pass: for any fireteam whose wave-level status is
    // terminal (cancelled / timeout / failed), flip every tool and plan
    // wave still showing `running` or `pending_approval` to an appropriate
    // terminal status. The replay block rebuilt cards from persisted
    // fireteam_tool_start events, but mid-flight tools at cancel time
    // never got a matching fireteam_tool_complete row — so without this
    // pass, switching chats and returning to a cancelled wave still shows
    // tools spinning inside dead specialists.
    for (let i = 0; i < restored.length; i++) {
      const it = restored[i] as any
      if (!it || it.type !== 'fireteam') continue
      const status = it.status
      if (status === 'running') continue
      const cascadeLabel =
        status === 'cancelled' ? 'Cancelled by operator'
        : status === 'timeout' ? 'Wave timeout'
        : status === 'failed' ? 'Wave failed'
        : null
      const cascadedMembers = (it.members || []).map((m: any) => {
        const flipTool = (t: any) => (
          t.status === 'running' || t.status === 'pending_approval'
            ? {
                ...t,
                status: 'error',
                final_output: t.final_output ?? cascadeLabel ?? undefined,
                duration: t.duration ?? Math.max(0, Date.now() - (t.timestamp?.getTime?.() ?? Date.now())),
              }
            : t
        )
        const nextTools = (m.tools || []).map(flipTool)
        const nextWaves = (m.planWaves || []).map((w: any) => {
          if (w.status !== 'running' && w.status !== 'pending_approval') return w
          return {
            ...w,
            tools: (w.tools || []).map(flipTool),
            status: 'error',
            interpretation: w.interpretation ?? cascadeLabel ?? undefined,
          }
        })
        return { ...m, tools: nextTools, planWaves: nextWaves }
      })
      restored[i] = { ...it, members: cascadedMembers }
    }

    // Sort by timestamp
    restored.sort((a: any, b: any) => {
      const ta = a.timestamp instanceof Date ? a.timestamp.getTime() : new Date(a.timestamp).getTime()
      const tb = b.timestamp instanceof Date ? b.timestamp.getTime() : new Date(b.timestamp).getTime()
      return ta - tb
    })

    // Apply state
    setChatItems(restored)
    setConversationId(conv.id)
    setCurrentPhase((conv.currentPhase || 'informational') as Phase)
    setAttackPathType(lastAttackPathType)
    setIterationCount(conv.iterationCount || 0)
    setIsLoading(conv.agentRunning)
    setIsStopped(false)
    setTodoList(lastTodoList)
    shouldAutoScroll.current = true
    setShowHistory(false)

    // Restore active skill from conversation
    if (conv.activeSkillId) {
      try {
        const res = await fetch(`/api/users/${userId}/chat-skills/${conv.activeSkillId}`)
        if (res.ok) {
          const skill = await res.json()
          setActiveSkill({ id: skill.id, name: skill.name, category: skill.category, content: skill.content })
        } else if (res.status === 404) {
          // Skill was deleted, clear from conversation
          updateConvMeta({ activeSkillId: '' }).catch(() => {})
          setActiveSkill(null)
        }
      } catch {
        // Skill may have been deleted or network error
        setActiveSkill(null)
      }
    } else {
      setActiveSkill(null)
    }

    if (lastApprovalRequest && !hasWorkAfterApproval) {
      setAwaitingApproval(true)
      setApprovalRequest(lastApprovalRequest)
      awaitingApprovalRef.current = true
    } else {
      setAwaitingApproval(false)
      setApprovalRequest(null)
    }
    if (lastQuestionRequest && !hasWorkAfterQuestion) {
      setAwaitingQuestion(true)
      setQuestionRequest(lastQuestionRequest)
      awaitingQuestionRef.current = true
    } else {
      setAwaitingQuestion(false)
      setQuestionRequest(null)
    }
    if (lastToolConfirmationRequest && !hasWorkAfterToolConfirmation) {
      setAwaitingToolConfirmation(true)
      setToolConfirmationRequest(lastToolConfirmationRequest)
      awaitingToolConfirmationRef.current = true
      const pendingTool = restored.findLast?.((item: any) => item.type === 'tool_execution' && item.status === 'pending_approval')
      const pendingWave = restored.findLast?.((item: any) => item.type === 'plan_wave' && item.status === 'pending_approval')
      if (pendingWave) {
        pendingApprovalWaveId.current = (pendingWave as any).id
      } else if (pendingTool) {
        pendingApprovalToolId.current = (pendingTool as any).id
      }
    } else {
      setAwaitingToolConfirmation(false)
      setToolConfirmationRequest(null)
    }

    isRestoringConversation.current = true
    onSwitchSession?.(conv.sessionId)
  }, [loadConversation, onSwitchSession, userId, setActiveSkill, updateConvMeta])

  const handleHistoryNewChat = useCallback(() => {
    setShowHistory(false)
    handleNewChat()
  }, [handleNewChat])

  const handleDeleteConversation = useCallback(async (id: string) => {
    await deleteConversation(id)
    onRefetchGraph?.()
    if (id === conversationId) {
      handleNewChat()
    }
  }, [deleteConversation, onRefetchGraph, conversationId, handleNewChat])

  return {
    conversationId,
    setConversationId,
    showHistory,
    setShowHistory,
    handleSelectConversation,
    handleHistoryNewChat,
    handleDeleteConversation,
  }
}
