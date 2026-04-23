import { useCallback, useRef, useEffect } from 'react'
import {
  MessageType,
  type ServerMessage,
  type TodoItem,
  type ApprovalRequestPayload,
  type QuestionRequestPayload,
  type ToolConfirmationRequestPayload,
  type FireteamDeployedPayload,
  type FireteamMemberStartedPayload,
  type FireteamThinkingPayload,
  type FireteamToolStartPayload,
  type FireteamToolOutputChunkPayload,
  type FireteamToolCompletePayload,
  type FireteamPlanStartPayload,
  type FireteamPlanCompletePayload,
  type FireteamMemberCompletedPayload,
  type FireteamCompletedPayload,
  type FireteamMemberAwaitingConfirmationPayload,
} from '@/lib/websocket-types'
import type { ChatItem, Message, FileDownloadItem, Phase, FireteamItem, FireteamMemberPanel } from '../types'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from '../AgentTimeline'
import {
  handleFireteamDeployed,
  handleFireteamMemberStarted,
  handleFireteamThinking,
  handleFireteamToolStart,
  handleFireteamToolOutputChunk,
  handleFireteamToolComplete,
  handleFireteamPlanStart,
  handleFireteamPlanComplete,
  handleFireteamMemberCompleted,
  handleFireteamCompleted,
} from './fireteamChatState'

interface WebSocketHandlerDeps {
  // From useChatState
  setChatItems: React.Dispatch<React.SetStateAction<ChatItem[]>>
  setIsLoading: (v: boolean) => void
  setIsStopped: (v: boolean) => void
  setIsStopping: (v: boolean) => void
  setCurrentPhase: (v: Phase) => void
  setIterationCount: (v: number) => void
  setAttackPathType: (v: string) => void
  setTodoList: (v: TodoItem[]) => void
  todoList: TodoItem[]
  itemIdCounter: React.MutableRefObject<number>
  // From useInteractionState
  setAwaitingApproval: (v: boolean) => void
  setApprovalRequest: (v: ApprovalRequestPayload | null) => void
  setAwaitingQuestion: (v: boolean) => void
  setQuestionRequest: (v: QuestionRequestPayload | null) => void
  setAwaitingToolConfirmation: (v: boolean) => void
  setToolConfirmationRequest: (v: ToolConfirmationRequestPayload | null) => void
  awaitingApprovalRef: React.MutableRefObject<boolean>
  isProcessingApproval: React.MutableRefObject<boolean>
  awaitingQuestionRef: React.MutableRefObject<boolean>
  isProcessingQuestion: React.MutableRefObject<boolean>
  awaitingToolConfirmationRef: React.MutableRefObject<boolean>
  isProcessingToolConfirmation: React.MutableRefObject<boolean>
  pendingApprovalToolId: React.MutableRefObject<string | null>
  pendingApprovalWaveId: React.MutableRefObject<string | null>
  // Fired after events that may have written new nodes to the graph DB
  // (TOOL_COMPLETE, FIRETEAM_TOOL_COMPLETE, TASK_COMPLETE, FIRETEAM_COMPLETED).
  // Debounced internally so concurrent wave tools coalesce into one refetch.
  onGraphMutation?: () => void
}

export function useWebSocketHandler(deps: WebSocketHandlerDeps) {
  const {
    setChatItems, setIsLoading, setIsStopped, setIsStopping,
    setCurrentPhase, setIterationCount, setAttackPathType, setTodoList,
    todoList, itemIdCounter,
    setAwaitingApproval, setApprovalRequest,
    setAwaitingQuestion, setQuestionRequest,
    setAwaitingToolConfirmation, setToolConfirmationRequest,
    awaitingApprovalRef, isProcessingApproval,
    awaitingQuestionRef, isProcessingQuestion,
    awaitingToolConfirmationRef, isProcessingToolConfirmation,
    pendingApprovalToolId, pendingApprovalWaveId,
    onGraphMutation,
  } = deps

  // Use a ref to avoid recreating the callback when todoList changes
  const todoListRef = useRef(todoList)
  useEffect(() => { todoListRef.current = todoList }, [todoList])

  // Debounced graph-refetch trigger. Ref-held so the stable handleWebSocketMessage
  // callback (deps: []) always hits the latest onGraphMutation.
  const onGraphMutationRef = useRef(onGraphMutation)
  useEffect(() => { onGraphMutationRef.current = onGraphMutation }, [onGraphMutation])
  const graphRefetchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const triggerGraphRefetch = useCallback(() => {
    if (graphRefetchTimerRef.current) clearTimeout(graphRefetchTimerRef.current)
    graphRefetchTimerRef.current = setTimeout(() => {
      graphRefetchTimerRef.current = null
      onGraphMutationRef.current?.()
    }, 500)
  }, [])
  useEffect(() => () => {
    if (graphRefetchTimerRef.current) clearTimeout(graphRefetchTimerRef.current)
  }, [])

  const handleWebSocketMessage = useCallback((message: ServerMessage) => {
    switch (message.type) {
      case MessageType.CONNECTED:
        break

      case MessageType.THINKING: {
        // Suppress `deploy_fireteam` thinking cards: the FireteamCard that
        // arrives immediately after carries the same thought+reasoning as
        // `plan_rationale`, so rendering a ThinkingItem before the card
        // duplicates the text. (Before this guard, users saw the exact same
        // thought twice in a row at the top of the chat.)
        if (message.payload.action === 'deploy_fireteam') {
          if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
            setIsLoading(true)
          }
          setIsStopped(false)
          break
        }
        const thinkingItem: ThinkingItem = {
          type: 'thinking',
          id: `thinking-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          thought: message.payload.thought || '',
          reasoning: message.payload.reasoning || '',
          action: 'thinking',
          updated_todo_list: todoListRef.current,
          input_tokens: Math.max(0, Number(message.payload.input_tokens || 0)),
          output_tokens: Math.max(0, Number(message.payload.output_tokens || 0)),
        }
        setChatItems(prev => [...prev, thinkingItem])
        if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
          setIsLoading(true)
        }
        setIsStopped(false)
        break
      }

      case MessageType.PLAN_START: {
        const pendingWaveId = pendingApprovalWaveId.current
        if (pendingWaveId) {
          pendingApprovalWaveId.current = null
          setChatItems((prev: ChatItem[]) => {
            const idx = prev.findIndex(item => item.type === 'plan_wave' && item.id === pendingWaveId)
            if (idx !== -1) {
              const wave = prev[idx] as PlanWaveItem
              return [
                ...prev.slice(0, idx),
                { ...wave, wave_id: message.payload.wave_id, status: 'running' as const, timestamp: new Date(), tool_count: message.payload.tool_count || wave.tool_count },
                ...prev.slice(idx + 1),
              ]
            }
            return prev
          })
        } else {
          const waveItem: PlanWaveItem = {
            type: 'plan_wave',
            id: `wave-${Date.now()}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            wave_id: message.payload.wave_id,
            plan_rationale: message.payload.plan_rationale || '',
            tool_count: message.payload.tool_count,
            tools: [],
            status: 'running',
          }
          setChatItems((prev: ChatItem[]) => [...prev, waveItem])
        }
        if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
          setIsLoading(true)
        }
        break
      }

      case MessageType.TOOL_START: {
        const wave_id = message.payload.wave_id
        if (wave_id) {
          setChatItems((prev: ChatItem[]) => {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === wave_id
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const pendingIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'pending_approval'
              )
              if (pendingIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                updatedTools[pendingIdx] = {
                  ...updatedTools[pendingIdx],
                  status: 'running',
                  timestamp: new Date(),
                  tool_args: message.payload.tool_args,
                  step_index: message.payload.step_index,
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
              const nestedTool: ToolExecutionItem = {
                type: 'tool_execution',
                id: `tool-${Date.now()}-${itemIdCounter.current++}`,
                timestamp: new Date(),
                tool_name: message.payload.tool_name,
                tool_args: message.payload.tool_args,
                status: 'running',
                output_chunks: [],
                step_index: message.payload.step_index,
              }
              return [
                ...prev.slice(0, waveIndex),
                { ...waveItem, tools: [...waveItem.tools, nestedTool] },
                ...prev.slice(waveIndex + 1),
              ]
            }
            const fallbackTool: ToolExecutionItem = {
              type: 'tool_execution',
              id: `tool-${Date.now()}-${itemIdCounter.current++}`,
              timestamp: new Date(),
              tool_name: message.payload.tool_name,
              tool_args: message.payload.tool_args,
              status: 'running',
              output_chunks: [],
            }
            return [...prev, fallbackTool]
          })
        } else {
          const pendingToolId = pendingApprovalToolId.current
          if (pendingToolId) {
            pendingApprovalToolId.current = null
            setChatItems((prev: ChatItem[]) => prev.map((item: ChatItem) =>
              'type' in item && item.type === 'tool_execution' && item.id === pendingToolId
                ? { ...item, status: 'running' as const, timestamp: new Date(), tool_args: message.payload.tool_args }
                : item
            ))
          } else {
            const toolItem: ToolExecutionItem = {
              type: 'tool_execution',
              id: `tool-${Date.now()}-${itemIdCounter.current++}`,
              timestamp: new Date(),
              tool_name: message.payload.tool_name,
              tool_args: message.payload.tool_args,
              status: 'running',
              output_chunks: [],
            }
            setChatItems((prev: ChatItem[]) => [...prev, toolItem])
          }
        }
        if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
          setIsLoading(true)
        }
        break
      }

      case MessageType.TOOL_OUTPUT_CHUNK: {
        const chunkWaveId = message.payload.wave_id
        setChatItems(prev => {
          if (chunkWaveId) {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === chunkWaveId
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const chunkStepIdx = message.payload.step_index
              const toolIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'running'
                  && (chunkStepIdx == null || t.step_index === chunkStepIdx)
              )
              if (toolIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                updatedTools[toolIdx] = {
                  ...updatedTools[toolIdx],
                  output_chunks: [...updatedTools[toolIdx].output_chunks, message.payload.chunk],
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
            }
            return prev
          }
          const toolIndex = prev.findIndex(
            item => 'type' in item &&
                    item.type === 'tool_execution' &&
                    item.tool_name === message.payload.tool_name &&
                    item.status === 'running'
          )
          if (toolIndex !== -1) {
            const toolItem = prev[toolIndex] as ToolExecutionItem
            return [
              ...prev.slice(0, toolIndex),
              { ...toolItem, output_chunks: [...toolItem.output_chunks, message.payload.chunk] },
              ...prev.slice(toolIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.TOOL_COMPLETE: {
        const completeWaveId = message.payload.wave_id
        if (completeWaveId) {
          setChatItems(prev => {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === completeWaveId
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const completeStepIdx = message.payload.step_index
              const toolIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'running'
                  && (completeStepIdx == null || t.step_index === completeStepIdx)
              )
              if (toolIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                const toolItem = updatedTools[toolIdx]
                const elapsed = Date.now() - toolItem.timestamp.getTime()
                updatedTools[toolIdx] = {
                  ...toolItem,
                  status: message.payload.success ? 'success' : 'error',
                  final_output: message.payload.output_summary,
                  actionable_findings: message.payload.actionable_findings || [],
                  recommended_next_steps: message.payload.recommended_next_steps || [],
                  duration: elapsed,
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
            }
            return prev
          })
        } else {
          setChatItems(prev => {
            const toolIndex = prev.findIndex(
              item => 'type' in item &&
                      item.type === 'tool_execution' &&
                      item.tool_name === message.payload.tool_name &&
                      item.status === 'running'
            )
            if (toolIndex !== -1) {
              const toolItem = prev[toolIndex] as ToolExecutionItem
              const elapsed = Date.now() - toolItem.timestamp.getTime()
              const updatedItem: ToolExecutionItem = {
                ...toolItem,
                status: message.payload.success ? 'success' : 'error',
                final_output: message.payload.output_summary,
                actionable_findings: message.payload.actionable_findings || [],
                recommended_next_steps: message.payload.recommended_next_steps || [],
                duration: elapsed,
              }
              return [
                ...prev.slice(0, toolIndex),
                updatedItem,
                ...prev.slice(toolIndex + 1),
              ]
            }
            return prev
          })
          setIsLoading(false)
        }
        triggerGraphRefetch()
        break
      }

      case MessageType.PLAN_COMPLETE: {
        setChatItems((prev: ChatItem[]) => {
          const waveIndex = prev.findIndex(
            (item: ChatItem) => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === message.payload.wave_id
          )
          if (waveIndex !== -1) {
            const waveItem = prev[waveIndex] as PlanWaveItem
            let status: PlanWaveItem['status'] = 'success'
            if (message.payload.failed === message.payload.total_steps) {
              status = 'error'
            } else if (message.payload.failed > 0) {
              status = 'partial'
            }
            return [
              ...prev.slice(0, waveIndex),
              { ...waveItem, status },
              ...prev.slice(waveIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.PLAN_ANALYSIS: {
        setChatItems(prev => {
          const waveIndex = prev.findIndex(
            (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === message.payload.wave_id
          )
          if (waveIndex !== -1) {
            const waveItem = prev[waveIndex] as PlanWaveItem
            return [
              ...prev.slice(0, waveIndex),
              {
                ...waveItem,
                interpretation: message.payload.interpretation,
                actionable_findings: message.payload.actionable_findings || [],
                recommended_next_steps: message.payload.recommended_next_steps || [],
              },
              ...prev.slice(waveIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.DEEP_THINK: {
        const deepThinkItem: DeepThinkItem = {
          type: 'deep_think',
          id: `deep-think-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          trigger_reason: message.payload.trigger_reason,
          analysis: message.payload.analysis,
          iteration: message.payload.iteration,
          phase: message.payload.phase,
        }
        setChatItems(prev => [...prev, deepThinkItem])
        break
      }

      case MessageType.PHASE_UPDATE:
        setCurrentPhase(message.payload.current_phase as Phase)
        setIterationCount(message.payload.iteration_count)
        if (message.payload.attack_path_type) {
          setAttackPathType(message.payload.attack_path_type)
        }
        break

      case MessageType.TODO_UPDATE:
        setTodoList(message.payload.todo_list)
        setChatItems(prev => {
          if (prev.length === 0) return prev
          const lastItem = prev[prev.length - 1]
          if ('type' in lastItem && lastItem.type === 'thinking') {
            return [
              ...prev.slice(0, -1),
              { ...lastItem, updated_todo_list: message.payload.todo_list }
            ]
          }
          return prev
        })
        break

      case MessageType.APPROVAL_REQUEST:
        if (awaitingApprovalRef.current || isProcessingApproval.current) {
          console.log('Ignoring duplicate approval request - already processing')
          break
        }
        console.log('Received approval request:', message.payload)
        awaitingApprovalRef.current = true
        setAwaitingApproval(true)
        setApprovalRequest(message.payload)
        setIsLoading(false)
        break

      case MessageType.QUESTION_REQUEST:
        if (awaitingQuestionRef.current || isProcessingQuestion.current) {
          console.log('Ignoring duplicate question request - already processing')
          break
        }
        console.log('Received question request:', message.payload)
        awaitingQuestionRef.current = true
        setAwaitingQuestion(true)
        setQuestionRequest(message.payload)
        setIsLoading(false)
        break

      case MessageType.TOOL_CONFIRMATION_REQUEST: {
        if (awaitingToolConfirmationRef.current || isProcessingToolConfirmation.current) {
          break
        }
        awaitingToolConfirmationRef.current = true
        setAwaitingToolConfirmation(true)
        setToolConfirmationRequest(message.payload)
        setIsLoading(false)

        const confMode = message.payload.mode || 'single'
        const confTools = message.payload.tools || []
        const escalatedAgentId = (message.payload as any).agent_id || null
        const escalatedAgentName = (message.payload as any).agent_name || null
        const isFireteamEscalation = Boolean(
          confMode === 'fireteam_escalation' || escalatedAgentId || escalatedAgentName,
        )

        // Fireteam escalations render INSIDE the matching member panel instead
        // of as a top-level plan_wave, so the approval UI stays grouped with
        // the agent that asked. See FIRETEAM.md §26.10.
        if (isFireteamEscalation) {
          const waveId = `wave-conf-${Date.now()}-${itemIdCounter.current++}`
          pendingApprovalWaveId.current = waveId
          pendingApprovalToolId.current = null
          const pendingTools: ToolExecutionItem[] = confTools.map((t: any, idx: number) => ({
            type: 'tool_execution' as const,
            id: `tool-conf-${Date.now()}-${idx}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            tool_name: t.tool_name || '',
            tool_args: t.tool_args || {},
            status: 'pending_approval' as const,
            output_chunks: [],
          }))
          const waveItem: PlanWaveItem = {
            type: 'plan_wave',
            id: waveId,
            timestamp: new Date(),
            wave_id: '',
            plan_rationale: message.payload.reasoning || '',
            tool_count: confTools.length,
            tools: pendingTools,
            status: 'pending_approval',
            isFireteamEscalation: true,
          }
          setChatItems((prev: ChatItem[]) => {
            // Find the most recent FireteamItem and inject the pending wave
            // into the matching member's panel. Fall back to top-level only
            // if no open fireteam or member match is found.
            let injected = false
            const next = prev.slice()
            for (let i = next.length - 1; i >= 0 && !injected; i--) {
              const it = next[i]
              if (!('type' in it) || it.type !== 'fireteam') continue
              const ft = it as FireteamItem
              const memberIdx = ft.members.findIndex((m: FireteamMemberPanel) =>
                (escalatedAgentId && m.member_id === escalatedAgentId)
                || (escalatedAgentName && m.name === escalatedAgentName),
              )
              if (memberIdx < 0) continue
              const member = ft.members[memberIdx]
              const updatedMember: FireteamMemberPanel = {
                ...member,
                status: 'needs_confirmation',
                planWaves: [...member.planWaves, waveItem],
              }
              const updatedFt: FireteamItem = {
                ...ft,
                members: [
                  ...ft.members.slice(0, memberIdx),
                  updatedMember,
                  ...ft.members.slice(memberIdx + 1),
                ],
              }
              next[i] = updatedFt
              injected = true
            }
            if (!injected) {
              // No matching fireteam member. Render at top level so the
              // operator can still approve/reject, but log so the mismatch is
              // visible when debugging.
              console.warn('[fireteam] escalation with no matching member panel', {
                agentId: escalatedAgentId, agentName: escalatedAgentName,
              })
              return [...prev, waveItem]
            }
            return next
          })
          break
        }

        if (confMode === 'plan') {
          const waveId = `wave-conf-${Date.now()}-${itemIdCounter.current++}`
          pendingApprovalWaveId.current = waveId
          pendingApprovalToolId.current = null
          const pendingTools: ToolExecutionItem[] = confTools.map((t: any, idx: number) => ({
            type: 'tool_execution' as const,
            id: `tool-conf-${Date.now()}-${idx}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            tool_name: t.tool_name || '',
            tool_args: t.tool_args || {},
            status: 'pending_approval' as const,
            output_chunks: [],
          }))
          const waveItem: PlanWaveItem = {
            type: 'plan_wave',
            id: waveId,
            timestamp: new Date(),
            wave_id: '',
            plan_rationale: message.payload.reasoning || '',
            tool_count: confTools.length,
            tools: pendingTools,
            status: 'pending_approval',
          }
          setChatItems((prev: ChatItem[]) => [...prev, waveItem])
        } else {
          const tool = confTools[0] || {}
          pendingApprovalWaveId.current = null
          setChatItems((prev: ChatItem[]) => {
            const existingIdx = prev.findIndex(
              (item: ChatItem) => item.type === 'tool_execution'
                && (item as ToolExecutionItem).tool_name === (tool.tool_name || '')
                && (item as ToolExecutionItem).status === 'running'
            )
            if (existingIdx !== -1) {
              const existing = prev[existingIdx] as ToolExecutionItem
              pendingApprovalToolId.current = existing.id
              return [
                ...prev.slice(0, existingIdx),
                { ...existing, status: 'pending_approval' as const, tool_args: tool.tool_args || existing.tool_args },
                ...prev.slice(existingIdx + 1),
              ]
            }
            const toolId = `tool-conf-${Date.now()}-${itemIdCounter.current++}`
            pendingApprovalToolId.current = toolId
            const toolItem: ToolExecutionItem = {
              type: 'tool_execution',
              id: toolId,
              timestamp: new Date(),
              tool_name: tool.tool_name || '',
              tool_args: tool.tool_args || {},
              status: 'pending_approval',
              output_chunks: [],
            }
            return [...prev, toolItem]
          })
        }
        break
      }

      // ---------------- Fireteam (multi-agent) events ----------------

      case MessageType.FIRETEAM_DEPLOYED: {
        const p = message.payload as FireteamDeployedPayload
        setChatItems(prev => handleFireteamDeployed(prev, p))
        break
      }
      case MessageType.FIRETEAM_MEMBER_STARTED: {
        const p = message.payload as FireteamMemberStartedPayload
        setChatItems(prev => handleFireteamMemberStarted(prev, p))
        break
      }
      case MessageType.FIRETEAM_THINKING: {
        const p = message.payload as FireteamThinkingPayload
        setChatItems(prev => handleFireteamThinking(prev, p))
        break
      }
      case MessageType.FIRETEAM_TOOL_START: {
        const p = message.payload as FireteamToolStartPayload
        setChatItems(prev => handleFireteamToolStart(prev, p))
        break
      }
      case MessageType.FIRETEAM_TOOL_OUTPUT_CHUNK: {
        const p = message.payload as FireteamToolOutputChunkPayload
        setChatItems(prev => handleFireteamToolOutputChunk(prev, p))
        break
      }
      case MessageType.FIRETEAM_TOOL_COMPLETE: {
        const p = message.payload as FireteamToolCompletePayload
        setChatItems(prev => handleFireteamToolComplete(prev, p))
        triggerGraphRefetch()
        break
      }
      case MessageType.FIRETEAM_PLAN_START: {
        const p = message.payload as FireteamPlanStartPayload
        setChatItems(prev => handleFireteamPlanStart(prev, p))
        break
      }
      case MessageType.FIRETEAM_PLAN_COMPLETE: {
        const p = message.payload as FireteamPlanCompletePayload
        setChatItems(prev => handleFireteamPlanComplete(prev, p))
        break
      }
      case MessageType.FIRETEAM_MEMBER_COMPLETED: {
        const p = message.payload as FireteamMemberCompletedPayload
        setChatItems(prev => handleFireteamMemberCompleted(prev, p))
        break
      }
      case MessageType.FIRETEAM_COMPLETED: {
        const p = message.payload as FireteamCompletedPayload
        setChatItems(prev => handleFireteamCompleted(prev, p))
        triggerGraphRefetch()
        break
      }

      case MessageType.FIRETEAM_MEMBER_AWAITING_CONFIRMATION: {
        const p = message.payload as FireteamMemberAwaitingConfirmationPayload
        const waveId = `ft-await-${Date.now()}-${itemIdCounter.current++}`
        const pendingTools: ToolExecutionItem[] = (p.tools || []).map((t, idx) => ({
          type: 'tool_execution' as const,
          id: `tool-conf-${Date.now()}-${idx}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          tool_name: t.tool_name || '',
          tool_args: t.tool_args || {},
          status: 'pending_approval' as const,
          output_chunks: [],
        }))
        const pendingWave: PlanWaveItem = {
          type: 'plan_wave',
          id: waveId,
          timestamp: new Date(),
          wave_id: '',
          plan_rationale: p.reasoning || '',
          tool_count: pendingTools.length,
          tools: pendingTools,
          status: 'pending_approval',
          isFireteamEscalation: true,
        }
        // Inject into the matching member's panel inside the live fireteam.
        // Does NOT set awaitingToolConfirmation/isLoading: other members keep
        // running in parallel; we only want to present the confirmation card
        // inline on the single member that asked.
        setChatItems((prev: ChatItem[]) => {
          const next = prev.slice()
          for (let i = next.length - 1; i >= 0; i--) {
            const it = next[i]
            if (!('type' in it) || it.type !== 'fireteam') continue
            const ft = it as FireteamItem
            if (ft.fireteam_id !== p.fireteam_id && ft.fireteam_id !== p.wave_id) continue
            const memberIdx = ft.members.findIndex((m: FireteamMemberPanel) => m.member_id === p.member_id)
            if (memberIdx < 0) continue
            const member = ft.members[memberIdx]
            const updatedMember: FireteamMemberPanel = {
              ...member,
              status: 'needs_confirmation',
              planWaves: [...member.planWaves, pendingWave],
            }
            next[i] = {
              ...ft,
              members: [
                ...ft.members.slice(0, memberIdx),
                updatedMember,
                ...ft.members.slice(memberIdx + 1),
              ],
            }
            return next
          }
          console.warn('[fireteam] awaiting_confirmation for unknown wave/member', p)
          return prev
        })
        break
      }

      case MessageType.RESPONSE: {
        const tier = message.payload.response_tier || (message.payload.task_complete ? 'full_report' : 'conversational')
        const assistantMessage: Message = {
          type: 'message',
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          content: message.payload.answer,
          phase: message.payload.phase as Phase,
          timestamp: new Date(),
          isReport: tier === 'full_report',
          responseTier: tier,
        }
        setChatItems(prev => [...prev, assistantMessage])
        setIsLoading(false)
        break
      }

      case MessageType.ERROR: {
        const errorMessage: Message = {
          type: 'message',
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: message.payload.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMessage])
        setIsLoading(false)
        break
      }

      case MessageType.TASK_COMPLETE: {
        const completeMessage: Message = {
          type: 'message',
          id: `complete-${Date.now()}`,
          role: 'assistant',
          content: message.payload.message,
          phase: message.payload.final_phase as Phase,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, completeMessage])
        setIsLoading(false)
        triggerGraphRefetch()
        break
      }

      case MessageType.GUIDANCE_ACK:
        break

      case MessageType.STOPPED:
        setIsLoading(false)
        setIsStopped(true)
        setIsStopping(false)
        break

      case MessageType.FILE_READY: {
        const fileItem: FileDownloadItem = {
          type: 'file_download',
          id: `file-${Date.now()}`,
          timestamp: new Date(),
          filepath: message.payload.filepath,
          filename: message.payload.filename,
          description: message.payload.description,
          source: message.payload.source,
        }
        setChatItems(prev => [...prev, fileItem])
        break
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return { handleWebSocketMessage }
}
