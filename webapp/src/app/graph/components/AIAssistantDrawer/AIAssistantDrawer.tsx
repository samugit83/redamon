/**
 * AI Assistant Drawer - WebSocket Version
 *
 * Real-time bidirectional communication with the agent using WebSocket.
 * Features streaming thoughts, tool executions, and beautiful timeline UI.
 * Single scrollable chat with all messages, thinking, and tool executions inline.
 */

'use client'

import { useState, useRef, useEffect, useCallback, KeyboardEvent } from 'react'
import { Send, Bot, User, Loader2, AlertCircle, Sparkles, RotateCcw, Shield, Target, Zap, HelpCircle, WifiOff, Wifi, Square, Play, Download } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import styles from './AIAssistantDrawer.module.css'
import { useAgentWebSocket } from '@/hooks/useAgentWebSocket'
import {
  MessageType,
  ConnectionStatus,
  type ServerMessage,
  type ApprovalRequestPayload,
  type QuestionRequestPayload,
  type TodoItem
} from '@/lib/websocket-types'
import { AgentTimeline } from './AgentTimeline'
import { TodoListWidget } from './TodoListWidget'
import type { ThinkingItem, ToolExecutionItem } from './AgentTimeline'

type Phase = 'informational' | 'exploitation' | 'post_exploitation'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  toolUsed?: string | null
  toolOutput?: string | null
  error?: string | null
  phase?: Phase
  timestamp: Date
  isGuidance?: boolean
  isReport?: boolean
}

type ChatItem = Message | ThinkingItem | ToolExecutionItem

interface AIAssistantDrawerProps {
  isOpen: boolean
  onClose: () => void
  userId: string
  projectId: string
  sessionId: string
  onResetSession?: () => void
  modelName?: string
}

const PHASE_CONFIG = {
  informational: {
    label: 'Informational',
    icon: Shield,
    color: 'var(--accent-primary)',
    bgColor: 'rgba(59, 130, 246, 0.1)',
  },
  exploitation: {
    label: 'Exploitation',
    icon: Target,
    color: 'var(--status-warning)',
    bgColor: 'rgba(245, 158, 11, 0.1)',
  },
  post_exploitation: {
    label: 'Post-Exploitation',
    icon: Zap,
    color: 'var(--status-error)',
    bgColor: 'rgba(239, 68, 68, 0.1)',
  },
}

type AttackPathType = 'cve_exploit' | 'brute_force_credential_guess'

const ATTACK_PATH_CONFIG = {
  cve_exploit: {
    label: 'CVE Exploit',
    shortLabel: 'CVE',
    color: 'var(--status-warning)',
    bgColor: 'rgba(245, 158, 11, 0.15)',
  },
  brute_force_credential_guess: {
    label: 'Brute Force',
    shortLabel: 'BRUTE',
    color: 'var(--accent-secondary, #8b5cf6)',
    bgColor: 'rgba(139, 92, 246, 0.15)',
  },
}

export function AIAssistantDrawer({
  isOpen,
  onClose,
  userId,
  projectId,
  sessionId,
  onResetSession,
  modelName,
}: AIAssistantDrawerProps) {
  const [chatItems, setChatItems] = useState<ChatItem[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isStopped, setIsStopped] = useState(false)
  const [currentPhase, setCurrentPhase] = useState<Phase>('informational')
  const [attackPathType, setAttackPathType] = useState<AttackPathType>('cve_exploit')
  const [iterationCount, setIterationCount] = useState(0)
  const [awaitingApproval, setAwaitingApproval] = useState(false)
  const [approvalRequest, setApprovalRequest] = useState<ApprovalRequestPayload | null>(null)
  const [modificationText, setModificationText] = useState('')

  // Q&A state
  const [awaitingQuestion, setAwaitingQuestion] = useState(false)
  const [questionRequest, setQuestionRequest] = useState<QuestionRequestPayload | null>(null)
  const [answerText, setAnswerText] = useState('')
  const [selectedOptions, setSelectedOptions] = useState<string[]>([])

  const [todoList, setTodoList] = useState<TodoItem[]>([])

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const isProcessingApproval = useRef(false)
  const awaitingApprovalRef = useRef(false)
  const isProcessingQuestion = useRef(false)
  const awaitingQuestionRef = useRef(false)
  const shouldAutoScroll = useRef(true)

  const scrollToBottom = useCallback((force = false) => {
    if (force || shouldAutoScroll.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [])

  // Check if user is at the bottom of the scroll
  const checkIfAtBottom = useCallback(() => {
    const container = messagesContainerRef.current
    if (!container) return true

    const threshold = 50 // pixels from bottom
    const isAtBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight < threshold

    shouldAutoScroll.current = isAtBottom
    return isAtBottom
  }, [])

  // Auto-scroll only if user is at bottom
  useEffect(() => {
    scrollToBottom()
  }, [chatItems, scrollToBottom])

  useEffect(() => {
    if (isOpen && inputRef.current && !awaitingApproval) {
      setTimeout(() => {
        inputRef.current?.focus()
        scrollToBottom(true) // Force scroll to bottom when opening
      }, 300)
    }
  }, [isOpen, awaitingApproval, scrollToBottom])

  // Reset state when session changes
  useEffect(() => {
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('cve_exploit')
    setIterationCount(0)
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    shouldAutoScroll.current = true // Reset to auto-scroll on new session
  }, [sessionId])

  // WebSocket message handler
  const handleWebSocketMessage = useCallback((message: ServerMessage) => {
    switch (message.type) {
      case MessageType.CONNECTED:
        break

      case MessageType.THINKING:
        // Add thinking item to chat
        const thinkingItem: ThinkingItem = {
          type: 'thinking',
          id: `thinking-${Date.now()}`,
          timestamp: new Date(),
          thought: message.payload.thought || '',
          reasoning: message.payload.reasoning || '',
          action: 'thinking',
          updated_todo_list: todoList,
        }
        setChatItems(prev => [...prev, thinkingItem])
        setIsLoading(true)
        setIsStopped(false)
        break

      case MessageType.TOOL_START:
        // Add tool execution item to chat
        const toolItem: ToolExecutionItem = {
          type: 'tool_execution',
          id: `tool-${Date.now()}`,
          timestamp: new Date(),
          tool_name: message.payload.tool_name,
          tool_args: message.payload.tool_args,
          status: 'running',
          output_chunks: [],
        }
        setChatItems(prev => [...prev, toolItem])
        setIsLoading(true)
        break

      case MessageType.TOOL_OUTPUT_CHUNK:
        // Append output chunk to the matching tool execution item (by tool_name)
        setChatItems(prev => {
          // Find the tool execution item by tool_name (handles any ordering)
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
              {
                ...toolItem,
                output_chunks: [...toolItem.output_chunks, message.payload.chunk],
              },
              ...prev.slice(toolIndex + 1)
            ]
          }
          return prev
        })
        break

      case MessageType.TOOL_COMPLETE:
        // Mark tool as complete and add rich analysis data
        setChatItems(prev => {
          // Find the tool execution item (may not be the last item due to message ordering)
          const toolIndex = prev.findIndex(
            item => 'type' in item &&
                    item.type === 'tool_execution' &&
                    item.tool_name === message.payload.tool_name &&
                    item.status === 'running'
          )
          if (toolIndex !== -1) {
            const toolItem = prev[toolIndex] as ToolExecutionItem
            const updatedItem: ToolExecutionItem = {
              ...toolItem,
              status: message.payload.success ? 'success' : 'error',
              final_output: message.payload.output_summary,
              actionable_findings: message.payload.actionable_findings || [],
              recommended_next_steps: message.payload.recommended_next_steps || [],
            }
            return [
              ...prev.slice(0, toolIndex),
              updatedItem,
              ...prev.slice(toolIndex + 1)
            ]
          }
          return prev
        })
        setIsLoading(false)
        break

      case MessageType.PHASE_UPDATE:
        setCurrentPhase(message.payload.current_phase as Phase)
        setIterationCount(message.payload.iteration_count)
        if (message.payload.attack_path_type) {
          setAttackPathType(message.payload.attack_path_type as AttackPathType)
        }
        break

      case MessageType.TODO_UPDATE:
        setTodoList(message.payload.todo_list)
        // Update the last thinking item with the new todo list
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
        // Ignore duplicate approval requests if we're already awaiting or just processed one
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
        // Ignore duplicate question requests if we're already awaiting or just processed one
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

      case MessageType.RESPONSE:
        // Add agent response message
        const assistantMessage: Message = {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          content: message.payload.answer,
          phase: message.payload.phase as Phase,
          timestamp: new Date(),
          isReport: message.payload.task_complete === true,
        }
        setChatItems(prev => [...prev, assistantMessage])
        setIsLoading(false)
        break

      case MessageType.ERROR:
        const errorMessage: Message = {
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: message.payload.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMessage])
        setIsLoading(false)
        break

      case MessageType.TASK_COMPLETE:
        const completeMessage: Message = {
          id: `complete-${Date.now()}`,
          role: 'assistant',
          content: message.payload.message,
          phase: message.payload.final_phase as Phase,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, completeMessage])
        setIsLoading(false)
        break

      case MessageType.GUIDANCE_ACK:
        // Already shown in chat from handleSend
        break

      case MessageType.STOPPED:
        setIsLoading(false)
        setIsStopped(true)
        break
    }
  }, [todoList])

  // Initialize WebSocket
  const { status, isConnected, reconnectAttempt, sendQuery, sendApproval, sendAnswer, sendGuidance, sendStop, sendResume } = useAgentWebSocket({
    userId: userId || process.env.NEXT_PUBLIC_USER_ID || 'default_user',
    projectId: projectId || process.env.NEXT_PUBLIC_PROJECT_ID || 'default_project',
    sessionId: sessionId || process.env.NEXT_PUBLIC_SESSION_ID || 'default_session',
    enabled: isOpen,
    onMessage: handleWebSocketMessage,
    onError: (error) => {
      // Only show connection errors once, not for every retry
      if (error.message === 'Initial connection failed') {
        const errorMsg: Message = {
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: `Failed to connect to agent. Please check that the backend is running at ${process.env.NEXT_PUBLIC_AGENT_WS_URL || 'ws://localhost:8090/ws/agent'}`,
          error: error.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMsg])
      }
    },
  })

  const handleSend = useCallback(() => {
    const question = inputValue.trim()
    if (!question || !isConnected || awaitingApproval || awaitingQuestion) return

    if (isLoading) {
      // Agent is working → send as guidance
      const guidanceMessage: Message = {
        id: `guidance-${Date.now()}`,
        role: 'user',
        content: question,
        isGuidance: true,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, guidanceMessage])
      setInputValue('')
      sendGuidance(question)
    } else {
      // Normal query
      const userMessage: Message = {
        id: `user-${Date.now()}`,
        role: 'user',
        content: question,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, userMessage])
      setInputValue('')
      setIsLoading(true)

      try {
        sendQuery(question)
      } catch (error) {
        setIsLoading(false)
      }
    }
  }, [inputValue, isConnected, isLoading, awaitingApproval, awaitingQuestion, sendQuery, sendGuidance])

  const handleApproval = useCallback((decision: 'approve' | 'modify' | 'abort') => {
    // Prevent double submission using ref (immediate check, not async state)
    if (!awaitingApproval || isProcessingApproval.current || !awaitingApprovalRef.current) {
      return
    }

    // Mark as processing immediately
    isProcessingApproval.current = true
    awaitingApprovalRef.current = false

    setAwaitingApproval(false)
    setApprovalRequest(null)
    setIsLoading(true)

    // Add decision message
    const decisionMessage: Message = {
      id: `decision-${Date.now()}`,
      role: 'user',
      content: decision === 'approve'
        ? 'Approved phase transition'
        : decision === 'modify'
        ? `Modified: ${modificationText}`
        : 'Aborted phase transition',
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, decisionMessage])

    try {
      sendApproval(decision, decision === 'modify' ? modificationText : undefined)
      setModificationText('')
    } catch (error) {
      setIsLoading(false)
      awaitingApprovalRef.current = false
      isProcessingApproval.current = false
    } finally {
      // Reset the processing flag after a delay to prevent backend from sending duplicate
      setTimeout(() => {
        isProcessingApproval.current = false
      }, 1000)
    }
  }, [modificationText, sendApproval, awaitingApproval])

  const handleAnswer = useCallback(() => {
    // Prevent double submission using ref (immediate check, not async state)
    if (!awaitingQuestion || isProcessingQuestion.current || !awaitingQuestionRef.current) {
      return
    }

    if (!questionRequest) return

    // Mark as processing immediately
    isProcessingQuestion.current = true
    awaitingQuestionRef.current = false

    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setIsLoading(true)

    const answer = questionRequest.format === 'text'
      ? answerText
      : selectedOptions.join(', ')

    // Add answer message
    const answerMessage: Message = {
      id: `answer-${Date.now()}`,
      role: 'user',
      content: `Answer: ${answer}`,
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, answerMessage])

    try {
      sendAnswer(answer)
      setAnswerText('')
      setSelectedOptions([])
    } catch (error) {
      setIsLoading(false)
      awaitingQuestionRef.current = false
      isProcessingQuestion.current = false
    } finally {
      // Reset the processing flag after a delay to prevent backend from sending duplicate
      setTimeout(() => {
        isProcessingQuestion.current = false
      }, 1000)
    }
  }, [questionRequest, answerText, selectedOptions, sendAnswer, awaitingQuestion])

  const handleStop = useCallback(() => {
    sendStop()
  }, [sendStop])

  const handleResume = useCallback(() => {
    sendResume()
    setIsStopped(false)
    setIsLoading(true)
  }, [sendResume])

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    e.target.style.height = 'auto'
    e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`
  }

  const handleDownloadMarkdown = useCallback(() => {
    if (chatItems.length === 0) return

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const lines: string[] = []

    // Header
    lines.push('# AI Agent Session Report')
    lines.push('')
    lines.push(`**Date:** ${new Date().toLocaleString()}  `)
    lines.push(`**Phase:** ${PHASE_CONFIG[currentPhase].label}  `)
    if (iterationCount > 0) lines.push(`**Step:** ${iterationCount}  `)
    if (modelName) lines.push(`**Model:** ${modelName}  `)
    lines.push('')
    lines.push('---')
    lines.push('')

    // Todo list snapshot
    if (todoList.length > 0) {
      lines.push('## Task List')
      lines.push('')
      todoList.forEach((item: TodoItem) => {
        const icon = item.status === 'completed' ? '[x]' : item.status === 'in_progress' ? '[-]' : '[ ]'
        const desc = item.description || item.content || item.activeForm || 'No description'
        lines.push(`- ${icon} ${desc}`)
      })
      lines.push('')
      lines.push('---')
      lines.push('')
    }

    // Chat timeline
    lines.push('## Session Timeline')
    lines.push('')

    chatItems.forEach(item => {
      if ('role' in item) {
        // Message
        const time = item.timestamp.toLocaleTimeString()
        if (item.role === 'user') {
          lines.push(`### User  \`${time}\``)
          if (item.isGuidance) lines.push('> *[Guidance]*')
        } else {
          lines.push(`### Assistant  \`${time}\``)
          if (item.isReport) lines.push('> **[Report]**')
        }
        lines.push('')
        lines.push(item.content)
        lines.push('')
        if (item.error) {
          lines.push(`> **Error:** ${item.error}`)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'thinking') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Thinking  \`${time}\``)
        lines.push('')
        if (item.thought) {
          lines.push(`> ${item.thought}`)
          lines.push('')
        }
        if (item.reasoning) {
          lines.push('<details>')
          lines.push('<summary>Reasoning</summary>')
          lines.push('')
          lines.push(item.reasoning)
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        if (item.updated_todo_list && item.updated_todo_list.length > 0) {
          lines.push('<details>')
          lines.push('<summary>Todo List Update</summary>')
          lines.push('')
          item.updated_todo_list.forEach(todo => {
            const icon = todo.status === 'completed' ? '[x]' : todo.status === 'in_progress' ? '[-]' : '[ ]'
            const desc = todo.description || todo.content || todo.activeForm || ''
            lines.push(`- ${icon} ${desc}`)
          })
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'tool_execution') {
        const time = item.timestamp.toLocaleTimeString()
        const statusIcon = item.status === 'success' ? 'OK' : item.status === 'error' ? 'FAIL' : 'RUNNING'
        lines.push(`### Tool: \`${item.tool_name}\`  \`${time}\`  [${statusIcon}]`)
        lines.push('')

        // Arguments
        if (item.tool_args && Object.keys(item.tool_args).length > 0) {
          lines.push('**Arguments**')
          lines.push('')
          Object.entries(item.tool_args).forEach(([key, value]) => {
            lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
          })
          lines.push('')
        }

        // Raw Output
        const rawOutput = item.output_chunks.join('')
        if (rawOutput) {
          lines.push('<details>')
          lines.push('<summary>Raw Output</summary>')
          lines.push('')
          lines.push('```')
          lines.push(rawOutput)
          lines.push('```')
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }

        // Analysis
        if (item.final_output) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(item.final_output)
          lines.push('')
        }

        // Actionable Findings
        if (item.actionable_findings && item.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          item.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }

        // Recommended Next Steps
        if (item.recommended_next_steps && item.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          item.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }

        lines.push('---')
        lines.push('')
      }
    })

    // Download
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redamon-session-${timestamp}.md`
    a.click()
    URL.revokeObjectURL(url)
  }, [chatItems, currentPhase, iterationCount, modelName, todoList])

  const handleNewChat = () => {
    // Cancel any running backend task before resetting
    if (isLoading) {
      sendStop()
    }
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('cve_exploit')
    setIterationCount(0)
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    shouldAutoScroll.current = true // Reset to auto-scroll on new chat
    onResetSession?.()
  }

  const PhaseIcon = PHASE_CONFIG[currentPhase].icon

  // Connection status indicator with color
  const getConnectionStatusColor = () => {
    return status === ConnectionStatus.CONNECTED ? '#10b981' : '#ef4444' // green : red
  }

  const getConnectionStatusIcon = () => {
    const color = getConnectionStatusColor()
    if (status === ConnectionStatus.CONNECTED) {
      return <Wifi size={12} className={styles.connectionIcon} style={{ color }} />
    } else if (status === ConnectionStatus.RECONNECTING) {
      return <Loader2 size={12} className={`${styles.connectionIcon} ${styles.spinner}`} style={{ color }} />
    } else {
      return <WifiOff size={12} className={styles.connectionIcon} style={{ color }} />
    }
  }

  const getConnectionStatusText = () => {
    switch (status) {
      case ConnectionStatus.CONNECTING:
        return 'Connecting...'
      case ConnectionStatus.CONNECTED:
        return 'Connected'
      case ConnectionStatus.RECONNECTING:
        return `Reconnecting... (${reconnectAttempt}/5)`
      case ConnectionStatus.FAILED:
        return 'Connection failed'
      case ConnectionStatus.DISCONNECTED:
        return 'Disconnected'
    }
  }

  // Group timeline items by their sequence (between messages)
  const groupedChatItems: Array<{ type: 'message' | 'timeline', content: Message | Array<ThinkingItem | ToolExecutionItem> }> = []

  let currentTimelineGroup: Array<ThinkingItem | ToolExecutionItem> = []

  chatItems.forEach((item) => {
    if ('role' in item) {
      // It's a message - push any accumulated timeline items first
      if (currentTimelineGroup.length > 0) {
        groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      // Then push the message
      groupedChatItems.push({ type: 'message', content: item })
    } else if ('type' in item && (item.type === 'thinking' || item.type === 'tool_execution')) {
      // It's a timeline item - add to current group
      currentTimelineGroup.push(item)
    }
  })

  // Push any remaining timeline items
  if (currentTimelineGroup.length > 0) {
    groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
  }

  const renderMessage = (item: Message) => {
    return (
      <div
        key={item.id}
        className={`${styles.message} ${
          item.role === 'user' ? styles.messageUser : styles.messageAssistant
        } ${item.isGuidance ? styles.messageGuidance : ''}`}
      >
        <div className={styles.messageIcon}>
          {item.role === 'user' ? <User size={14} /> : <Bot size={14} />}
        </div>
        <div className={styles.messageContent}>
          {item.isGuidance && (
            <span className={styles.guidanceBadge}>Guidance</span>
          )}
          {item.isReport && (
            <div className={styles.reportHeader}>
              <span className={styles.reportBadge}>Report</span>
            </div>
          )}
          <div
            className={styles.messageText}
            {...(item.isReport ? { 'data-report-content': true } : {})}
          >
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ className, children, ...props }: any) {
                  const match = /language-(\w+)/.exec(className || '')
                  const language = match ? match[1] : ''
                  const isInline = !className

                  return !isInline && language ? (
                    <SyntaxHighlighter
                      style={vscDarkPlus as any}
                      language={language}
                      PreTag="div"
                    >
                      {String(children).replace(/\n$/, '')}
                    </SyntaxHighlighter>
                  ) : (
                    <code className={className} {...props}>
                      {children}
                    </code>
                  )
                }
              }}
            >
              {item.content}
            </ReactMarkdown>
          </div>

          {item.error && (
            <div className={styles.errorBadge}>
              <AlertCircle size={12} />
              <span>{item.error}</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div
      className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}
      aria-hidden={!isOpen}
    >
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <div className={styles.headerIcon}>
            <Bot size={16} />
          </div>
          <div className={styles.headerText}>
            <h2 className={styles.title}>AI Agent</h2>
            <div className={styles.connectionStatus}>
              {getConnectionStatusIcon()}
              <span className={styles.subtitle} style={{ color: getConnectionStatusColor() }}>
                {getConnectionStatusText()}
              </span>
            </div>
          </div>
        </div>
        <div className={styles.headerActions}>
          <button
            className={styles.iconButton}
            onClick={handleDownloadMarkdown}
            title="Download chat as Markdown"
            aria-label="Download chat as Markdown"
            disabled={chatItems.length === 0}
          >
            <Download size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleNewChat}
            title="New conversation"
            aria-label="Start new conversation"
          >
            <RotateCcw size={14} />
          </button>
          <button
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close assistant"
          >
            &times;
          </button>
        </div>
      </div>

      {/* Phase Indicator */}
      <div className={styles.phaseIndicator}>
        <div
          className={styles.phaseBadge}
          style={{
            backgroundColor: PHASE_CONFIG[currentPhase].bgColor,
            borderColor: PHASE_CONFIG[currentPhase].color,
          }}
        >
          <PhaseIcon size={14} style={{ color: PHASE_CONFIG[currentPhase].color }} />
          <span style={{ color: PHASE_CONFIG[currentPhase].color }}>
            {PHASE_CONFIG[currentPhase].label}
          </span>
        </div>

        {/* Attack Path Badge - Show when in exploitation or post_exploitation phase */}
        {(currentPhase === 'exploitation' || currentPhase === 'post_exploitation') && (
          <div
            className={styles.phaseBadge}
            style={{
              backgroundColor: ATTACK_PATH_CONFIG[attackPathType].bgColor,
              borderColor: ATTACK_PATH_CONFIG[attackPathType].color,
            }}
          >
            <span style={{ color: ATTACK_PATH_CONFIG[attackPathType].color }}>
              {ATTACK_PATH_CONFIG[attackPathType].shortLabel}
            </span>
          </div>
        )}

        {iterationCount > 0 && (
          <span className={styles.iterationCount}>Step {iterationCount}</span>
        )}

        {modelName && (
          <span className={styles.modelBadge}>{modelName}</span>
        )}
      </div>

      {/* Todo List Widget */}
      {todoList.length > 0 && (
        <div className={styles.todoWidgetContainer}>
          <TodoListWidget items={todoList} />
        </div>
      )}

      {/* Unified Chat (Messages + Timeline Items) */}
      <div className={styles.messages} ref={messagesContainerRef} onScroll={checkIfAtBottom}>
        {chatItems.length === 0 && (
          <div className={styles.emptyState}>
            <div className={styles.emptyIcon}>
              <img src="/logo.png" alt="RedAmon" width={72} height={72} style={{ objectFit: 'contain' }} />
            </div>
            <h3 className={styles.emptyTitle}>How can I help you?</h3>
            <p className={styles.emptyDescription}>
              Ask me about recon data, vulnerabilities, exploitation, or post-exploitation activities.
            </p>
            <div className={styles.suggestions}>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Map the attack surface: list all domains, subdomains, IPs, open ports, and services discovered')}
                disabled={!isConnected}
              >
                Map the full attack surface
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Which vulnerabilities have known Metasploit exploit modules available?')}
                disabled={!isConnected}
              >
                Find exploitable CVEs with Metasploit modules
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Were any credentials, API keys, or secrets leaked in GitHub repositories?')}
                disabled={!isConnected}
              >
                Check for leaked secrets on GitHub
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Are any CISA Known Exploited Vulnerabilities (KEV) present in the scan results?')}
                disabled={!isConnected}
              >
                Find CISA Known Exploited Vulnerabilities
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('What web endpoints, parameters, and forms were discovered by the crawler?')}
                disabled={!isConnected}
              >
                Show discovered web endpoints and parameters
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Give me a prioritized risk summary of all findings ranked by severity and exploitability')}
                disabled={!isConnected}
              >
                Prioritized risk summary
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('What technology versions were detected, and which ones have known CVEs?')}
                disabled={!isConnected}
              >
                Detect outdated technologies with known CVEs
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Which services expose authentication that could be tested with credential brute force?')}
                disabled={!isConnected}
              >
                Find brute-forceable services
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Analyze TLS certificates and HTTP security headers for misconfigurations')}
                disabled={!isConnected}
              >
                Analyze TLS and security headers
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Find and exploit the most critical CVE affecting the primary target')}
                disabled={!isConnected}
              >
                Exploit the most critical vulnerability
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Find the most critical CVE on the target, exploit it with Metasploit, and open a shell session')}
                disabled={!isConnected}
              >
                Exploit a critical CVE and open a session
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Brute force SSH credentials on the target, then list sensitive files and directories')}
                disabled={!isConnected}
              >
                Brute force SSH and explore the server
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('After gaining access, search for passwords, API keys, config files, and database credentials on the server')}
                disabled={!isConnected}
              >
                Hunt for secrets on a compromised server
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Exploit the target web server and replace the homepage with a defacement page as proof of compromise')}
                disabled={!isConnected}
              >
                Deface the target homepage
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Use any secrets or credentials found on GitHub to attempt access to the target server and report what you find')}
                disabled={!isConnected}
              >
                Leverage GitHub secrets to access the server
              </button>
            </div>
          </div>
        )}

        {/* Render messages and timeline items in chronological order */}
        {groupedChatItems.map((groupItem, index) => {
          if (groupItem.type === 'message') {
            return renderMessage(groupItem.content as Message)
          } else {
            // Render timeline group
            const items = groupItem.content as Array<ThinkingItem | ToolExecutionItem>
            return (
              <AgentTimeline
                key={`timeline-${index}`}
                items={items}
                isStreaming={isLoading && index === groupedChatItems.length - 1}
              />
            )
          }
        })}

        {isLoading && (
          <div className={`${styles.message} ${styles.messageAssistant}`}>
            <div className={styles.messageIcon}>
              <Bot size={14} />
            </div>
            <div className={styles.messageContent}>
              <div className={styles.loadingIndicator}>
                <Loader2 size={14} className={styles.spinner} />
                <span>Processing...</span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Approval Dialog */}
      {awaitingApproval && approvalRequest && (
        <div className={styles.approvalDialog}>
          <div className={styles.approvalHeader}>
            <AlertCircle size={16} />
            <span>Phase Transition Request</span>
          </div>
          <div className={styles.approvalContent}>
            <p className={styles.approvalTransition}>
              <span className={styles.approvalFrom}>{approvalRequest.from_phase}</span>
              <span className={styles.approvalArrow}>→</span>
              <span className={styles.approvalTo}>{approvalRequest.to_phase}</span>
            </p>
            <p className={styles.approvalReason}>{approvalRequest.reason}</p>

            {approvalRequest.planned_actions.length > 0 && (
              <div className={styles.approvalSection}>
                <strong>Planned Actions:</strong>
                <ul>
                  {approvalRequest.planned_actions.map((action, i) => (
                    <li key={i}>{action}</li>
                  ))}
                </ul>
              </div>
            )}

            {approvalRequest.risks.length > 0 && (
              <div className={styles.approvalSection}>
                <strong>Risks:</strong>
                <ul>
                  {approvalRequest.risks.map((risk, i) => (
                    <li key={i}>{risk}</li>
                  ))}
                </ul>
              </div>
            )}

            <textarea
              className={styles.modificationInput}
              placeholder="Optional: provide modification feedback..."
              value={modificationText}
              onChange={(e) => setModificationText(e.target.value)}
            />
          </div>
          <div className={styles.approvalActions}>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonApprove}`}
              onClick={() => handleApproval('approve')}
              disabled={isLoading}
            >
              Approve
            </button>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonModify}`}
              onClick={() => handleApproval('modify')}
              disabled={isLoading || !modificationText.trim()}
            >
              Modify
            </button>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonAbort}`}
              onClick={() => handleApproval('abort')}
              disabled={isLoading}
            >
              Abort
            </button>
          </div>
        </div>
      )}

      {/* Q&A Dialog */}
      {awaitingQuestion && questionRequest && (
        <div className={styles.questionDialog}>
          <div className={styles.questionHeader}>
            <HelpCircle size={16} />
            <span>Agent Question</span>
          </div>
          <div className={styles.questionContent}>
            <div className={styles.questionText}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  code({ className, children, ...props }: any) {
                    const match = /language-(\w+)/.exec(className || '')
                    const language = match ? match[1] : ''
                    const isInline = !className

                    return !isInline && language ? (
                      <SyntaxHighlighter
                        style={vscDarkPlus as any}
                        language={language}
                        PreTag="div"
                      >
                        {String(children).replace(/\n$/, '')}
                      </SyntaxHighlighter>
                    ) : (
                      <code className={className} {...props}>
                        {children}
                      </code>
                    )
                  }
                }}
              >
                {questionRequest.question}
              </ReactMarkdown>
            </div>
            {questionRequest.context && (
              <div className={styles.questionContext}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {questionRequest.context}
                </ReactMarkdown>
              </div>
            )}

            {questionRequest.format === 'text' && (
              <textarea
                className={styles.answerInput}
                placeholder={questionRequest.default_value || 'Type your answer...'}
                value={answerText}
                onChange={(e) => setAnswerText(e.target.value)}
              />
            )}

            {questionRequest.format === 'single_choice' && questionRequest.options.length > 0 && (
              <div className={styles.optionsList}>
                {questionRequest.options.map((option, i) => (
                  <label key={i} className={styles.optionRadio}>
                    <input
                      type="radio"
                      name="question-option"
                      value={option}
                      checked={selectedOptions[0] === option}
                      onChange={() => setSelectedOptions([option])}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            )}

            {questionRequest.format === 'multi_choice' && questionRequest.options.length > 0 && (
              <div className={styles.optionsList}>
                {questionRequest.options.map((option, i) => (
                  <label key={i} className={styles.optionCheckbox}>
                    <input
                      type="checkbox"
                      value={option}
                      checked={selectedOptions.includes(option)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedOptions([...selectedOptions, option])
                        } else {
                          setSelectedOptions(selectedOptions.filter(o => o !== option))
                        }
                      }}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
          <div className={styles.questionActions}>
            <button
              className={`${styles.answerButton} ${styles.answerButtonSubmit}`}
              onClick={handleAnswer}
              disabled={isLoading || (questionRequest.format === 'text' ? !answerText.trim() : selectedOptions.length === 0)}
            >
              Submit Answer
            </button>
          </div>
        </div>
      )}

      {/* Input */}
      <div className={styles.inputContainer}>
        <div className={styles.inputWrapper}>
          <textarea
            ref={inputRef}
            className={styles.input}
            value={inputValue}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder={
              !isConnected
                ? 'Connecting to agent...'
                : awaitingApproval
                ? 'Respond to the approval request above...'
                : awaitingQuestion
                ? 'Answer the question above...'
                : isStopped
                ? 'Agent stopped. Click resume to continue...'
                : isLoading
                ? 'Send guidance to the agent...'
                : 'Ask a question...'
            }
            rows={1}
            disabled={awaitingApproval || awaitingQuestion || !isConnected || isStopped}
          />
          <div className={styles.inputActions}>
            {(isLoading || isStopped) && (
              <button
                className={`${styles.stopResumeButton} ${isStopped ? styles.resumeButton : styles.stopButton}`}
                onClick={isStopped ? handleResume : handleStop}
                aria-label={isStopped ? 'Resume agent' : 'Stop agent'}
                title={isStopped ? 'Resume execution' : 'Stop execution'}
              >
                {isStopped ? <Play size={13} /> : <Square size={13} />}
              </button>
            )}
            <button
              className={styles.sendButton}
              onClick={handleSend}
              disabled={!inputValue.trim() || awaitingApproval || awaitingQuestion || !isConnected || isStopped}
              aria-label="Send message"
            >
              <Send size={13} />
            </button>
          </div>
        </div>
        <span className={styles.inputHint}>
          {isConnected
            ? isLoading
              ? 'Send guidance or stop the agent'
              : 'Press Enter to send, Shift+Enter for new line'
            : 'Waiting for connection...'}
        </span>
      </div>
    </div>
  )
}
