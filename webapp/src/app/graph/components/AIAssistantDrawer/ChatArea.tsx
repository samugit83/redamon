'use client'

import React, { useRef, useEffect, useState, useCallback, useMemo } from 'react'
import { Bot, User, AlertCircle, Copy, Check } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { AgentTimeline } from './AgentTimeline'
import { FileDownloadCard } from './FileDownloadCard'
import { TodoListWidget } from './TodoListWidget'
import { AgentStatusChips } from './AgentStatusChips'
import { deriveAgentStatus, hasAgentStatus } from './agentStatus'
import { SuggestionPanels } from './SuggestionPanels'
import { extractTextFromChildren } from './phaseConfig'
import { parseNodeContextQuery } from '@/lib/agentQueryEnvelope'
import { copyText } from '@/lib/copyText'
import type { ChatItem, Message, FileDownloadItem, FireteamItem, LatsSearchItem } from './types'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from './AgentTimeline'
import styles from './AIAssistantDrawer.module.css'
import type { TodoItem } from '@/lib/websocket-types'
import { LOOP_SETTINGS_URL, LOOP_WIKI_URL, type LoopDisplay } from './hooks/loopStatus'

type TimelineGroupItem = ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem | FireteamItem | LatsSearchItem

type GroupedItem = {
  type: 'message' | 'timeline' | 'file_download'
  content: Message | TimelineGroupItem[] | FileDownloadItem
}

interface ChatAreaProps {
  messagesContainerRef: React.RefObject<HTMLDivElement | null>
  messagesEndRef: React.RefObject<HTMLDivElement | null>
  checkIfAtBottom: () => boolean
  chatItems: ChatItem[]
  groupedChatItems: GroupedItem[]
  isLoading: boolean
  todoList: TodoItem[]
  statusWord: string
  isConnected: boolean
  setInputValue: (v: string) => void
  missingApiKeys: Set<string>
  /** Absent when the keys are the project owner's (a collaborator's drawer): nothing to add. */
  openApiKeyModal?: (toolId: string) => void
  handleTimelineToolConfirmation: (itemId: string, decision: 'approve' | 'reject') => void
  /** Cancel a single running tool card. Receives the tool's item.id. */
  handleToolStop?: (itemId: string) => void
  /** Agent in the Loop: the status word, the chip and the notices of a loop run. */
  loop?: LoopDisplay
  /** A model call waiting for the provider's rate limit, with its countdown. */
  rateLimitWord?: string | null
}

export function ChatArea({
  messagesContainerRef,
  messagesEndRef,
  checkIfAtBottom,
  chatItems,
  groupedChatItems,
  isLoading,
  todoList,
  statusWord,
  isConnected,
  setInputValue,
  missingApiKeys,
  openApiKeyModal,
  handleTimelineToolConfirmation,
  handleToolStop,
  loop,
  rateLimitWord,
}: ChatAreaProps) {
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null)
  const [copiedFieldKey, setCopiedFieldKey] = useState<string | null>(null)
  const eyeRef = useRef<HTMLImageElement>(null)

  // Live KPI chips for the Todos bar, derived from data already in chatItems
  // (see agentStatus.ts). Single reverse scan, no extra state.
  const agentStatus = useMemo(() => deriveAgentStatus(chatItems), [chatItems])
  const showAgentStatus = hasAgentStatus(agentStatus) || Boolean(loop?.chip)

  // Random heartbeat animation for the loading eye
  useEffect(() => {
    if (!isLoading) return
    let timeout: ReturnType<typeof setTimeout>
    const beat = () => {
      const el = eyeRef.current
      if (!el) return
      el.style.transition = 'transform 0.15s ease-out'
      el.style.transform = 'scale(1.25)'
      setTimeout(() => {
        el.style.transform = 'scale(1)'
        setTimeout(() => {
          el.style.transform = 'scale(1.15)'
          setTimeout(() => {
            el.style.transform = 'scale(1)'
          }, 150)
        }, 120)
      }, 150)
      timeout = setTimeout(beat, 4000 + Math.random() * 6000)
    }
    timeout = setTimeout(beat, 2000 + Math.random() * 4000)
    return () => clearTimeout(timeout)
  }, [isLoading])

  const handleCopyMessage = useCallback((messageId: string, content: string) => {
    copyText(content).then(() => {
      setCopiedMessageId(messageId)
      setTimeout(() => setCopiedMessageId(null), 2000)
    })
  }, [])

  const handleCopyField = useCallback((key: string, text: string) => {
    copyText(text).then(() => {
      setCopiedFieldKey(key)
      setTimeout(() => setCopiedFieldKey(null), 2000)
    })
  }, [])

  const renderMessage = (item: Message) => {
    // A node-scoped first message carries the whole node context inline. Show
    // the operator's actual request as the bubble and tuck the context behind
    // a disclosure so the chat stays readable (live and on restore alike).
    const nodeCtx = item.role === 'user' ? parseNodeContextQuery(item.content) : null
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
          {nodeCtx ? (
            <>
              <span className={styles.nodeContextBadge}>{nodeCtx.nodeLabel}</span>
              <div className={styles.messageText}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{nodeCtx.request}</ReactMarkdown>
              </div>
              <details className={styles.nodeContextDetails}>
                <summary>Node context sent to the agent</summary>
                <pre className={styles.nodeContextPre}>{nodeCtx.context}</pre>
              </details>
            </>
          ) : (
            <>
          {item.responseTier === 'full_report' && (
            <div className={styles.reportHeader}>
              <span className={styles.reportBadge}>Report</span>
            </div>
          )}
          {item.responseTier === 'summary' && (
            <div className={styles.reportHeader}>
              <span className={styles.summaryBadge}>Summary</span>
            </div>
          )}
          <div
            className={styles.messageText}
            {...(item.responseTier === 'full_report' || item.responseTier === 'summary' ? { 'data-report-content': true } : {})}
          >
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ className, children, ...props }: any) {
                  const match = /language-(\w+)/.exec(className || '')
                  const language = match ? match[1] : ''
                  const isInline = !className
                  const codeText = String(children).replace(/\n$/, '')

                  if (!isInline) {
                    const codeKey = `code-${item.id}-${codeText.slice(0, 20)}`
                    return (
                      <div className={styles.codeBlockWrapper}>
                        <button
                          className={`${styles.codeBlockCopyButton} ${copiedFieldKey === codeKey ? styles.codeBlockCopyButtonCopied : ''}`}
                          onClick={() => handleCopyField(codeKey, codeText)}
                          title="Copy code"
                        >
                          {copiedFieldKey === codeKey ? <Check size={11} /> : <Copy size={11} />}
                        </button>
                        {language ? (
                          <SyntaxHighlighter
                            style={vscDarkPlus as any}
                            language={language}
                            PreTag="div"
                          >
                            {codeText}
                          </SyntaxHighlighter>
                        ) : (
                          <pre><code className={className} {...props}>{children}</code></pre>
                        )}
                      </div>
                    )
                  }

                  return (
                    <code className={className} {...props}>
                      {children}
                    </code>
                  )
                },
                td({ children, ...props }: any) {
                  const text = extractTextFromChildren(children)
                  if (!text || text.length < 3) {
                    return <td {...props}>{children}</td>
                  }
                  const cellKey = `td-${item.id}-${text.slice(0, 30)}`
                  return (
                    <td {...props}>
                      <span className={styles.tableCellContent}>
                        {children}
                        <button
                          className={`${styles.tableCellCopyButton} ${copiedFieldKey === cellKey ? styles.tableCellCopyButtonCopied : ''}`}
                          onClick={() => handleCopyField(cellKey, text)}
                          title="Copy value"
                        >
                          {copiedFieldKey === cellKey ? <Check size={10} /> : <Copy size={10} />}
                        </button>
                      </span>
                    </td>
                  )
                },
              }}
            >
              {item.content}
            </ReactMarkdown>
          </div>

          {item.role === 'assistant' && !item.isGuidance && (
            <button
              className={`${styles.copyButton} ${copiedMessageId === item.id ? styles.copyButtonCopied : ''}`}
              onClick={() => handleCopyMessage(item.id, item.content)}
              title="Copy to clipboard"
            >
              {copiedMessageId === item.id ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
            </button>
          )}
            </>
          )}

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
    <>
      {(todoList.length > 0 || showAgentStatus) && (
        <div className={styles.todoWidgetContainer}>
          <TodoListWidget
            items={todoList}
            headerRight={showAgentStatus ? (
              <AgentStatusChips {...agentStatus} loopActive={loop?.chip} loopUnattended={loop?.unattended} />
            ) : undefined}
          />
        </div>
      )}

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
            <SuggestionPanels isConnected={isConnected} setInputValue={setInputValue} />
          </div>
        )}

        {groupedChatItems.map((groupItem, index) => {
          if (groupItem.type === 'message') {
            return renderMessage(groupItem.content as Message)
          } else if (groupItem.type === 'file_download') {
            const file = groupItem.content as FileDownloadItem
            return (
              <FileDownloadCard
                key={file.id}
                filepath={file.filepath}
                filename={file.filename}
                description={file.description}
                source={file.source}
                projectId={file.projectId}
              />
            )
          } else {
            const items = groupItem.content as TimelineGroupItem[]
            return (
              <AgentTimeline
                key={`timeline-${index}`}
                items={items}
                isStreaming={isLoading && index === groupedChatItems.length - 1}
                missingApiKeys={missingApiKeys}
                onAddApiKey={openApiKeyModal}
                onToolConfirmation={handleTimelineToolConfirmation}
                onToolStop={handleToolStop}
              />
            )
          }
        })}

        {isLoading && (
          <div className={`${styles.message} ${styles.messageAssistant}`}>
            <div className={`${styles.messageIcon} ${styles.loadingEyeIcon}`}>
              <div className={styles.eyeContainer}>
                <img src="/logo.png" alt="RedAmon" width={34} height={21} className={styles.loadingEye} ref={eyeRef} />
                <div className={styles.eyePupil} />
              </div>
            </div>
            <div className={styles.messageContent}>
              <div className={styles.loadingIndicator}>
                <span key={rateLimitWord ? 'rate-limit' : loop?.statusWord ?? statusWord} className={styles.loadingWord}>
                  {rateLimitWord ?? loop?.statusWord ?? statusWord}
                </span>
              </div>
            </div>
          </div>
        )}

        {loop && loop.notices.length > 0 && (
          <div className={styles.loopNotices} role="status">
            {loop.notices.map(n => (
              <div key={n.text} className={`${styles.loopNotice} ${styles[`loopNotice_${n.tone}`] ?? ''}`}>
                <span>{n.text}</span>
                {n.links && (
                  <span className={styles.loopNoticeLinks}>
                    <a href={LOOP_WIKI_URL} target="_blank" rel="noopener noreferrer">Set up Agent in the Loop</a>
                    <a href={LOOP_SETTINGS_URL}>Global Settings → MCP Server</a>
                  </span>
                )}
              </div>
            ))}
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>
    </>
  )
}
