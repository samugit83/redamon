'use client'

import React, { useMemo } from 'react'
import { Bot, Wifi, WifiOff, Loader2, AlertTriangle, Eye, EyeOff, History, Plus, Download } from 'lucide-react'
import { ConnectionStatus } from '@/lib/websocket-types'
import { Tooltip } from '@/components/ui/Tooltip/Tooltip'
import { ConversationHistory } from './ConversationHistory'
import { formatTokenCount } from '@/lib/formatTokens'
import type { Conversation } from '@/hooks/useConversations'
import type { ChatItem } from './types'
import styles from './AIAssistantDrawer.module.css'

interface DrawerHeaderProps {
  status: ConnectionStatus
  reconnectAttempt: number
  sessionId: string
  requireToolConfirmation: boolean
  hasOtherChains: boolean
  isOtherChainsHidden: boolean
  onToggleOtherChains?: () => void
  showHistory: boolean
  setShowHistory: (v: boolean) => void
  handleNewChat: () => void
  handleDownloadMarkdown: () => void
  chatItems: ChatItem[]
  onClose: () => void
  conversations: Conversation[]
  handleSelectConversation: (conv: Conversation) => void
  handleDeleteConversation: (id: string) => void
  handleHistoryNewChat: () => void
}

export function DrawerHeader({
  status,
  reconnectAttempt,
  sessionId,
  requireToolConfirmation,
  hasOtherChains,
  isOtherChainsHidden,
  onToggleOtherChains,
  showHistory,
  setShowHistory,
  handleNewChat,
  handleDownloadMarkdown,
  chatItems,
  onClose,
  conversations,
  handleSelectConversation,
  handleDeleteConversation,
  handleHistoryNewChat,
}: DrawerHeaderProps) {
  const getConnectionStatusColor = () =>
    status === ConnectionStatus.CONNECTED ? '#10b981' : '#ef4444'

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
      case ConnectionStatus.CONNECTING: return 'Connecting...'
      case ConnectionStatus.CONNECTED: return 'Connected'
      case ConnectionStatus.RECONNECTING: return `Reconnecting... (${reconnectAttempt}/5)`
      case ConnectionStatus.FAILED: return 'Connection failed'
      case ConnectionStatus.DISCONNECTED: return 'Disconnected'
    }
  }

  // Sum LLM tokens across every root think + every fireteam member. Root
  // ThinkingItems carry per-turn deltas; fireteam members track cumulative
  // totals on the panel. Summing both gives the session-wide total.
  const { totalInput, totalOutput } = useMemo(() => {
    let inTot = 0
    let outTot = 0
    for (const item of chatItems) {
      if (!('type' in item)) continue
      if (item.type === 'thinking') {
        inTot += item.input_tokens ?? 0
        outTot += item.output_tokens ?? 0
      } else if (item.type === 'fireteam') {
        for (const m of item.members) {
          inTot += m.input_tokens_used ?? 0
          outTot += m.output_tokens_used ?? 0
        }
      }
    }
    return { totalInput: inTot, totalOutput: outTot }
  }, [chatItems])
  const hasTokenTotal = totalInput > 0 || totalOutput > 0

  return (
    <>
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
              <span className={styles.sessionCode} title={sessionId}>
                Session: {sessionId.slice(-8)}
              </span>
              {hasTokenTotal && (
                <Tooltip content={`Session LLM usage · input ${totalInput.toLocaleString()} · output ${totalOutput.toLocaleString()}`}>
                  <span className={styles.tokenTotal}>
                    in {formatTokenCount(totalInput)} · out {formatTokenCount(totalOutput)}
                  </span>
                </Tooltip>
              )}
              {!requireToolConfirmation && (
                <Tooltip content="Tool confirmation is disabled. Dangerous tools will execute without manual approval.">
                  <div className={styles.dangerBadge}>
                    <AlertTriangle size={12} />
                    <span>Auto-exec</span>
                  </div>
                </Tooltip>
              )}
            </div>
          </div>
        </div>
        <div className={styles.headerActions}>
          {hasOtherChains && onToggleOtherChains && (
            <button
              className={`${styles.iconButton} ${isOtherChainsHidden ? styles.iconButtonActive : ''}`}
              onClick={onToggleOtherChains}
              title={isOtherChainsHidden ? 'Show all sessions in graph' : 'Show only this session in graph'}
              aria-label={isOtherChainsHidden ? 'Show all sessions in graph' : 'Show only this session in graph'}
            >
              {isOtherChainsHidden ? <Eye size={14} /> : <EyeOff size={14} />}
            </button>
          )}
          <button
            className={styles.iconButton}
            onClick={() => setShowHistory(!showHistory)}
            title="Session history"
            aria-label="Session history"
          >
            <History size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleNewChat}
            title="New session"
            aria-label="Start new session"
          >
            <Plus size={14} />
          </button>
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
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close assistant"
          >
            &times;
          </button>
        </div>
      </div>

      {showHistory && (
        <ConversationHistory
          conversations={conversations}
          currentSessionId={sessionId}
          onBack={() => setShowHistory(false)}
          onSelect={handleSelectConversation}
          onDelete={handleDeleteConversation}
          onNewChat={handleHistoryNewChat}
        />
      )}
    </>
  )
}
