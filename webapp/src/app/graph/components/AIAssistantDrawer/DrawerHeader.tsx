'use client'

import React, { useMemo } from 'react'
import { Bot, Wifi, WifiOff, Loader2, AlertTriangle, Eye, EyeOff, History, Plus, Download, FolderOpen } from 'lucide-react'
import { ConnectionStatus } from '@/lib/websocket-types'
import { useTheme } from '@/hooks/useTheme'
import { Tooltip } from '@/components/ui/Tooltip/Tooltip'
import { ConversationHistory, type ConversationSharingControls } from './ConversationHistory'
import { formatTokenCount } from '@/lib/formatTokens'
import { describeWsClose } from '@/hooks/agentWsClose'
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
  handleDownloadMarkdown: () => void | Promise<void>
  chatItems: ChatItem[]
  onClose: () => void
  onOpenFileSystem?: () => void
  conversations: Conversation[]
  conversationsLoading?: boolean
  handleSelectConversation: (conv: Conversation) => void
  handleDeleteConversation: (id: string) => void
  handleHistoryNewChat: () => void
  /** Why the socket is not connected (the hook's error). */
  connectionError?: string | null
  /** The last close the agent sent, kept while reconnecting. */
  lastClose?: { code: number; reason: string } | null
  /** The URL dialed, without its query. */
  socketUrl?: string | null
  /** The agent service's own health answer, asked once the socket has failed. */
  agentHealthError?: string | null
  /** The session list could not be loaded. */
  conversationsError?: string | null
  /** Conversation sharing in the history (step 5.8); absent without write sharing in force. */
  historySharing?: ConversationSharingControls | null
}

/** The lines under the status that say why the drawer is not connected. */
export function connectionDetailLines({
  status, connectionError, lastClose, socketUrl, agentHealthError,
}: Pick<DrawerHeaderProps, 'status' | 'connectionError' | 'lastClose' | 'socketUrl' | 'agentHealthError'>): string[] {
  const where = socketUrl ? ` · ${socketUrl}` : ''
  if (status === ConnectionStatus.FAILED) {
    const lines = [connectionError || (lastClose ? `Last ${describeWsClose(lastClose.code, lastClose.reason)}${where}` : `Could not connect${where}`)]
    if (agentHealthError) lines.push(`Agent service: ${agentHealthError}`)
    return lines
  }
  if (status === ConnectionStatus.RECONNECTING && lastClose) {
    return [`Last ${describeWsClose(lastClose.code, lastClose.reason)}${where}`]
  }
  return []
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
  onOpenFileSystem,
  conversations,
  conversationsLoading,
  handleSelectConversation,
  handleDeleteConversation,
  handleHistoryNewChat,
  connectionError,
  lastClose,
  socketUrl,
  agentHealthError,
  conversationsError,
  historySharing,
}: DrawerHeaderProps) {
  const { isLight } = useTheme()
  const detailLines = connectionDetailLines({ status, connectionError, lastClose, socketUrl, agentHealthError })

  // The header is a dark strip in dark mode and a light strip in light mode, so
  // the status color needs to shift: bright emerald/red read on the dark header,
  // but on the light header they wash out, so use deeper shades for contrast.
  const getConnectionStatusColor = () => {
    if (status === ConnectionStatus.CONNECTED) return isLight ? '#047857' : '#10b981'
    return isLight ? '#dc2626' : '#ef4444'
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
            {detailLines.length > 0 && (
              <div role="status" aria-label="Agent connection detail">
                {detailLines.map((line, i) => (
                  <div
                    key={i}
                    className={`${styles.connectionDetail} ${status === ConnectionStatus.RECONNECTING ? styles.connectionDetailMuted : ''}`}
                  >
                    {line}
                  </div>
                ))}
              </div>
            )}
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
          {onOpenFileSystem && (
            <button
              className={styles.iconButton}
              onClick={onOpenFileSystem}
              title="Open Workspace (files + jobs)"
              aria-label="Open Workspace"
            >
              <FolderOpen size={14} />
            </button>
          )}
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
          loading={conversationsLoading}
          currentSessionId={sessionId}
          onBack={() => setShowHistory(false)}
          onSelect={handleSelectConversation}
          onDelete={handleDeleteConversation}
          onNewChat={handleHistoryNewChat}
          error={conversationsError}
          sharing={historySharing}
        />
      )}
    </>
  )
}
