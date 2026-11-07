/**
 * AI Assistant Drawer - WebSocket Version
 *
 * Thin orchestrator: wires hooks together and renders sub-components.
 * All state logic lives in hooks/; all JSX sections live in sub-components.
 */

'use client'

import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import type { ActiveSkill } from './hooks/useSendHandlers'
import styles from './AIAssistantDrawer.module.css'

// Hooks
import { useLoadingWord } from './hooks/useLoadingWord'
import { useChatState } from './hooks/useChatState'
import { useInteractionState } from './hooks/useInteractionState'
import { useScrollBehavior } from './hooks/useScrollBehavior'
import { useAttackSkillData } from './hooks/useAttackSkillData'
import { useApiKeyModal, API_KEY_INFO } from './hooks/useApiKeyModal'
import { useModelPicker } from './hooks/useModelPicker'
import { useSettingsModal } from './hooks/useSettingsModal'
import { useWebSocketHandler } from './hooks/useWebSocketHandler'
import { useConversationRestoration } from './hooks/useConversationRestoration'
import { clearProjectSession } from './sessionMemory'
import { useSendHandlers } from './hooks/useSendHandlers'
import { useDownloadMarkdown } from './hooks/useDownloadMarkdown'
import { usePendingNodeQuery } from './hooks/usePendingNodeQuery'

// External hooks
import { useAgentWebSocket } from '@/hooks/useAgentWebSocket'
import { useAgentHealth } from '@/hooks/useAgentHealth'
import { ConnectionStatus, type ConnectedPayload } from '@/lib/websocket-types'
import { useOptionalAuth } from '@/providers/AuthProvider'
import { useOptionalProject } from '@/providers/ProjectProvider'
import { loopDisplay, stampLoopStatus, type LoopStatusView } from './hooks/loopStatus'
import { useRateLimitWait } from './hooks/rateLimitWait'
import { useConversations } from '@/hooks/useConversations'
import { useChatPersistence } from '@/hooks/useChatPersistence'
import { useToast } from '@/components/ui'
import { CONVERSATION_FAILURE_TITLE, DECISION_NOT_SENT, deleteWarningsText } from './drawerNotices'

// Sub-components
import { DrawerHeader } from './DrawerHeader'
import { PhaseIndicatorBar } from './PhaseIndicatorBar'
import { SettingsModal } from './SettingsModal'
import { usePluginChatActions } from '@/components/plugins/usePluginChatActions'
import { OverrideReviewModal } from '@/components/plugins/review/OverrideReviewModal'
import { SkillVersionsModal } from '@/components/plugins/review/SkillVersionsModal'
import { isBuiltinSkill } from '@/lib/plugins/builtinSkills'
import { ModelPickerModal } from './ModelPickerModal'
import { ChatArea } from './ChatArea'
import { ApprovalDialog } from './ApprovalDialog'
import { QuestionDialog } from './QuestionDialog'
import { InputArea } from './InputArea'
import { ApiKeyModal } from './ApiKeyModal'
import { SkillDataNotice } from './SkillDataNotice'

// Types
import type { AIAssistantDrawerProps } from './types'

// Persisted drawer width (per-user via localStorage)
const WIDTH_STORAGE_KEY = 'redamon-ai-assistant-drawer-width'
const DEFAULT_WIDTH_PX = 672
const MIN_WIDTH_PX = 360
const MAX_WIDTH_PX = 1400

export function AIAssistantDrawer({
  isOpen,
  onClose,
  userId,
  projectId,
  sessionId,
  onResetSession,
  onSwitchSession,
  modelName,
  onModelChange,
  toolPhaseMap,
  stealthMode = false,
  onToggleStealth,
  onRefetchGraph,
  isOtherChainsHidden = false,
  onToggleOtherChains,
  hasOtherChains = false,
  requireToolConfirmation = true,
  graphViewCypher,
  onOpenFileSystem,
  pendingNodeQuery,
  onPendingNodeQueryConsumed,
}: AIAssistantDrawerProps) {
  // ─── State hooks ─────────────────────────────────────────────────────────────
  const [activeSkill, setActiveSkill] = useState<ActiveSkill | null>(null)
  const statusWord = useLoadingWord()
  // Agent in the Loop: the live status of this session's run (null otherwise).
  const [loopStatus, setLoopStatus] = useState<LoopStatusView | null>(null)
  useEffect(() => { setLoopStatus(null) }, [sessionId])
  // Under act-as the run is driven by the impersonated user's own token.
  const effectiveUserId = useOptionalProject()?.userId ?? null
  const signedInId = useOptionalAuth()?.user?.id
  const actingAs = Boolean(effectiveUserId && signedInId && effectiveUserId !== signedInId)
  const loop = useMemo(() => loopDisplay(loopStatus, { actingAs }), [loopStatus, actingAs])
  const toast = useToast()

  const {
    chatItems, setChatItems,
    inputValue, setInputValue,
    isLoading, setIsLoading,
    isStopped, setIsStopped,
    isStopping, setIsStopping,
    currentPhase, setCurrentPhase,
    attackPathType, setAttackPathType,
    iterationCount, setIterationCount,
    todoList, setTodoList,
    isRestoringConversation,
    itemIdCounter,
    groupedChatItems,
    resetChatState,
  } = useChatState()
  // A model call waiting for the provider's rate limit, with its countdown.
  const { setRateLimitWait, rateLimitWord } = useRateLimitWait(isLoading, sessionId)
  const isLoadingRef = useRef(isLoading)
  isLoadingRef.current = isLoading

  const {
    awaitingApproval, setAwaitingApproval,
    approvalRequest, setApprovalRequest,
    modificationText, setModificationText,
    awaitingToolConfirmation, setAwaitingToolConfirmation,
    setToolConfirmationRequest,
    awaitingQuestion, setAwaitingQuestion,
    questionRequest, setQuestionRequest,
    answerText, setAnswerText,
    selectedOptions, setSelectedOptions,
    isProcessingApproval, awaitingApprovalRef,
    isProcessingQuestion, awaitingQuestionRef,
    isProcessingToolConfirmation, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    resetInteractionState,
  } = useInteractionState()

  const {
    messagesEndRef, messagesContainerRef,
    shouldAutoScroll,
    scrollToBottom, checkIfAtBottom, resetScrollState,
  } = useScrollBehavior(chatItems)

  const { skillData, refetch: refetchSkillData, error: skillDataError } = useAttackSkillData(userId, projectId)

  const {
    missingApiKeys,
    apiKeyModal,
    apiKeyValue, setApiKeyValue,
    apiKeyVisible, setApiKeyVisible,
    apiKeySaving,
    openApiKeyModal, closeApiKeyModal, saveApiKey,
    fetchApiKeyStatus,
  } = useApiKeyModal(userId)

  const {
    showModelModal, setShowModelModal,
    modelSearch, setModelSearch,
    modelsLoading, modelsError,
    filteredModels,
    handleSelectModel,
    modelSearchRef,
  } = useModelPicker(userId, onModelChange)

  const {
    showSettingsDropdown, setShowSettingsDropdown,
    settingsModal, setSettingsModal,
    projectFormData, updateProjectField,
    settingsDropdownRef,
    projectLoadError,
  } = useSettingsModal(projectId)

  // Plugin chat-session actions from the gear menu (design §6.7): the review modal (step 6.5)
  // and the core versions modal (step 6.6). The versions modal opens on the session's skill
  // (attackPathType), built-in or the person's own, so they land on the right skill.
  const [reviewChangeSetId, setReviewChangeSetId] = useState<string | null>(null)
  const [versionsFor, setVersionsFor] = useState<{ projectId: string | null; initialSkill?: string } | null>(null)
  const { run: runPluginChatAction, modals: pluginChatModals } = usePluginChatActions({
    onReviewProposal: (changeSetId) => setReviewChangeSetId(changeSetId),
    onCoreScreen: (screen, context) => {
      if (screen === 'skill.text.versions') {
        const sessionSkill = attackPathType.startsWith('user_skill:') || isBuiltinSkill(attackPathType) ? attackPathType : undefined
        setVersionsFor({ projectId: context.projectId ?? null, initialSkill: sessionSkill })
      }
    },
  })

  // ─── Conversation persistence ─────────────────────────────────────────────
  const {
    conversations,
    loading: conversationsLoading,
    error: conversationsError,
    fetchConversations,
    createConversation,
    deleteConversation,
    loadConversation,
  } = useConversations(projectId, userId, {
    // The list is polled while the history is open: its failure is shown there, not toasted every 5s.
    onError: (action, err) => {
      if (action !== 'list') toast.error(err.message, CONVERSATION_FAILURE_TITLE[action])
    },
    onDeleteWarnings: (warnings) => toast.warning(deleteWarningsText(warnings), 'Session deleted with warnings'),
  })

  // ─── handleNewChat (cross-cutting - touches state from multiple hooks) ─────
  // Defined before useConversationRestoration via a stable ref pattern
  const handleNewChatRef = useRef<() => void>(() => {})
  const updateConvMetaRef = useRef<(updates: Record<string, any>) => Promise<void>>(async () => {})

  // ─── Conversation restoration ──────────────────────────────────────────────
  const {
    conversationId, setConversationId,
    showHistory, setShowHistory,
    handleSelectConversation,
    resyncActiveConversation,
    handleHistoryNewChat,
    handleDeleteConversation,
    restoreForProject,
  } = useConversationRestoration({
    loadConversation,
    deleteConversation,
    fetchConversations,
    onSwitchSession,
    onRefetchGraph,
    projectId,
    userId,
    setChatItems,
    setCurrentPhase,
    setAttackPathType,
    setIterationCount,
    setIsLoading,
    setIsStopped,
    setIsStopping,
    setTodoList,
    isRestoringConversation,
    shouldAutoScroll,
    setAwaitingApproval,
    setApprovalRequest,
    setAwaitingQuestion,
    setQuestionRequest,
    setAwaitingToolConfirmation,
    setToolConfirmationRequest,
    awaitingApprovalRef,
    awaitingQuestionRef,
    awaitingToolConfirmationRef,
    pendingApprovalToolId,
    pendingApprovalWaveId,
    setActiveSkill,
    updateConvMeta: useCallback((updates: Record<string, any>) => updateConvMetaRef.current(updates), []),
    handleNewChat: useCallback(() => handleNewChatRef.current(), []),
    notifyError: useCallback((message: string) => toast.error(message), [toast]),
  })

  const { saveMessage, updateConversation: updateConvMeta } = useChatPersistence(conversationId)

  // Keep ref up-to-date for useConversationRestoration
  useEffect(() => { updateConvMetaRef.current = updateConvMeta }, [updateConvMeta])

  // Now that we have setConversationId and setShowHistory, define handleNewChat
  const handleNewChat = useCallback(() => {
    resetChatState()
    resetInteractionState()
    resetScrollState()
    setConversationId(null)
    setShowHistory(false)
    setActiveSkill(null)
    // Explicit "new chat": forget this project's saved session so a later
    // switch back starts fresh rather than reopening the abandoned chat.
    clearProjectSession(projectId)
    onResetSession?.()
  }, [resetChatState, resetInteractionState, resetScrollState, setConversationId, setShowHistory, setActiveSkill, onResetSession, projectId])

  // Keep ref up-to-date
  useEffect(() => { handleNewChatRef.current = handleNewChat }, [handleNewChat])

  // ─── WebSocket ────────────────────────────────────────────────────────────
  const { handleWebSocketMessage } = useWebSocketHandler({
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
    onGraphMutation: onRefetchGraph,
    setLoopStatus,
    setRateLimitWait,
  })

  const {
    status, isConnected, reconnectAttempt,
    error: socketError, lastClose, url: socketUrl,
    sendQuery, sendGuidance, sendApproval, sendToolConfirmation,
    sendFireteamMemberConfirmation,
    sendAnswer, sendSkillInject, sendStop, sendResume, sendToolStop,
  } = useAgentWebSocket({
    userId,
    projectId,
    sessionId,
    graphViewCypher,
    // A run keeps the socket open with the drawer closed: closing it dropped
    // every event of the run until the drawer reopened.
    enabled: isOpen || isLoading,
    runActive: isLoading,
    onMessage: handleWebSocketMessage,
    // On every (re)connect, reconcile with the server: re-read the timeline
    // (the backend flushed its persist queue first) whenever a run is or was
    // believed to be going, and take the spinner state from the server's live
    // agent_running instead of trusting events that may have been lost.
    onConnect: useCallback((payload: ConnectedPayload) => {
      setLoopStatus(stampLoopStatus(payload?.loop_state, Date.now()))
      resyncActiveConversation(sessionId, {
        agentRunning: payload?.agent_running,
        clientRunning: isLoadingRef.current,
        isRunActive: () => isLoadingRef.current,
      })
    }, [resyncActiveConversation, sessionId]),
  })

  // The agent's own health answer (container down vs. refusing) once the socket gave up.
  const agentHealth = useAgentHealth({ enabled: status === ConnectionStatus.FAILED })

  // ─── Send handlers ────────────────────────────────────────────────────────
  const {
    inputRef,
    handleSend,
    sendNodeContextQuery,
    handleApproval,
    handleTimelineToolConfirmation,
    handleAnswer,
    handleStop,
    handleResume,
    handleToolStop,
    handleKeyDown,
    handleInputChange,
    activateSkill,
    userResizedRef,
  } = useSendHandlers({
    inputValue, setInputValue,
    isLoading, setIsLoading, setIsStopped, setIsStopping,
    setChatItems, chatItems,
    activeSkill, setActiveSkill,
    awaitingApproval, setAwaitingApproval, setApprovalRequest, modificationText, setModificationText,
    awaitingQuestion, setAwaitingQuestion, questionRequest, setQuestionRequest,
    answerText, setAnswerText, selectedOptions, setSelectedOptions,
    awaitingToolConfirmation, setAwaitingToolConfirmation, setToolConfirmationRequest,
    isProcessingApproval, awaitingApprovalRef,
    isProcessingQuestion, awaitingQuestionRef,
    isProcessingToolConfirmation, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    sendQuery, sendGuidance, sendSkillInject, sendApproval, sendToolConfirmation, sendFireteamMemberConfirmation, sendAnswer, sendStop, sendResume, sendToolStop,
    conversationId, setConversationId, projectId, userId, sessionId,
    createConversation, saveMessage, updateConvMeta,
  })

  // A decision made while the socket is down would be shown as sent and never
  // reach the agent; the pending request stays open until the connection is back.
  const isConnectedRef = useRef(isConnected)
  isConnectedRef.current = isConnected
  const guardedApproval = useCallback((decision: 'approve' | 'modify' | 'abort') => {
    if (!isConnectedRef.current) { toast.error(DECISION_NOT_SENT, 'Not connected'); return }
    handleApproval(decision)
  }, [handleApproval, toast])
  const guardedAnswer = useCallback(() => {
    if (!isConnectedRef.current) { toast.error(DECISION_NOT_SENT, 'Not connected'); return }
    handleAnswer()
  }, [handleAnswer, toast])
  const guardedToolConfirmation = useCallback((itemId: string, decision: 'approve' | 'reject') => {
    if (!isConnectedRef.current) { toast.error(DECISION_NOT_SENT, 'Not connected'); return }
    handleTimelineToolConfirmation(itemId, decision)
  }, [handleTimelineToolConfirmation, toast])

  // ─── Markdown download ────────────────────────────────────────────────────
  const { handleDownloadMarkdown } = useDownloadMarkdown({
    chatItems,
    currentPhase,
    iterationCount,
    modelName: modelName ?? '',
    todoList,
    sessionId,
  })

  // ─── Side effects ─────────────────────────────────────────────────────────
  // Fetch API key status when connected
  useEffect(() => {
    if (isConnected) fetchApiKeyStatus()
  }, [isConnected, fetchApiKeyStatus])

  // Focus input + force scroll when drawer opens
  useEffect(() => {
    if (isOpen && inputRef.current && !awaitingApproval) {
      setTimeout(() => {
        inputRef.current?.focus()
        scrollToBottom(true)
      }, 300)
    }
  }, [isOpen, awaitingApproval, scrollToBottom, inputRef])

  // Node-scoped first message ("Ask agent" in the node drawer). Declared
  // before the session-reset effect below, which clears the chat on the new
  // sessionId before the fresh socket connects and this sends.
  usePendingNodeQuery({
    pendingNodeQuery,
    isConnected,
    send: sendNodeContextQuery,
    onConsumed: onPendingNodeQueryConsumed,
    onArmed: useCallback(() => setShowHistory(false), [setShowHistory]),
  })

  // Reset state when session changes (skip when restoring a conversation)
  useEffect(() => {
    if (isRestoringConversation.current) {
      isRestoringConversation.current = false
      return
    }
    resetChatState()
    resetInteractionState()
    resetScrollState()
    setConversationId(null)
    setActiveSkill(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // Per-project session memory: when the current project actually changes,
  // restore THAT project's last-open session (or a fresh chat), so the previous
  // project's conversation never leaks in. Skips the initial mount so opening
  // the drawer for the first time keeps its existing blank behavior.
  const prevProjectIdRef = useRef<string | null>(null)
  useEffect(() => {
    const prev = prevProjectIdRef.current
    prevProjectIdRef.current = projectId
    if (prev === null || prev === projectId || !projectId) return
    restoreForProject()
  }, [projectId, restoreForProject])

  // ─── Drawer width (persisted per-user, drag handle on left edge) ───────────
  const [drawerWidth, setDrawerWidth] = useState<number>(() => {
    if (typeof window === 'undefined') return DEFAULT_WIDTH_PX
    const raw = window.localStorage.getItem(WIDTH_STORAGE_KEY)
    if (!raw) return DEFAULT_WIDTH_PX
    const n = parseInt(raw, 10)
    if (!Number.isFinite(n)) return DEFAULT_WIDTH_PX
    return Math.min(Math.max(n, MIN_WIDTH_PX), MAX_WIDTH_PX)
  })
  const [isResizing, setIsResizing] = useState(false)
  const lastWidthRef = useRef<number>(drawerWidth)

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    setIsResizing(true)
  }, [])

  useEffect(() => {
    if (!isResizing) return
    const handleMouseMove = (e: MouseEvent) => {
      const raw = window.innerWidth - e.clientX
      const clamped = Math.min(Math.max(raw, MIN_WIDTH_PX), MAX_WIDTH_PX)
      lastWidthRef.current = clamped
      setDrawerWidth(clamped)
    }
    const handleMouseUp = () => {
      setIsResizing(false)
      try {
        window.localStorage.setItem(WIDTH_STORAGE_KEY, String(Math.round(lastWidthRef.current)))
      } catch {
        // localStorage unavailable - width still applies for the session.
      }
    }
    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
    const prevUserSelect = document.body.style.userSelect
    const prevCursor = document.body.style.cursor
    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'col-resize'
    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      document.body.style.userSelect = prevUserSelect
      document.body.style.cursor = prevCursor
    }
  }, [isResizing])

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div
      className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''} ${isResizing ? styles.drawerResizing : ''}`}
      style={{ width: `${drawerWidth}px` }}
      aria-hidden={!isOpen}
    >
      {isOpen && (
        <div
          className={styles.resizeHandle}
          onMouseDown={handleResizeStart}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize drawer"
        />
      )}
      <DrawerHeader
        status={status}
        reconnectAttempt={reconnectAttempt}
        sessionId={sessionId}
        requireToolConfirmation={requireToolConfirmation}
        hasOtherChains={hasOtherChains}
        isOtherChainsHidden={isOtherChainsHidden}
        onToggleOtherChains={onToggleOtherChains}
        showHistory={showHistory}
        setShowHistory={setShowHistory}
        handleNewChat={handleNewChat}
        handleDownloadMarkdown={handleDownloadMarkdown}
        chatItems={chatItems}
        onClose={onClose}
        onOpenFileSystem={onOpenFileSystem}
        conversations={conversations}
        conversationsLoading={conversationsLoading}
        handleSelectConversation={handleSelectConversation}
        handleDeleteConversation={handleDeleteConversation}
        handleHistoryNewChat={handleHistoryNewChat}
        connectionError={socketError?.message ?? null}
        lastClose={lastClose}
        socketUrl={socketUrl}
        agentHealthError={agentHealth.status === 'offline' ? agentHealth.error : null}
        conversationsError={conversationsError}
      />

      <PhaseIndicatorBar
        currentPhase={currentPhase}
        toolPhaseMap={toolPhaseMap}
        attackPathType={attackPathType}
        skillData={skillData}
        iterationCount={iterationCount}
        stealthMode={stealthMode}
        onToggleStealth={onToggleStealth}
        settingsDropdownRef={settingsDropdownRef}
        showSettingsDropdown={showSettingsDropdown}
        setShowSettingsDropdown={setShowSettingsDropdown}
        setSettingsModal={setSettingsModal}
        modelName={modelName}
        setShowModelModal={setShowModelModal}
        projectId={projectId}
        sessionId={sessionId}
        conversationId={conversationId}
        onRunPluginAction={runPluginChatAction}
      />

      <SkillDataNotice error={skillDataError} />

      {pluginChatModals}

      {reviewChangeSetId && (
        <OverrideReviewModal
          changeSetId={reviewChangeSetId}
          scopeOwnerId={userId}
          projectId={projectId}
          onClose={() => setReviewChangeSetId(null)}
          onDecided={(outcome) => {
            setReviewChangeSetId(null)
            if (outcome === 'saved') refetchSkillData()
          }}
        />
      )}

      {versionsFor && (
        <SkillVersionsModal
          projectId={versionsFor.projectId}
          initialSkill={versionsFor.initialSkill}
          scopeOwnerId={userId}
          onClose={() => setVersionsFor(null)}
          onOpenReview={(changeSetId) => { setVersionsFor(null); setReviewChangeSetId(changeSetId) }}
          onReviewAgain={(changeSetId) => { setVersionsFor(null); setReviewChangeSetId(changeSetId) }}
        />
      )}

      <SettingsModal
        settingsModal={settingsModal}
        setSettingsModal={setSettingsModal}
        projectFormData={projectFormData}
        updateProjectField={updateProjectField}
        projectId={projectId}
        loadError={projectLoadError}
      />

      <ModelPickerModal
        showModelModal={showModelModal}
        setShowModelModal={setShowModelModal}
        modelSearch={modelSearch}
        setModelSearch={setModelSearch}
        modelSearchRef={modelSearchRef}
        modelsLoading={modelsLoading}
        modelsError={modelsError}
        filteredModels={filteredModels}
        modelName={modelName}
        onModelChange={onModelChange}
        handleSelectModel={handleSelectModel}
      />

      <ChatArea
        messagesContainerRef={messagesContainerRef}
        messagesEndRef={messagesEndRef}
        checkIfAtBottom={checkIfAtBottom}
        chatItems={chatItems}
        groupedChatItems={groupedChatItems}
        isLoading={isLoading}
        todoList={todoList}
        statusWord={statusWord}
        isConnected={isConnected}
        setInputValue={setInputValue}
        missingApiKeys={missingApiKeys}
        openApiKeyModal={openApiKeyModal}
        handleTimelineToolConfirmation={guardedToolConfirmation}
        handleToolStop={handleToolStop}
        loop={loop}
        rateLimitWord={rateLimitWord}
      />

      <ApprovalDialog
        awaitingApproval={awaitingApproval}
        approvalRequest={approvalRequest}
        modificationText={modificationText}
        isLoading={isLoading}
        isConnected={isConnected}
        setModificationText={setModificationText}
        handleApproval={guardedApproval}
      />

      <QuestionDialog
        awaitingQuestion={awaitingQuestion}
        questionRequest={questionRequest}
        answerText={answerText}
        selectedOptions={selectedOptions}
        isLoading={isLoading}
        setAnswerText={setAnswerText}
        setSelectedOptions={setSelectedOptions}
        handleAnswer={guardedAnswer}
        isConnected={isConnected}
      />

      <InputArea
        inputRef={inputRef}
        inputValue={inputValue}
        handleInputChange={handleInputChange}
        handleKeyDown={handleKeyDown}
        handleSend={handleSend}
        handleStop={handleStop}
        handleResume={handleResume}
        isConnected={isConnected}
        isLoading={isLoading}
        isStopped={isStopped}
        isStopping={isStopping}
        awaitingApproval={awaitingApproval}
        awaitingQuestion={awaitingQuestion}
        awaitingToolConfirmation={awaitingToolConfirmation}
        userId={userId}
        setInputValue={setInputValue}
        activeSkill={activeSkill}
        setActiveSkill={setActiveSkill}
        onSkillActivate={activateSkill}
        userResizedRef={userResizedRef}
      />

      <ApiKeyModal
        apiKeyModal={apiKeyModal}
        apiKeyInfo={API_KEY_INFO}
        apiKeyValue={apiKeyValue}
        apiKeyVisible={apiKeyVisible}
        apiKeySaving={apiKeySaving}
        setApiKeyValue={setApiKeyValue}
        setApiKeyVisible={setApiKeyVisible}
        closeApiKeyModal={closeApiKeyModal}
        saveApiKey={saveApiKey}
      />
    </div>
  )
}
