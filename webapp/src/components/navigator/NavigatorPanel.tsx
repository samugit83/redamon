/**
 * The AI Navigator overlay (plan §9.4): not a modal (users copy from the page while chatting),
 * Escape closes it, a click outside does not. Three views: Intro (an empty conversation or no
 * project), Chat, History. Everything is scoped to the selected project: switching project ends the
 * answer in flight and shows that project's conversations.
 */
'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Compass, History, MoreHorizontal, Plus, Square, X, Send } from 'lucide-react'
import { useAlertModal } from '@/components/ui'
import { useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { IntroView, type IntroVariant } from './views/IntroView'
import { ChatView } from './views/ChatView'
import { HistoryView, type ThreadItem } from './views/HistoryView'
import { useNavigatorChat } from './useNavigatorChat'
import { ACTING_AS_NO_MODEL, navigatorMessage } from './messages'
import styles from './Navigator.module.css'

export interface ProjectNavigatorStatus {
  allowed: boolean
  reason?: string
  isOwner?: boolean
  actingAs?: boolean
  modelConfigured?: boolean
  routes?: string[]
  routeReasons?: Record<string, string>
  retentionDays?: number
}

const api = (projectId: string) => `/api/navigator/projects/${encodeURIComponent(projectId)}`

function lastKey(userId: string | null, projectId: string) {
  return `redamon.navigator.last.v1.${userId ?? 'anon'}.${projectId}`
}
function readLast(userId: string | null, projectId: string): string | null {
  try {
    return window.localStorage.getItem(lastKey(userId, projectId))
  } catch {
    return null
  }
}
function writeLast(userId: string | null, projectId: string, threadId: string | null) {
  try {
    if (threadId) window.localStorage.setItem(lastKey(userId, projectId), threadId)
    else window.localStorage.removeItem(lastKey(userId, projectId))
  } catch {
    // storage off: the panel opens the newest conversation instead
  }
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store' })
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    const code = (body as { code?: string } | null)?.code ?? null
    throw Object.assign(new Error(navigatorMessage(code, { status: res.status })), { code, status: res.status })
  }
  return body as T
}

export function NavigatorPanel({
  id, open, projectId, projectName, userId, style, onClose, onOpenAgent, agentAllowed, onAnswerDone, onResetPosition, pagePath,
}: {
  id: string
  open: boolean
  projectId: string | null
  projectName: string | null
  userId: string | null
  style: React.CSSProperties
  onClose: () => void
  onOpenAgent: () => void
  agentAllowed: boolean
  onAnswerDone: () => void
  onResetPosition: () => void
  pagePath: string
}) {
  const queryClient = useQueryClient()
  const { dangerConfirm } = useAlertModal()
  const { ensureFeatureModel } = useFeatureModelGate()
  const [view, setView] = useState<'chat' | 'history'>('chat')
  const [draft, setDraft] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  const status = useQuery({
    queryKey: ['navigator', projectId, 'status'],
    queryFn: () => getJson<ProjectNavigatorStatus>(`${api(projectId!)}/status`),
    enabled: !!projectId,
    staleTime: 30_000,
  })
  const allowed = status.data?.allowed === true
  const threads = useQuery({
    queryKey: ['navigator', projectId, 'threads'],
    queryFn: () => getJson<{ threads: ThreadItem[] }>(`${api(projectId!)}/threads`).then((b) => b.threads),
    enabled: !!projectId && allowed,
  })

  const chat = useNavigatorChat(projectId, {
    pagePath,
    onThreadCreated: (tid) => {
      if (projectId) writeLast(userId, projectId, tid)
      void queryClient.invalidateQueries({ queryKey: ['navigator', projectId, 'threads'] })
    },
    onAnswerDone: () => {
      void queryClient.invalidateQueries({ queryKey: ['navigator', projectId, 'threads'] })
      onAnswerDone()
    },
    onModelNoTools: () => {
      void ensureFeatureModel('navigator', { force: true, message: 'This model can’t call tools. Choose another.' })
    },
  })
  const { open: openThread } = chat

  // A project switch: open that project's last conversation, else its newest, else the Intro.
  const openedFor = useRef<string | null>(null)
  useEffect(() => {
    if (!projectId || !threads.data || openedFor.current === projectId) return
    openedFor.current = projectId
    const remembered = readLast(userId, projectId)
    const pick = threads.data.find((t) => t.id === remembered)?.id ?? threads.data[0]?.id ?? null
    void openThread(pick)
  }, [projectId, threads.data, userId, openThread])
  useEffect(() => {
    if (openedFor.current !== projectId) {
      void openThread(null)
      setView('chat')
    }
  }, [projectId, openThread])

  useEffect(() => {
    if (open) inputRef.current?.focus()
  }, [open])
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !document.querySelector('[role="dialog"][aria-modal="true"]')) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose, open])

  const variant: IntroVariant | null = !projectId ? 'no_project'
    : status.data && !status.data.allowed ? ((status.data.reason as IntroVariant) ?? 'navigator_not_available') : null
  const actingAsNoModel = status.data?.actingAs === true && status.data.modelConfigured === false
  const inputDisabled = !projectId || !allowed || chat.streaming || actingAsNoModel

  const send = useCallback(async (text: string) => {
    if (!text.trim()) return
    setView('chat')
    setDraft('')
    await chat.send(text)
    void queryClient.invalidateQueries({ queryKey: ['navigator', projectId, 'status'] })
  }, [chat, queryClient, projectId])

  const newConversation = useCallback(() => {
    if (projectId) writeLast(userId, projectId, null)
    void openThread(null)
    setView('chat')
    inputRef.current?.focus()
  }, [projectId, userId, openThread])

  const deleteThread = useCallback(async (tid: string) => {
    if (!projectId) return
    const ok = await dangerConfirm('Delete this conversation? This can’t be undone.', 'Delete conversation', { confirmLabel: 'Delete' })
    if (!ok) return
    await fetch(`${api(projectId)}/threads/${encodeURIComponent(tid)}`, { method: 'DELETE' }).catch(() => undefined)
    if (chat.threadId === tid) newConversation()
    void queryClient.invalidateQueries({ queryKey: ['navigator', projectId, 'threads'] })
  }, [projectId, dangerConfirm, chat.threadId, newConversation, queryClient])

  const errorText = useMemo(() => {
    if (!chat.error) return null
    return navigatorMessage(chat.error.code, { retryAfterSeconds: chat.error.retryAfterSeconds, status: chat.error.status })
  }, [chat.error])

  const statusError = status.error ? (status.error as Error).message : null

  return (
    <div id={id} role="dialog" aria-modal="false" aria-label="AI Navigator" className={styles.panel} style={style}
      data-testid="navigator-panel">
      <header className={styles.header}>
        <Compass size={16} aria-hidden />
        <span className={styles.title}>AI Navigator</span>
        <span className={styles.projectChip} title={projectName ?? undefined}>
          {status.isLoading ? <span className={styles.spinner} aria-hidden /> : (projectName ?? 'No project')}
        </span>
        <span className={styles.headerSpacer} />
        <button type="button" className={styles.iconButton} aria-label="History" aria-pressed={view === 'history'}
          disabled={!allowed} onClick={() => setView(view === 'history' ? 'chat' : 'history')}><History size={15} /></button>
        <button type="button" className={styles.iconButton} aria-label="New conversation" disabled={!allowed}
          onClick={newConversation}><Plus size={15} /></button>
        <div className={styles.menuWrap}>
          <button type="button" className={styles.iconButton} aria-label="More" aria-expanded={menuOpen}
            onClick={() => setMenuOpen((v) => !v)}><MoreHorizontal size={15} /></button>
          {menuOpen && (
            <div className={styles.menu} role="menu" onMouseLeave={() => setMenuOpen(false)}>
              <button type="button" role="menuitem" onClick={() => { setMenuOpen(false); void ensureFeatureModel('navigator', { force: true }) }}>Change model</button>
              <a role="menuitem" href="/settings?tab=models" onClick={() => setMenuOpen(false)}>Models by feature</a>
              <button type="button" role="menuitem" onClick={() => { setMenuOpen(false); onResetPosition() }}>Reset button position</button>
            </div>
          )}
        </div>
        <button type="button" className={styles.iconButton} aria-label="Close AI Navigator" onClick={onClose}><X size={15} /></button>
      </header>

      <div className={styles.body}>
        {statusError && (
          <div className={styles.inlineError}>
            AI Navigator couldn&apos;t load ({statusError}).{' '}
            <button type="button" className={styles.linkButton} onClick={() => void status.refetch()}>Retry</button>
          </div>
        )}
        {variant && <IntroView variant={variant} agentAllowed={agentAllowed} onOpenAgent={projectId ? onOpenAgent : undefined} />}
        {!variant && allowed && view === 'history' && (
          <HistoryView
            threads={threads.data ?? []}
            loading={threads.isLoading}
            error={threads.error ? (threads.error as Error).message : null}
            activeId={chat.threadId}
            retentionDays={status.data?.retentionDays ?? null}
            onOpen={(tid) => { if (projectId) writeLast(userId, projectId, tid); void openThread(tid); setView('chat') }}
            onNew={newConversation}
            onDelete={(tid) => void deleteThread(tid)}
            onRetry={() => void threads.refetch()}
          />
        )}
        {!variant && allowed && view === 'chat' && (
          chat.loading
            ? <div className={styles.chat}><div className={styles.skeleton} /><div className={styles.skeleton} /></div>
            : <ChatView
                messages={chat.messages}
                agentAllowed={agentAllowed}
                onOpenAgent={onOpenAgent}
                onRetry={(text) => void send(text)}
                empty={<IntroView agentAllowed={agentAllowed} onOpenAgent={onOpenAgent} onExample={(t) => void send(t)} />}
              />
        )}
      </div>

      {(errorText || actingAsNoModel) && (
        <div className={styles.errorBar} role="alert">
          {actingAsNoModel ? ACTING_AS_NO_MODEL : errorText}
          {chat.error?.code === 'too_many_threads' && (
            <button type="button" className={styles.linkButton} onClick={() => setView('history')}>Open History</button>
          )}
          {chat.error?.code === 'thread_full' && (
            <button type="button" className={styles.linkButton} onClick={newConversation}>New conversation</button>
          )}
          {chat.error?.code === 'busy' && chat.error.threadId && (
            <button type="button" className={styles.linkButton} onClick={() => {
              void fetch(`${api(projectId!)}/threads/${encodeURIComponent(chat.error!.threadId!)}/stop`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
              }).then(() => chat.clearError())
            }}>Stop it</button>
          )}
        </div>
      )}

      <form className={styles.inputRow} onSubmit={(e) => { e.preventDefault(); void send(draft) }}>
        <textarea
          ref={inputRef}
          className={styles.input}
          value={draft}
          maxLength={4000}
          rows={2}
          placeholder={!projectId ? 'Select a project first' : 'Ask about RedAmon or this project…'}
          disabled={inputDisabled}
          aria-label="Message AI Navigator"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              void send(draft)
            }
          }}
        />
        {chat.streaming
          ? <button type="button" className={styles.sendButton} aria-label="Stop" onClick={chat.stop}><Square size={14} /></button>
          : <button type="submit" className={styles.sendButton} aria-label="Send" disabled={inputDisabled || !draft.trim()}><Send size={14} /></button>}
      </form>
    </div>
  )
}
