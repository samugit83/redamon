'use client'

import { Trash2, Plus } from 'lucide-react'
import styles from '../Navigator.module.css'

export interface ThreadItem {
  id: string
  title: string
  lastMessageAt: string
}

function relative(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  const min = Math.round(ms / 60_000)
  if (min < 1) return 'just now'
  if (min < 60) return `${min} min ago`
  const h = Math.round(min / 60)
  if (h < 24) return `${h} h ago`
  const d = Math.round(h / 24)
  return d === 1 ? 'yesterday' : `${d} days ago`
}

/** The person's conversations on the current project (plan §9.10). */
export function HistoryView({ threads, loading, error, activeId, retentionDays, onOpen, onNew, onDelete, onRetry }: {
  threads: readonly ThreadItem[]
  loading: boolean
  error: string | null
  activeId: string | null
  retentionDays: number | null
  onOpen: (id: string) => void
  onNew: () => void
  onDelete: (id: string) => void
  onRetry: () => void
}) {
  return (
    <div className={styles.history} data-testid="navigator-history">
      <button type="button" className={styles.newButton} onClick={onNew}><Plus size={14} /> New conversation</button>
      {loading && (
        <ul className={styles.threadList} aria-busy="true">
          {[0, 1, 2].map((i) => <li key={i} className={styles.skeleton} />)}
        </ul>
      )}
      {!loading && error && (
        <div className={styles.inlineError}>{error} <button type="button" className={styles.linkButton} onClick={onRetry}>Retry</button></div>
      )}
      {!loading && !error && threads.length === 0 && <p className={styles.muted}>No conversations on this project yet.</p>}
      {!loading && !error && threads.length > 0 && (
        <ul className={styles.threadList}>
          {threads.map((t) => (
            <li key={t.id} className={t.id === activeId ? styles.threadActive : undefined}>
              <button type="button" className={styles.threadOpen} onClick={() => onOpen(t.id)} title={t.title}>
                <span className={styles.threadTitle}>{t.title || 'Untitled conversation'}</span>
                <span className={styles.threadTime}>{relative(t.lastMessageAt)}</span>
              </button>
              <button type="button" className={styles.iconButton} aria-label={`Delete ${t.title || 'conversation'}`} onClick={() => onDelete(t.id)}>
                <Trash2 size={14} />
              </button>
            </li>
          ))}
        </ul>
      )}
      {retentionDays !== null && (
        <p className={styles.footerNote}>Conversations are deleted after {retentionDays} {retentionDays === 1 ? 'day' : 'days'} without activity.</p>
      )}
    </div>
  )
}
