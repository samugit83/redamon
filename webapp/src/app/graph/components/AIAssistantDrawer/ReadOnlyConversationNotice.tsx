'use client'

import { Lock, Plus } from 'lucide-react'
import type { ReadOnlyConversationView } from './hooks/useConversationRestoration'
import styles from './AIAssistantDrawer.module.css'

/**
 * In place of the composer while a read-only session is on screen (step 5.8, SH-22): another person's
 * shared session, or one reassigned from a deleted account, whose agent run cannot be continued.
 */
export function ReadOnlyConversationNotice({ view, onNewChat }: { view: ReadOnlyConversationView; onNewChat: () => void }) {
  const who = view.by ? (view.authorDeleted ? `by ${view.by} (account deleted)` : `by ${view.by}`) : null
  const why = view.authorDeleted
    ? 'Its author’s account was deleted, so it can be read but not continued.'
    : 'Shared with the project’s members to read; only its author can continue it.'
  return (
    <div className={styles.readOnlyNotice} role="status">
      <Lock size={13} aria-hidden="true" />
      <div className={styles.readOnlyNoticeText}>
        <strong>Read-only session{who ? ` ${who}` : ''}.</strong> {why}
      </div>
      <button type="button" className={styles.readOnlyNoticeButton} onClick={onNewChat}>
        <Plus size={12} aria-hidden="true" /> New session
      </button>
    </div>
  )
}
