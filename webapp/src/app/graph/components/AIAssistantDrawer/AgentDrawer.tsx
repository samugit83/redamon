'use client'

import { Bot } from 'lucide-react'
import { usePermissionRefused } from '@/hooks/useCan'
import { ForbiddenNotice } from '@/components/auth/ForbiddenNotice'
import { AIAssistantDrawer } from './AIAssistantDrawer'
import type { AIAssistantDrawerProps } from './types'
import styles from './AIAssistantDrawer.module.css'

/**
 * The agent drawer the graph page mounts (step 3.16b, UI-12): the chat, or, for someone whose set
 * lacks agent:chat with the permissions switch on, the same drawer holding only the ForbiddenNotice.
 * The chat is then not mounted at all, so nothing of it is asked: no socket ticket (the ticket route
 * asks agent:chat), conversation list, keys or models. With the switch off, as before (DV-30).
 */
export function AgentDrawer(props: AIAssistantDrawerProps) {
  const refused = usePermissionRefused('agent:chat', props.projectId || null)
  if (refused) return <RefusedAgentDrawer isOpen={props.isOpen} onClose={props.onClose} />
  return <AIAssistantDrawer {...props} />
}

function RefusedAgentDrawer({ isOpen, onClose }: Pick<AIAssistantDrawerProps, 'isOpen' | 'onClose'>) {
  return (
    <div className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`} aria-hidden={!isOpen}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <div className={styles.headerIcon}>
            <Bot size={16} />
          </div>
          <div className={styles.headerText}>
            <h2 className={styles.title}>AI Agent</h2>
          </div>
        </div>
        <div className={styles.headerActions}>
          <button className={styles.closeButton} onClick={onClose} aria-label="Close assistant">
            &times;
          </button>
        </div>
      </div>
      <div className={styles.messages}>
        <ForbiddenNotice permission="agent:chat" />
      </div>
    </div>
  )
}
