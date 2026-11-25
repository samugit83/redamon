'use client'

import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton/WikiInfoButton'
import styles from './admin.module.css'

/**
 * The heading every console page opens with: the section's icon, its title and lead, and the page's actions.
 * `wiki` (a wiki-links key) adds the book icon beside the title, outside the heading so its name stays the title.
 */
export function ConsoleHeader({ icon: Icon, title, lead, actions, wiki, wikiTitle = 'Open Identity & Access Management wiki page' }: {
  icon: LucideIcon
  title: ReactNode
  lead?: ReactNode
  actions?: ReactNode
  wiki?: string
  wikiTitle?: string
}) {
  return (
    <header className={styles.header}>
      <div className={styles.headerMain}>
        <span className={styles.headerIcon} aria-hidden="true"><Icon size={20} strokeWidth={1.75} /></span>
        <div className={styles.headerText}>
          <div className={styles.titleRow}>
            <h1 className={styles.title}>{title}</h1>
            {wiki && <WikiInfoButton target={wiki} title={wikiTitle} size={15} />}
          </div>
          {lead && <p className={styles.lead}>{lead}</p>}
        </div>
      </div>
      {actions && <div className={styles.headerActions}>{actions}</div>}
    </header>
  )
}
