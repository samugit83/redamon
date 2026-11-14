'use client'

import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import styles from './admin.module.css'

/** The heading every console page opens with: the section's icon, its title and lead, and the page's actions. */
export function ConsoleHeader({ icon: Icon, title, lead, actions }: {
  icon: LucideIcon
  title: ReactNode
  lead?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className={styles.header}>
      <div className={styles.headerMain}>
        <span className={styles.headerIcon} aria-hidden="true"><Icon size={20} strokeWidth={1.75} /></span>
        <div className={styles.headerText}>
          <h1 className={styles.title}>{title}</h1>
          {lead && <p className={styles.lead}>{lead}</p>}
        </div>
      </div>
      {actions && <div className={styles.headerActions}>{actions}</div>}
    </header>
  )
}
