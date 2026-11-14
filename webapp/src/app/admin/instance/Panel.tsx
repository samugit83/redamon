'use client'

import type { ReactNode } from 'react'
import type { PanelId } from './instanceView'
import { PANEL_ICONS } from './panelIcons'
import styles from './instance.module.css'

/**
 * One section of the Instance page: a labelled region whose id is the page anchor (`/admin/instance#tunnels`).
 * On a wide page the title and lead sit in a column beside the controls; narrower, above them.
 */
export function Panel({ id, title, lead, children }: { id: PanelId; title: string; lead?: ReactNode; children: ReactNode }) {
  const headingId = `${id}-title`
  const Icon = PANEL_ICONS[id]
  return (
    <section id={id} aria-labelledby={headingId} className={styles.panel}>
      <div className={styles.panelHead}>
        <span className={styles.panelIcon} aria-hidden="true"><Icon size={18} strokeWidth={1.75} /></span>
        <div className={styles.panelHeadText}>
          <h2 id={headingId} className={styles.panelTitle}>{title}</h2>
          {lead && <p className={styles.panelLead}>{lead}</p>}
        </div>
      </div>
      <div className={styles.panelBody}>{children}</div>
    </section>
  )
}

/** A checkbox whose label names it and whose hint describes it (the hint stays out of the name). */
export function CheckField({ id, label, hint, checked, onChange }: {
  id: string; label: string; hint: string; checked: boolean; onChange: (checked: boolean) => void
}) {
  return (
    <div className={styles.check}>
      <input id={id} type="checkbox" checked={checked} aria-describedby={`${id}-hint`} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <label htmlFor={id}>{label}</label>
        <br />
        <span id={`${id}-hint`} className={styles.hint}>{hint}</span>
      </span>
    </div>
  )
}

/** A labelled field: the label, the control, then its hint, or its error in the hint's place. */
export function FieldRow({ id, label, hint, error, children }: {
  id: string; label: string; hint: string; error?: string | null; children: ReactNode
}) {
  return (
    <div className={styles.field}>
      <label htmlFor={id}>{label}</label>
      {children}
      <span id={`${id}-hint`} className={error ? styles.fieldError : styles.hint}>{error ?? hint}</span>
    </div>
  )
}

/**
 * Why a Root-only panel is read-only: an administrator reads it, the confirmed Root changes it,
 * and a Root the boot chose automatically learns what makes it able to.
 */
export function RootOnlyNote({ unconfirmedRoot }: { unconfirmedRoot: boolean }) {
  return (
    <p className={styles.note} role="note">
      {unconfirmedRoot
        ? 'You are Root, chosen automatically: you change these once the host confirms you (./redamon.sh set-root <email>, or ./redamon.sh update).'
        : 'Only Root changes these settings.'}
    </p>
  )
}
