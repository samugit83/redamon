'use client'

import type { ReactNode } from 'react'
import type { PanelId } from './instanceView'
import { PANEL_ICONS } from './panelIcons'
import styles from './instance.module.css'

/**
 * One section of the Instance page: a labelled region whose id is the page anchor (`/admin/instance#retention`).
 * On a wide page the title and lead sit in a column beside the controls; narrower, above them.
 */
export function Panel({ id, title, lead, children }: { id: PanelId; title: string; lead?: ReactNode; children: ReactNode }) {
  const headingId = `${id}-title`
  const Icon = PANEL_ICONS[id]
  return (
    <section id={id} aria-labelledby={headingId} className={styles.panel}>
      <div className={styles.panelHead}>
        <span className={styles.panelIcon} aria-hidden="true"><Icon size={16} strokeWidth={1.75} /></span>
        <div className={styles.panelHeadText}>
          <h2 id={headingId} className={styles.panelTitle}>{title}</h2>
          {lead && <p className={styles.panelLead}>{lead}</p>}
        </div>
      </div>
      <div className={styles.panelBody}>{children}</div>
    </section>
  )
}

/** The field container: a bordered box holding one setting per row (FieldRow, CheckField, ValueRow). */
export function Rows({ children }: { children: ReactNode }) {
  return <div className={styles.rows}>{children}</div>
}

/** A checkbox whose label names it and whose hint describes it (the hint stays out of the name). */
export function CheckField({ id, label, hint, checked, onChange }: {
  id: string; label: string; hint: string; checked: boolean; onChange: (checked: boolean) => void
}) {
  return (
    <div className={`${styles.row} ${styles.rowCheck}`}>
      <input
        id={id}
        type="checkbox"
        className="checkbox"
        checked={checked}
        aria-describedby={`${id}-hint`}
        onChange={(e) => onChange(e.target.checked)}
      />
      <div className={styles.rowText}>
        <label htmlFor={id} className={styles.rowLabel}>{label}</label>
        <span id={`${id}-hint`} className={styles.rowHint}>{hint}</span>
      </div>
    </div>
  )
}

/** A labelled field: the label and its hint (or its error in the hint's place) left, the control right. */
export function FieldRow({ id, label, hint, error, children }: {
  id: string; label: string; hint: string; error?: string | null; children: ReactNode
}) {
  return (
    <div className={styles.row}>
      <div className={styles.rowText}>
        <label htmlFor={id} className={styles.rowLabel}>{label}</label>
        <span id={`${id}-hint`} className={error ? styles.rowError : styles.rowHint}>{error ?? hint}</span>
      </div>
      <div className={styles.rowControl}>{children}</div>
    </div>
  )
}

/**
 * A row whose right side is not one labelled control: a value read back, a switch, a group of
 * radios. `labelId` names the row's text, for a control that takes its name from it.
 */
export function ValueRow({ label, labelId, hint, children }: {
  label: string; labelId?: string; hint?: ReactNode; children: ReactNode
}) {
  return (
    <div className={styles.row}>
      <div className={styles.rowText}>
        <span id={labelId} className={styles.rowLabel}>{label}</span>
        {hint && <span className={styles.rowHint}>{hint}</span>}
      </div>
      <div className={styles.rowControl}>{children}</div>
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
