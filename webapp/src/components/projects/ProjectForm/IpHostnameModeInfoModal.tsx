'use client'

/**
 * "How '<mode>' works": the info modal of one hostname mode (04_ui_spec.md §3).
 * Sections in a fixed order, read from ipHostnameModes.ts; the footer toggles a
 * table comparing all four modes and can pick the mode it explains.
 *
 * Safe nested inside WorkflowNodeModal: that modal ignores Escape, and this one
 * is portalled, so Escape closes only this one and the shared Modal returns
 * focus to the info button that opened it.
 */
import { useId, useState, useSyncExternalStore } from 'react'
import { Modal } from '@/components/ui'
import { IpHostnameDiagram } from './IpHostnameDiagram'
import {
  IP_HOSTNAME_COMPARISON, IP_HOSTNAME_MODES, type IpHostnameMode, ipHostnameModeInfo,
} from './ipHostnameModes'
import styles from './IpHostnameModeInfoModal.module.css'

const NARROW_QUERY = '(max-width: 639px)'

const narrowQuery = () => (typeof window.matchMedia === 'function' ? window.matchMedia(NARROW_QUERY) : null)

function subscribeNarrow(onChange: () => void): () => void {
  const mq = narrowQuery()
  mq?.addEventListener?.('change', onChange)
  return () => mq?.removeEventListener?.('change', onChange)
}

/** Below 640 px the modal takes the whole screen (§8). */
function useNarrowViewport(): boolean {
  return useSyncExternalStore(subscribeNarrow, () => narrowQuery()?.matches ?? false, () => false)
}

export interface IpHostnameModeInfoModalProps {
  /** The mode to explain; null when closed. */
  mode: IpHostnameMode | null
  onClose: () => void
  /** The project's current mode, so "Use this mode" says when it already is. */
  currentMode?: IpHostnameMode
  /** Picks the mode; absent when the form is read-only. */
  onSelect?: (mode: IpHostnameMode) => void
  /** Why a mode cannot be picked here (scan_all on a third-party engagement). */
  disabledReasons?: Partial<Record<IpHostnameMode, string>>
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const id = useId()
  return (
    <section className={styles.section} aria-labelledby={id}>
      <h3 id={id} className={styles.heading}>{title}</h3>
      {children}
    </section>
  )
}

export function IpHostnameModeInfoModal({
  mode, onClose, currentMode, onSelect, disabledReasons = {},
}: IpHostnameModeInfoModalProps) {
  const narrow = useNarrowViewport()
  const [compare, setCompare] = useState(false)
  const compareId = useId()
  if (!mode) return null

  // Each opening starts on the mode's own explanation, not a table left open.
  const close = () => {
    setCompare(false)
    onClose()
  }

  const info = ipHostnameModeInfo(mode)
  const disabledReason = disabledReasons[info.mode] ?? null
  const inUse = currentMode === info.mode

  return (
    <Modal
      isOpen
      onClose={close}
      title={`How '${info.label}' works`}
      size={narrow ? 'full' : 'large'}
      className={styles.modal}
      footer={(
        <div className={styles.footer}>
          <button
            type="button"
            className="secondaryButton"
            aria-expanded={compare}
            aria-controls={compareId}
            onClick={() => setCompare(v => !v)}
          >
            {compare ? 'Hide the comparison' : 'Compare all four modes'}
          </button>
          <span className={styles.footerSpacer} />
          {onSelect && (
            <button
              type="button"
              className="primaryButton"
              disabled={inUse || disabledReason !== null}
              title={disabledReason ?? (inUse ? 'This is the current mode' : undefined)}
              onClick={() => { onSelect(info.mode); close() }}
            >
              {inUse ? 'In use' : 'Use this mode'}
            </button>
          )}
          <button type="button" className="secondaryButton" onClick={close}>Close</button>
        </div>
      )}
    >
      <div className={styles.body} data-mode={info.mode}>
        {disabledReason && <p className={styles.danger} role="note">{disabledReason}</p>}

        <Section title="In one sentence">
          <p className={styles.sentence}>{info.sentence}</p>
        </Section>

        <Section title="Diagram">
          <IpHostnameDiagram mode={info.mode} />
        </Section>

        <Section title="What RedAmon does">
          <ol className={styles.list}>
            {info.steps.map(s => <li key={s}>{s}</li>)}
          </ol>
        </Section>

        <Section title="What you will see in the graph">
          <ul className={styles.list}>
            {info.graph.map(s => <li key={s}>{s}</li>)}
          </ul>
        </Section>

        <Section title="Traffic">
          <dl className={styles.traffic}>
            <dt>Your IPs</dt>
            <dd>{info.traffic.targets}</dd>
            <dt>Lookups</dt>
            <dd>{info.traffic.lookups}</dd>
          </dl>
          <ul className={styles.list}>
            {info.guarantees.map(s => <li key={s}>{s}</li>)}
          </ul>
          {info.warning && <p className={styles.danger}>{info.warning}</p>}
        </Section>

        <div className={styles.columns}>
          <Section title="When to use">
            <ul className={styles.list}>
              {info.whenToUse.map(s => <li key={s}>{s}</li>)}
            </ul>
          </Section>
          <Section title="When not to use">
            <ul className={styles.list}>
              {info.whenNotToUse.map(s => <li key={s}>{s}</li>)}
            </ul>
          </Section>
        </div>

        <Section title="Example">
          <p className={styles.sentence}>{info.example.setup}</p>
          <ul className={styles.list}>
            {info.example.outcome.map(s => <li key={s}>{s}</li>)}
          </ul>
        </Section>

        <div id={compareId} hidden={!compare}>
          {compare && (
            <Section title="All four modes compared">
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <thead>
                    <tr>
                      <td />
                      {IP_HOSTNAME_MODES.map(m => (
                        <th key={m.mode} scope="col" aria-current={m.mode === info.mode ? 'true' : undefined}>
                          {m.label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {IP_HOSTNAME_COMPARISON.map(row => (
                      <tr key={row.question}>
                        <th scope="row">{row.question}</th>
                        {IP_HOSTNAME_MODES.map(m => <td key={m.mode}>{row.answers[m.mode]}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}
        </div>
      </div>
    </Modal>
  )
}
