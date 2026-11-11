'use client'

/**
 * The four "Hostnames on target IPs" cards (04_ui_spec.md §1-§2): a native radio
 * group, so arrow keys move the selection as in any radio group, in reach order.
 *
 * The info button is a sibling of each card's <label>, never inside it: a click
 * inside a label also checks its radio, and opening help must not change the
 * mode. The pick goes back through `onModeChange` to TargetSection, which owns
 * every updateField call of the section (parity.test.ts).
 */
import { useId, useState } from 'react'
import { AlertTriangle, HelpCircle } from 'lucide-react'
import { IpHostnameModeInfoModal } from './IpHostnameModeInfoModal'
import { IP_HOSTNAME_MODES, type IpHostnameMode } from './ipHostnameModes'
import styles from './IpHostnameModeCards.module.css'

export const SCAN_ALL_THIRD_PARTY_REASON =
  'Not available for third-party engagements: an authorisation for addresses does not cover every site ' +
  'hosted on them. Use Record + scan matching with the names the client owns.'

export interface IpHostnameModeCardsProps {
  value: IpHostnameMode
  onModeChange: (mode: IpHostnameMode) => void
  /** The id of the visible "Hostnames on target IPs" label. */
  labelledBy: string
  /** D-03: scan_all is refused on a third-party engagement. */
  thirdParty?: boolean
  /** The whole form is read-only. */
  disabled?: boolean
}

export function IpHostnameModeCards({
  value, onModeChange, labelledBy, thirdParty = false, disabled = false,
}: IpHostnameModeCardsProps) {
  const [infoMode, setInfoMode] = useState<IpHostnameMode | null>(null)
  const idBase = useId()
  const disabledReasons: Partial<Record<IpHostnameMode, string>> =
    thirdParty ? { scan_all: SCAN_ALL_THIRD_PARTY_REASON } : {}

  return (
    <>
      <div className={styles.cards} role="radiogroup" aria-labelledby={labelledBy}>
        {IP_HOSTNAME_MODES.map(m => {
          const checked = value === m.mode
          const reason = disabledReasons[m.mode]
          const summaryId = `${idBase}-${m.mode}-summary`
          return (
            <div
              key={m.mode}
              className={`${styles.card} ${checked ? styles.cardChecked : ''} ${reason ? styles.cardDisabled : ''}`}
              data-mode={m.mode}
            >
              <label className={styles.cardLabel}>
                <input
                  type="radio"
                  name="ipHostnameMode"
                  value={m.mode}
                  className={styles.radio}
                  checked={checked}
                  disabled={disabled || !!reason}
                  aria-describedby={summaryId}
                  onChange={() => onModeChange(m.mode)}
                />
                <span className={styles.text}>
                  <span className={styles.head}>
                    <span className={styles.title}>{m.label}</span>
                    {m.badge && (
                      <span className={`${styles.badge} ${m.badge === 'NEEDS CONFIRM' ? styles.badgeWarn : ''}`}>
                        {m.badge === 'NEEDS CONFIRM' && <AlertTriangle size={11} aria-hidden="true" />}
                        {m.badge}
                      </span>
                    )}
                  </span>
                  <span id={summaryId} className={styles.summary}>
                    {m.summary}
                    {reason && <span className={styles.reason}> {reason}</span>}
                  </span>
                </span>
              </label>
              <button
                type="button"
                className={styles.helpButton}
                aria-label={`How '${m.label}' works`}
                aria-haspopup="dialog"
                onClick={() => setInfoMode(m.mode)}
              >
                <HelpCircle size={14} aria-hidden="true" />
                <span className={styles.helpText}>How</span>
              </button>
            </div>
          )
        })}
      </div>
      <IpHostnameModeInfoModal
        mode={infoMode}
        currentMode={value}
        onClose={() => setInfoMode(null)}
        onSelect={disabled ? undefined : onModeChange}
        disabledReasons={disabledReasons}
      />
    </>
  )
}
