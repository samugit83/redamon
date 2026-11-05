/**
 * AgentStatusChips - live KPI chips for the Todos bar.
 *
 * At-a-glance signals of agent behaviour:
 *   1. Loop risk score + tier (health)         - Zap
 *   2. Discovery stall (turns since a finding)  - Radar
 *   3. LATS status (reasoning mode)             - Network
 *   4. Agent in the Loop, and a red ShieldAlert when that run has tool
 *      confirmation off (dangerous tools run without asking)  - Cable
 *
 * All values are derived by ChatArea from data it already holds (the latest
 * thinking item carries score/tier/stall; the latest running LATS item carries
 * rollouts/budget), so this component is a pure presenter.
 */

'use client'

import { Zap, Radar, Network, Cable, ShieldAlert } from 'lucide-react'
import {
  LOOP_CHIP_LABEL,
  LOOP_CHIP_TOOLTIP,
  LOOP_UNATTENDED_LABEL,
  LOOP_UNATTENDED_TOOLTIP,
} from './hooks/loopStatus'
import styles from './AgentStatusChips.module.css'

interface AgentStatusChipsProps {
  score?: number | null
  tier?: string | null
  stall?: number | null
  latsActive: boolean
  latsRollouts?: number
  latsBudget?: number
  /** The run's model calls are answered by Agent in the Loop. */
  loopActive?: boolean
  /** That loop run has tool confirmation off: dangerous tools run unattended. */
  loopUnattended?: boolean
}

// Stall turns at/above which the chip warns (matches the LATS re-activation
// floor - this is when the meta-controllers start to re-engage).
const STALL_WARN = 5

export function AgentStatusChips({
  score,
  tier,
  stall,
  latsActive,
  latsRollouts,
  latsBudget,
  loopActive = false,
  loopUnattended = false,
}: AgentStatusChipsProps) {
  const hasScore = typeof score === 'number' && !Number.isNaN(score)
  const tierClass = tier ? styles[`tier_${tier}`] || '' : ''
  const stallClass =
    typeof stall === 'number' && stall >= STALL_WARN ? styles.stallWarn : ''

  return (
    <div className={styles.chips}>
      {/* 1. Loop risk health */}
      <span
        className={`${styles.chip} ${tierClass}`}
        title={
          hasScore
            ? `Loop risk ${score!.toFixed(1)}${tier ? ` (${tier})` : ''} - higher is worse`
            : 'Loop risk - waiting for first score'
        }
      >
        <Zap size={12} className={styles.icon} />
        <span className={styles.value}>{hasScore ? score!.toFixed(1) : '-'}</span>
      </span>

      {/* 2. Discovery stall */}
      <span
        className={`${styles.chip} ${stallClass}`}
        title={
          typeof stall === 'number'
            ? `${stall} think turn${stall === 1 ? '' : 's'} since a new finding`
            : 'Turns since a new finding'
        }
      >
        <Radar size={12} className={styles.icon} />
        <span className={styles.value}>{typeof stall === 'number' ? stall : '-'}</span>
      </span>

      {/* 3. LATS reasoning mode */}
      <span
        className={`${styles.chip} ${latsActive ? styles.latsActive : styles.latsIdle}`}
        title={
          latsActive
            ? `LATS tree search active - ${latsRollouts ?? 0}/${latsBudget ?? 0} rollouts`
            : 'LATS idle (normal ReAct)'
        }
      >
        <Network size={12} className={styles.icon} />
        <span className={styles.value}>
          {latsActive ? `${latsRollouts ?? 0}/${latsBudget ?? 0}` : 'idle'}
        </span>
      </span>

      {/* 4. Agent in the Loop */}
      {loopActive && (
        <span className={`${styles.chip} ${styles.latsActive}`} title={LOOP_CHIP_TOOLTIP}>
          <Cable size={12} className={styles.icon} />
          <span className={styles.value}>{LOOP_CHIP_LABEL}</span>
        </span>
      )}
      {loopActive && loopUnattended && (
        <span
          className={styles.unattended}
          role="img"
          aria-label={LOOP_UNATTENDED_LABEL}
          title={LOOP_UNATTENDED_TOOLTIP}
        >
          <ShieldAlert size={14} />
        </span>
      )}
    </div>
  )
}
