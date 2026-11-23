import { HOLD_MAX_NO_USE_S, HOLD_WARN_BEFORE_S } from '@/lib/sandbox/contract'

/** Hours without use after which a sandbox held only by live sessions warns (7 with the contract's timings). */
export const WARN_AFTER_HOURS = (HOLD_MAX_NO_USE_S - HOLD_WARN_BEFORE_S) / 3600

/** `HH:MM` in the viewer's local time. */
export function stopTimeLabel(stopAtEpochS: number): string {
  const d = new Date(stopAtEpochS * 1000)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

export function stopWarningText(stopAtEpochS: number): string {
  return `Your Kali sandbox stops at ${stopTimeLabel(stopAtEpochS)} because it has not been used for ${WARN_AFTER_HOURS} hours; use it to keep it running`
}
