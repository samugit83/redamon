'use client'

import { Layers } from 'lucide-react'
import { muteableLabel } from '@/lib/muteTarget'
import { formatNodeId } from '../RedZoneTables/nodeId'
import { READ_ONLY_REASON, unmuteableReason, useMuteNodeContext } from './MuteNodeContext'
import type { MultiMuteOptions, MultiMuteSeed } from './multiMuteModel'
import styles from './MuteButton.module.css'

export const MULTI_MUTE_TITLE = 'Find the findings like this one and mute them together'

const EXPLOIT_GVM_REASON =
  'A GVM exploit is a confirmed exploitation, so Multi mute does not look for others ' +
  'like it. Use Mute to hide this one alone.'

const JS_FILE_REASON =
  'A JS file is a container, not a finding: muting it with others would orphan every ' +
  'finding found in it.'

/** Why Multi mute cannot start from this node, or null when it can. */
export function multiMuteDisabledReason(
  seed: Pick<MultiMuteSeed, 'label' | 'findingType'>, readOnly: boolean, readOnlyReason?: string,
): string | null {
  if (readOnly) return readOnlyReason ?? READ_ONLY_REASON
  const label = seed.label
  if (!label) return null
  if (!muteableLabel([label])) return unmuteableReason(label)
  if (label === 'ExploitGvm') return EXPLOIT_GVM_REASON
  if (label === 'JsReconFinding' && seed.findingType === 'js_file') return JS_FILE_REASON
  return null
}

interface MultiMuteButtonProps extends MultiMuteOptions {
  seed: MultiMuteSeed
  /** "Multi" instead of "Multi mute", for table rows. */
  compact?: boolean
}

/**
 * Opens Multi mute on this finding. Renders nothing outside the graph page's
 * `MuteNodeProvider`, or for a row that is not one node.
 */
export function MultiMuteButton({ seed, compact = false, onSeedMuted, onMuted }: MultiMuteButtonProps) {
  const { projectId, readOnly, readOnlyReason, openMultiMute } = useMuteNodeContext()
  const graphId = formatNodeId(seed.graphId)
  if (!projectId || !(seed.nodeId || graphId)) return null
  const reason = multiMuteDisabledReason(seed, readOnly, readOnlyReason)

  return (
    <button
      type="button"
      className={styles.muteButton}
      disabled={!!reason}
      title={reason ?? MULTI_MUTE_TITLE}
      aria-label="Multi mute"
      onClick={e => {
        // Several tables select or expand a row on click; this should do neither.
        e.stopPropagation()
        openMultiMute({ ...seed, graphId }, { onSeedMuted, onMuted })
      }}
    >
      <Layers size={13} aria-hidden="true" />
      {compact ? 'Multi' : 'Multi mute'}
    </button>
  )
}
