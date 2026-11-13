'use client'

import { useState } from 'react'
import { GuardedLink } from '@/components/GuardedLink'
import { TrafficMindSettingsModal } from '@/components/traffic/TrafficMindSettingsModal'
import type { InstanceSettingsView } from './instanceView'
import { Panel } from './Panel'
import styles from './instance.module.css'

/** The egress guard's switches (the modal's EGRESS_TOGGLES): each blocks a class of destination when on. */
export const EGRESS_SWITCHES: readonly { key: string; label: string }[] = [
  { key: 'captureEgressBlockPrivate', label: 'private IPs' },
  { key: 'captureEgressBlockLinkLocal', label: 'link-local IPs' },
  { key: 'captureEgressBlockLoopback', label: 'loopback IPs' },
  { key: 'captureEgressBlockCgnat', label: 'CGNAT' },
  { key: 'captureEgressBlockReserved', label: 'reserved ranges' },
  { key: 'captureEgressBlockMulticast', label: 'multicast' },
  { key: 'captureEgressBlockUnspecified', label: 'unspecified addresses' },
  { key: 'captureEgressBlockHardGuardrail', label: 'sensitive hostnames' },
  { key: 'captureEgressBlockUnresolvable', label: 'unresolvable hosts' },
  { key: 'captureEgressBlockEmptyHost', label: 'empty host' },
  { key: 'captureEgressFailClosed', label: 'fail closed on a guard error' },
]

const SCOPES: Record<string, string> = { both: 'Recon and agent', recon: 'Recon only', agent: 'Agent only' }

/** The guard switches turned off: each lets the proxy reach that class, or (fail-closed off) forwards unvetted. */
export function relaxedEgress(settings: InstanceSettingsView): string[] {
  return EGRESS_SWITCHES.filter((s) => settings[s.key] === false).map((s) => s.label)
}

/**
 * TrafficMind and its egress policy (platform:traffic_capture): a summary of the instance-wide
 * capture proxy, and its settings in the same dialog the TrafficMind page opens
 * (TrafficMindSettingsModal, which reads and saves /api/admin/instance-settings as the signed-in
 * person with the identity switch on). Closing the dialog reads the summary again.
 */
export function TrafficMindPanel({ settings, userId, onChanged }: {
  settings: InstanceSettingsView
  userId: string
  onChanged: () => void
}) {
  const [open, setOpen] = useState(false)
  const enabled = settings.captureProxyEnabled === true
  const relaxed = relaxedEgress(settings)
  return (
    <Panel
      id="traffic"
      title="TrafficMind and egress policy"
      lead="The capture proxy every user's scans and agent runs share, and the destinations it refuses to reach."
    >
      <dl className={styles.readList}>
        <dt>Capture proxy</dt>
        <dd>{enabled ? 'On' : 'Off'}</dd>
        {enabled && (
          <>
            <dt>Scope</dt><dd>{SCOPES[String(settings.captureProxyScope)] ?? String(settings.captureProxyScope ?? '')}</dd>
            <dt>Listen port</dt><dd>{String(settings.captureProxyPort ?? '')}</dd>
            <dt>Retention</dt><dd>{String(settings.captureProxyRetentionDays ?? '')} days</dd>
          </>
        )}
        <dt>Egress guard</dt>
        <dd>{relaxed.length === 0 ? 'Every class of destination blocked' : `Relaxed: ${relaxed.join(', ')}`}</dd>
      </dl>
      <div className={styles.actions}>
        <button type="button" className="primaryButton" onClick={() => setOpen(true)}>Edit TrafficMind settings</button>
        <GuardedLink href="/traffic">Open TrafficMind</GuardedLink>
      </div>
      <TrafficMindSettingsModal
        isOpen={open}
        userId={userId}
        onClose={() => {
          setOpen(false)
          onChanged()
        }}
      />
    </Panel>
  )
}
