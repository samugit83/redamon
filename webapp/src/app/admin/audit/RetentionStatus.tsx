'use client'

import { useEffect, useState } from 'react'
import { GuardedLink } from '@/components/GuardedLink'
import { keptText, retentionOf, type RetentionView } from '../instance/AuditRetentionPanel'
import type { InstanceSettingsView } from '../instance/instanceView'
import consoleStyles from '../admin.module.css'

const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' })

/**
 * One line on the audit viewer: how long rows are kept, and a change waiting its delay, read from the
 * instance settings (administrators, governance switch on). Says nothing when they cannot be read:
 * the viewer works without it. Root, who changes it, gets the link to the Instance page.
 */
export function RetentionStatus() {
  const [state, setState] = useState<{ retention: RetentionView; canManage: boolean } | null>(null)
  useEffect(() => {
    let live = true
    fetch('/api/admin/instance-settings', { cache: 'no-store' })
      .then(async (res) => (res.ok ? (await res.json()) as InstanceSettingsView : null))
      .then((settings) => {
        const retention = retentionOf(settings)
        if (live && retention) setState({ retention, canManage: settings?.canManageAuditRetention === true })
      })
      .catch(() => undefined)
    return () => { live = false }
  }, [])
  if (!state) return null
  const { retention, canManage } = state
  return (
    <p className={consoleStyles.lead} role="status">
      Audit rows: {keptText(retention.days).toLowerCase()}.
      {retention.pending && ` From ${day(retention.pending.effectiveAt)}: ${keptText(retention.pending.days).toLowerCase()}.`}
      {canManage && <> <GuardedLink href="/admin/instance#retention">Change the audit retention</GuardedLink></>}
    </p>
  )
}
