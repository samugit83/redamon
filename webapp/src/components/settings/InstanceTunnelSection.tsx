'use client'

/**
 * The instance tunnel group (step 2.4; the admin console's Instance page, step 6.7): unused since
 * every person runs their own tunnel, with their own credentials, from their own Kali sandbox
 * (group 1, OQ-G1-2 A). Whoever holds platform:tunnels sees a notice saying so, with no controls;
 * anyone else sees their tunnel status. /api/admin/instance-settings still answers the stored group
 * read-only and takes only its "off".
 */
import { useCallback, useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { readApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import styles from '@/components/settings/Settings.module.css'
import { TunnelStatusReadOnly } from './TunnelStatusReadOnly'

const INSTANCE_SETTINGS_URL = '/api/admin/instance-settings'
const LOAD_FAILED = "Couldn't load the tunnel settings"

type View = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'readonly' } | { kind: 'perPerson' }

export function InstanceTunnelSection() {
  const [view, setView] = useState<View>({ kind: 'loading' })

  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const resp = await fetch(INSTANCE_SETTINGS_URL, { cache: 'no-store' })
      if (resp.status === 403 || resp.status === 404) {
        setView({ kind: 'readonly' })
        return
      }
      if (!resp.ok) throw await readApiError(resp, LOAD_FAILED)
      const body = await resp.json() as Record<string, unknown>
      setView({ kind: body.canManageTunnels === true ? 'perPerson' : 'readonly' })
    } catch (err) {
      setView({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [])

  useEffect(() => { load() }, [load])

  if (view.kind === 'loading') {
    return <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
  }
  if (view.kind === 'error') {
    return (
      <div className={styles.emptyState} role="alert">
        {view.message}.{' '}
        <button type="button" className="textButton" onClick={load}>Retry</button>
      </div>
    )
  }
  if (view.kind === 'readonly') return <TunnelStatusReadOnly />
  return (
    <div className={styles.settingsGrid}>
      <div className="formGroup">
        <span className="formLabel">Tunnel settings</span>
        <span role="note">
          Tunnels are per person: each person turns on their own tunnel, with their own ngrok or chisel
          credentials, in Global Settings, and it runs in their own Kali sandbox. The instance tunnel is not used.
        </span>
      </div>
    </div>
  )
}
