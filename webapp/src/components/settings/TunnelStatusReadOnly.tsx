'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import styles from '@/components/settings/Settings.module.css'

type TunnelView = { kind: 'loading' } | { kind: 'error' } | { kind: 'loaded'; providers: string[] }

/** The Tunneling section for an account that may not change the tunnel: its state and who manages it. */
export function TunnelStatusReadOnly() {
  const [view, setView] = useState<TunnelView>({ kind: 'loading' })
  useEffect(() => {
    let live = true
    fetch('/api/agent/tunnel-status', { cache: 'no-store' })
      .then(async res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const body = await res.json() as Partial<Record<'ngrok' | 'chisel', { active?: boolean }>>
        const providers = (['ngrok', 'chisel'] as const).filter(p => body?.[p]?.active === true)
        if (live) setView({ kind: 'loaded', providers })
      })
      .catch(() => { if (live) setView({ kind: 'error' }) })
    return () => { live = false }
  }, [])

  return (
    <div className={styles.settingsGrid}>
      <div className="formGroup">
        <span className="formLabel">Tunnel status</span>
        <span role="status">
          {view.kind === 'loading' && <><Loader2 size={14} className={styles.spin} /> Checking...</>}
          {view.kind === 'error' && 'Status unavailable'}
          {view.kind === 'loaded' && (view.providers.length ? `On (${view.providers.join(' and ')})` : 'Off')}
        </span>
        <span className="formHint">The tunnel is managed by an administrator.</span>
      </div>
    </div>
  )
}
