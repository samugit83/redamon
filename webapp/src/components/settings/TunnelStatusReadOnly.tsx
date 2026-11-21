'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import styles from '@/components/settings/Settings.module.css'

type TunnelView = { kind: 'loading' } | { kind: 'error' } | { kind: 'loaded'; providers: string[] }

interface Props {
  /** Per-user Kali sandboxes: the state is the person's own tunnel. */
  perPerson?: boolean
  /** The person may turn a tunnel on (per-person mode changes only the hint). */
  canManage?: boolean
  /** The stored setting reads on. */
  flagOn?: boolean
  /** Per-person mode: turn one's own tunnel off, offered while it runs or the setting reads on. */
  onTurnOff?: () => void
  turningOff?: boolean
}

/**
 * The Tunneling section's tunnel state and who manages it, for an account that may not change the
 * tunnel. Per-user Kali sandboxes: the person's own tunnel; turning one on is what the Tunnels
 * permission allows, and turning it off is offered whenever a tunnel runs or the setting reads on,
 * so a stop that never reached the sandbox can be sent again.
 */
export function TunnelStatusReadOnly({ perPerson = false, canManage = false, flagOn = false, onTurnOff, turningOff = false }: Props = {}) {
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

  const running = view.kind === 'loaded' && view.providers.length > 0
  const offerOff = perPerson && !!onTurnOff && (running || flagOn)
  const hint = !perPerson
    ? 'The tunnel is managed by an administrator.'
    : canManage
      ? 'Your own tunnel, in your own Kali sandbox.'
      : 'Your own tunnel, in your own Kali sandbox. Turning one on needs the Tunnels permission; turning yours off does not.'

  return (
    <div className={styles.settingsGrid}>
      <div className="formGroup">
        <span className="formLabel">Tunnel status</span>
        <span role="status">
          {view.kind === 'loading' && <><Loader2 size={14} className={styles.spin} /> Checking...</>}
          {view.kind === 'error' && 'Status unavailable'}
          {view.kind === 'loaded' && (view.providers.length ? `On (${view.providers.join(' and ')})` : 'Off')}
        </span>
        <span className="formHint">{hint}</span>
        {offerOff && (
          <div>
            <button type="button" className="secondaryButton" onClick={onTurnOff} disabled={turningOff}>
              {turningOff ? <><Loader2 size={14} className={styles.spin} /> Turning off...</> : 'Turn my tunnel off'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
