'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import styles from '@/components/settings/Settings.module.css'
import { tunnelDisplay, type TunnelDisplay } from '@/lib/tunnelDisplay'

const PROVIDERS = ['ngrok', 'chisel'] as const
type Provider = (typeof PROVIDERS)[number]

/**
 * `running`: a tunnel process runs (`active`), what the off control follows. `shown`: each tunnel
 * that is not off, as its `status` says (tunnelDisplay), what the line shows.
 */
type TunnelView =
  | { kind: 'loading' }
  | { kind: 'error' }
  | { kind: 'loaded'; running: boolean; shown: { provider: Provider; display: TunnelDisplay }[] }

/** "On (ngrok)", "Connecting (chisel)", "Failed (chisel): reason", joined; "Off" when none shows. */
export function tunnelStatusLine(shown: { provider: Provider; display: TunnelDisplay }[]): string {
  const named = (state: TunnelDisplay['state']) => shown.filter(s => s.display.state === state).map(s => s.provider)
  const parts: string[] = []
  if (named('on').length) parts.push(`On (${named('on').join(' and ')})`)
  if (named('connecting').length) parts.push(`Connecting (${named('connecting').join(' and ')})`)
  for (const s of shown) if (s.display.state === 'error') parts.push(`Failed (${s.provider}): ${s.display.reason}`)
  return parts.length ? parts.join('; ') : 'Off'
}

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
        const body = await res.json() as Partial<Record<Provider, { active?: unknown; status?: unknown }>> | null
        const running = PROVIDERS.some(p => body?.[p]?.active === true)
        const shown = PROVIDERS.map(provider => ({ provider, display: tunnelDisplay(body?.[provider]) }))
          .filter(s => s.display.state !== 'off')
        if (live) setView({ kind: 'loaded', running, shown })
      })
      .catch(() => { if (live) setView({ kind: 'error' }) })
    return () => { live = false }
  }, [])

  const running = view.kind === 'loaded' && view.running
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
          {view.kind === 'loaded' && tunnelStatusLine(view.shown)}
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
