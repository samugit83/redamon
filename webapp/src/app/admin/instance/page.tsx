'use client'

import { useCallback, useEffect, useState } from 'react'
import { GuardedLink } from '@/components/GuardedLink'
import { InstanceTunnelSection } from '@/components/settings/InstanceTunnelSection'
import { failureText } from '@/components/settings/failureText'
import { useAuth } from '@/providers/AuthProvider'
import { readApiError } from '@/lib/apiError'
import { PERMISSION_IDS } from '@/lib/authz/permissions'
import type { Holds } from '../consoleSections'
import {
  otherPlatformTools, visiblePanels, type InstanceSettingsView, type PanelId,
} from './instanceView'
import { INSTANCE_SETTINGS_URL } from './instanceSettingsClient'
import { Panel } from './Panel'
import { PublicUrlPanel, SecurityPolicyPanel } from './SecurityPolicyPanel'
import { SharingPolicyPanel, sharingPolicyOf } from './SharingPolicyPanel'
import { DefaultSetPanel } from './DefaultSetPanel'
import { NucleiTemplatesPanel } from './NucleiTemplatesPanel'
import { TrafficMindPanel } from './TrafficMindPanel'
import { LlmProvidersPanel } from './LlmProvidersPanel'
import { QuotasPanel } from './QuotasPanel'
import styles from './instance.module.css'

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  /** `settings` null: the route refused them (a member holding only a tool used elsewhere). */
  | { kind: 'ready'; settings: InstanceSettingsView | null }

const LOAD_FAILED = "Couldn't load the instance settings"

const TITLES: Record<PanelId, string> = {
  security: 'Security policy',
  'public-url': 'Public address',
  sharing: 'Sharing policy',
  'default-set': 'Defaults for new members',
  'llm-providers': 'Instance LLM providers',
  quotas: 'Quotas',
  tunnels: 'Tunnel',
  traffic: 'TrafficMind and egress policy',
  nuclei: 'Nuclei templates',
  plugins: 'Plugins',
  'other-tools': 'Platform tools used elsewhere',
}

const PLATFORM = PERMISSION_IDS.filter((p) => p.startsWith('platform:'))

/**
 * /admin/instance (step 6.7, GV-08, UI-04, SH-21 UI): what the instance shares, one panel per
 * group, each shown to whoever holds it. The console shell (AdminConsole.tsx) already turned away
 * anyone holding none of instance:settings, instance:quotas or a platform:* permission; this page
 * shows the panels each route answers for, and writes through those routes only.
 */
export default function InstancePage() {
  const { user, capabilities } = useAuth()
  const holds: Holds = (p) => capabilities.has(p)
  const [state, setState] = useState<State>({ kind: 'loading' })

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setState({ kind: 'loading' })
    try {
      const res = await fetch(INSTANCE_SETTINGS_URL, { cache: 'no-store' })
      if (res.status === 403) {
        setState({ kind: 'ready', settings: null })
        return
      }
      if (!res.ok) throw await readApiError(res, LOAD_FAILED)
      setState({ kind: 'ready', settings: await res.json() as InstanceSettingsView })
    } catch (err) {
      setState({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [])

  useEffect(() => { load() }, [load])

  const ready = state.kind === 'ready'
  // A link to a panel (/admin/instance#tunnels, from Global Settings) lands once the panels exist.
  useEffect(() => {
    if (!ready || !window.location.hash) return
    document.getElementById(decodeURIComponent(window.location.hash.slice(1)))?.scrollIntoView?.()
  }, [ready])

  if (state.kind === 'loading') {
    return <div className={styles.page}><h1 className={styles.title}>Instance</h1><p className={styles.state} role="status">Loading the instance settings…</p></div>
  }
  if (state.kind === 'error') {
    return (
      <div className={styles.page}>
        <h1 className={styles.title}>Instance</h1>
        <div className={styles.error} role="alert">{state.message}</div>
        <div><button type="button" className="primaryButton" onClick={() => load()}>Retry</button></div>
      </div>
    )
  }

  const settings = state.settings
  const panels = visiblePanels({ holds, settings, sharingPolicyShown: sharingPolicyOf(settings) !== null })
  const unconfirmedRoot = user?.accountType === 'root' && settings?.canManageSecurityPolicy !== true
  const isConfirmedRoot = settings?.canManageSecurityPolicy === true
  const onSaved = (next: InstanceSettingsView) => setState({ kind: 'ready', settings: next })
  const memberOverride = user?.accountType === 'member' && PLATFORM.some(holds)

  const render = (id: PanelId) => {
    switch (id) {
      case 'security':
        return <SecurityPolicyPanel key={id} settings={settings!} unconfirmedRoot={unconfirmedRoot} onSaved={onSaved} />
      case 'public-url':
        return <PublicUrlPanel key={id} settings={settings!} unconfirmedRoot={unconfirmedRoot} onSaved={onSaved} />
      case 'sharing':
        return <SharingPolicyPanel key={id} settings={settings!} unconfirmedRoot={unconfirmedRoot} onSaved={onSaved} />
      case 'default-set':
        return <DefaultSetPanel key={id} canEdit={isConfirmedRoot && holds('roles:manage')} unconfirmedRoot={unconfirmedRoot} />
      case 'llm-providers':
        return <LlmProvidersPanel key={id} />
      case 'quotas':
        return <QuotasPanel key={id} settings={settings!} onSaved={onSaved} />
      case 'tunnels':
        return (
          <Panel key={id} id={id} title={TITLES[id]} lead="The ngrok or chisel tunnel every user's reverse shells share (port 4444).">
            <InstanceTunnelSection placement="instance" />
          </Panel>
        )
      case 'traffic':
        return <TrafficMindPanel key={id} settings={settings!} userId={user?.id ?? ''} onChanged={() => load(true)} />
      case 'nuclei':
        return <NucleiTemplatesPanel key={id} />
      case 'plugins':
        return (
          <Panel key={id} id={id} title={TITLES[id]} lead="Install, update, enable, disable and uninstall plugins, and grant their permissions.">
            <div><GuardedLink href="/plugins">Open the Plugins page</GuardedLink></div>
          </Panel>
        )
      case 'other-tools':
        return (
          <Panel key={id} id={id} title={TITLES[id]}>
            {memberOverride && (
              <p className={styles.state} role="note">
                Your account is a member account. It sees this page because it holds a platform permission as a personal
                override, for example one kept from before the upgrade. The tools below have nothing to set here; this is where
                you use them.
              </p>
            )}
            <ul className={styles.toolList}>
              {otherPlatformTools(holds).map((t) => (
                <li key={t.permission}>
                  <code>{t.permission}</code>: {t.where} <GuardedLink href={t.href}>{t.linkLabel}</GuardedLink>
                </li>
              ))}
            </ul>
          </Panel>
        )
    }
  }

  return (
    <div className={styles.page}>
      <h1 className={styles.title}>Instance</h1>
      <p className={styles.lead}>The settings the whole instance shares. Each section is shown to whoever may manage it.</p>
      {panels.length === 0 ? (
        <p className={styles.state}>No section of this page is open to you.</p>
      ) : (
        <>
          {panels.length > 1 && (
            <nav aria-label="Instance sections">
              <ul className={styles.actions} style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                {panels.map((id) => <li key={id}><a href={`#${id}`}>{TITLES[id]}</a></li>)}
              </ul>
            </nav>
          )}
          {panels.map(render)}
        </>
      )}
    </div>
  )
}
