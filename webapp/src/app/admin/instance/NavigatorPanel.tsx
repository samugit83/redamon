'use client'

import { useEffect, useState } from 'react'
import { useToast, Toggle } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import type { InstanceSettingsView } from './instanceView'
import { putInstanceSettings } from './instanceSettingsClient'
import { Panel, RootOnlyNote } from './Panel'
import styles from './instance.module.css'

interface DocsHealth {
  wiki: { present: boolean; pages: number; sections: number; updated_at?: number | null } | null
  agentOutdated?: boolean
}

const SAVE_FAILED = 'AI Navigator was not switched'

/**
 * AI Navigator on or off for the whole instance (plan §5.5, §9.13): the confirmed Root changes it
 * with its password; any other administrator reads it. Below it, whether the agent has the
 * documentation the docs answers come from (§8.13).
 */
export function NavigatorInstancePanel({ settings, unconfirmedRoot, onSaved, canReadHealth }: {
  settings: InstanceSettingsView
  unconfirmedRoot: boolean
  onSaved: (settings: InstanceSettingsView) => void
  canReadHealth: boolean
}) {
  const toast = useToast()
  const enabled = settings.navigatorEnabled !== false
  const canEdit = settings.canManageNavigator === true
  const [asking, setAsking] = useState<boolean | null>(null)
  const [health, setHealth] = useState<DocsHealth | null | 'error'>(null)

  useEffect(() => {
    if (!canReadHealth) return
    let gone = false
    fetch('/api/admin/navigator/health', { cache: 'no-store' })
      .then(async (r) => (r.ok ? (await r.json()) as DocsHealth : 'error' as const))
      .catch(() => 'error' as const)
      .then((h) => { if (!gone) setHealth(h) })
    return () => { gone = true }
  }, [canReadHealth])

  const docs = health === null ? 'Checking the documentation…'
    : health === 'error' ? "Couldn't check the documentation: the agent did not answer."
      : health.agentOutdated ? 'The agent is older than the web app: rebuild it with ./redamon.sh update.'
        : health.wiki?.present
          ? `Documentation: ${health.wiki.pages} pages${health.wiki.updated_at ? `, updated ${new Date(health.wiki.updated_at * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' })}` : ''}.`
          : 'Documentation not installed: run ./redamon.sh update (or git submodule update --init redamon.wiki).'

  return (
    <Panel id="navigator" title="AI Navigator"
      lead="The read-only chat that answers questions about RedAmon and each project's data, on each person's own model. Off hides it for everyone and ends every answer being written.">
      <div className={styles.actions}>
        <Toggle
          checked={enabled}
          disabled={!canEdit}
          onChange={(v: boolean) => setAsking(v)}
          aria-label="AI Navigator"
          labelOff="Off"
          labelOn="On"
        />
      </div>
      {!canEdit && <RootOnlyNote unconfirmedRoot={unconfirmedRoot} />}
      {canReadHealth && <p className={styles.note} role="status" data-testid="navigator-docs-status">{docs}</p>}
      <StepUpModal
        isOpen={asking !== null}
        title={asking ? 'Turn AI Navigator on' : 'Turn AI Navigator off'}
        message={asking
          ? 'Everyone who holds navigator:use sees AI Navigator again. Enter your password to confirm.'
          : 'AI Navigator disappears for everyone and every answer being written ends. Enter your password to confirm.'}
        confirmLabel={asking ? 'Turn on' : 'Turn off'}
        onConfirm={async (password) => {
          const answer = await putInstanceSettings({ navigatorEnabled: asking, stepUpPassword: password }, SAVE_FAILED)
          onSaved(answer)
          toast.success(asking ? 'AI Navigator is on' : 'AI Navigator is off')
        }}
        onClose={() => setAsking(null)}
      />
    </Panel>
  )
}
