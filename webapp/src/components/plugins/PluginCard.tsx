'use client'

import { useState } from 'react'
import { Puzzle } from 'lucide-react'
import { WikiInfoButton } from '@/components/ui'
import type { CardState, PluginEntry } from '@/lib/plugins/pageModel'
import { PERMISSION_TEXT, isPluginPermission } from '@/lib/plugins/permissions'
import { PluginBadge } from './PluginBadge'
import styles from './plugins.module.css'

export type CardAction = 'install' | 'update' | 'enable' | 'disable' | 'uninstall' | 'deleteKept' | 'details'

const ADMIN_LABEL: Record<CardState, { text: string; chip: string }> = {
  not_installed: { text: 'Not installed', chip: 'chipSecondary' },
  installing: { text: 'Installing…', chip: 'chipInfo' },
  updating: { text: 'Updating…', chip: 'chipInfo' },
  uninstalling: { text: 'Uninstalling…', chip: 'chipInfo' },
  ready: { text: 'Ready', chip: 'chipSuccess' },
  disabled: { text: 'Disabled', chip: 'chipSecondary' },
  failed: { text: 'Failed', chip: 'chipError' },
  incompatible: { text: 'Incompatible', chip: 'chipWarning' },
  revoked: { text: 'Revoked', chip: 'chipError' },
}

const USER_LABEL: Record<CardState, string> = {
  not_installed: 'Not installed',
  installing: 'Installing…',
  updating: 'Updating…',
  uninstalling: 'Uninstalling…',
  ready: 'Installed',
  disabled: 'Disabled',
  failed: 'Unavailable',
  incompatible: 'Needs an update',
  revoked: 'Revoked',
}

const TRANSIENT: CardState[] = ['installing', 'updating', 'uninstalling']

interface PluginCardProps {
  entry: PluginEntry
  /** The viewer holds platform:plugins (the page model's `managesPlugins`). */
  manages: boolean
  busy?: boolean
  onAction: (action: CardAction, entry: PluginEntry) => void
}

/** The catalog's image for the plugin, or a placeholder when it names none or it cannot be served. */
function PluginAvatar({ src, name }: { src?: string; name: string }) {
  const [failedSrc, setFailedSrc] = useState<string | null>(null)
  if (!src || failedSrc === src) {
    return (
      <div className={`${styles.avatar} ${styles.avatarPlaceholder}`} data-testid="plugin-avatar-placeholder" aria-hidden>
        <Puzzle size={40} />
      </div>
    )
  }
  return <img className={styles.avatar} src={src} alt={`${name} icon`} onError={() => setFailedSrc(src)} />
}

/** One plugin on the Plugins page; the actions whoever manages plugins may take depend on its state. */
export function PluginCard({ entry, manages, busy = false, onAction }: PluginCardProps) {
  const { state } = entry
  const label = manages ? ADMIN_LABEL[state].text : USER_LABEL[state]
  const chip = manages ? ADMIN_LABEL[state].chip : state === 'ready' ? 'chipSuccess' : 'chipSecondary'
  const permissions = entry.installed?.grantedPermissions ?? entry.available?.permissions.map((p) => p.id) ?? []
  const act = (a: CardAction) => () => onAction(a, entry)

  const buttons: { action: CardAction; label: string; danger?: boolean; disabled?: boolean }[] = []
  if (manages && !TRANSIENT.includes(state)) {
    if (state === 'not_installed') {
      buttons.push({ action: 'install', label: 'Install', disabled: !entry.available })
      if (entry.keptData) buttons.push({ action: 'deleteKept', label: 'Delete kept data', danger: true })
    } else {
      // Updating to a release the catalog has not revoked is how a revoked plugin comes back.
      if (entry.update) buttons.push({ action: 'update', label: `Update to ${entry.update.version}` })
      if (state === 'ready') buttons.push({ action: 'disable', label: 'Disable' })
      if (state === 'disabled') buttons.push({ action: 'enable', label: 'Enable' })
      if (state === 'failed') buttons.push({ action: 'enable', label: 'Retry' })
      buttons.push({ action: 'uninstall', label: 'Uninstall', danger: true })
      buttons.push({ action: 'details', label: 'Details' })
    }
  }

  return (
    <div className={`card ${styles.pluginCard}`} data-testid={`plugin-card-${entry.id}`}>
      <div className="cardHeader">
        <div className={styles.cardHead}>
          <div>
            <div className={styles.titleRow}>
              <h3 className="cardTitle">{entry.displayName}</h3>
              <PluginBadge />
            </div>
          </div>
          <div className={styles.headEnd}>
            <span className={`chip ${chip}`} data-testid="plugin-state">
              {TRANSIENT.includes(state) ? (
                <span className={styles.busy} role="status">
                  <span className="spinner spinnerSmall" aria-hidden />
                  {label}
                </span>
              ) : (
                label
              )}
            </span>
            {entry.docsUrl && (
              <WikiInfoButton target={entry.docsUrl} title={`Open the ${entry.displayName} documentation`} size={15} />
            )}
          </div>
        </div>
      </div>
      <div className={`cardBody ${styles.cardBody}`}>
        <div className={styles.cardMain}>
          {entry.description && <p className={styles.description}>{entry.description}</p>}
          <div className={styles.meta}>
            <span>
              {entry.installed?.version ? `Installed ${entry.installed.version}` : 'Not installed'}
              {entry.update ? ` · ${entry.update.version} available` : !entry.installed && entry.available ? ` · ${entry.available.version} available` : ''}
              {entry.inCatalog === false && ' · no longer in the catalog'}
              {entry.keptData && ' · data kept from an earlier install'}
            </span>
            {permissions.length > 0 && (
              <span className={styles.permissions}>
                {permissions.map((p) => (
                  <span key={p} className="chip chipSecondary">
                    {isPluginPermission(p) ? PERMISSION_TEXT[p].title : p}
                  </span>
                ))}
              </span>
            )}
          </div>
          {state === 'revoked' && entry.installed?.revokedReason && (
            <div className={styles.error}>Revoked by the catalog: {entry.installed.revokedReason}</div>
          )}
          {manages && entry.installed?.lastError && <div className={styles.error}>{entry.installed.lastError}</div>}
          {manages && !entry.installed && entry.lastAttemptError && (
            <div className={styles.error}>Last attempt: {entry.lastAttemptError}</div>
          )}
          {manages && state === 'not_installed' && entry.installBlocked && <div className={styles.notice}>{entry.installBlocked}</div>}
          {buttons.length > 0 && (
            <div className={styles.actions}>
              {buttons.map((b) => (
                <button
                  key={b.label}
                  type="button"
                  className={
                    b.danger
                      ? `secondaryButton ${styles.danger}`
                      : b.action === 'install' || b.action === 'update'
                        ? 'primaryButton'
                        : b.action === 'details'
                          ? 'textButton'
                          : 'secondaryButton'
                  }
                  disabled={busy || b.disabled}
                  onClick={act(b.action)}
                >
                  {b.label}
                </button>
              ))}
            </div>
          )}
        </div>
        <PluginAvatar src={entry.icon} name={entry.displayName} />
      </div>
    </div>
  )
}
