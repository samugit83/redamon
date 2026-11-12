'use client'

import { useState } from 'react'
import { ExternalLink, Upload } from 'lucide-react'
import { useAlertModal, WikiInfoButton } from '@/components/ui'
import { CatalogStatus } from '@/components/plugins/CatalogStatus'
import { ConsentDialog } from '@/components/plugins/ConsentDialog'
import { OfflineInstallDialog } from '@/components/plugins/OfflineInstallDialog'
import { PluginDetailsDrawer } from '@/components/plugins/PluginDetailsDrawer'
import { PluginCard, type CardAction } from '@/components/plugins/PluginCard'
import { PluginNavLinks } from '@/components/plugins/PluginNavLinks'
import { RunnerStatusBanner } from '@/components/plugins/RunnerStatusBanner'
import { UninstallDialog } from '@/components/plugins/UninstallDialog'
import { PluginApiError, usePluginAction, usePluginsPage } from '@/hooks/usePlugins'
import { errorMessage } from '@/lib/apiError'
import type { PluginEntry } from '@/lib/plugins/pageModel'
import styles from './page.module.css'

const CATALOG_REPO_URL = 'https://github.com/samugit83/redamon-plugins'
// The install checks' details derive from the plugin's manifest: a few, each already capped.
const DETAILS_SHOWN = 5

/**
 * The alert for a failed lifecycle call. Only a JSON 4xx is a refusal: with no answer, or a
 * proxy's page instead of ours, the operation may still finish (reconcile reclaims its
 * lease), and one that says `committed` took effect.
 */
export function operationFailure(err: PluginApiError): { title: string; message: string } {
  const details = err.details?.length ? `\n${err.details.slice(0, DETAILS_SHOWN).map((d) => `• ${d}`).join('\n')}` : ''
  if (err.body?.committed === true) return { title: 'The plugin operation took effect, with an error', message: err.message }
  const unread = err.status === 0 || err.code === 'non_json_response' || err.code === 'empty_response'
  if (unread && err.status !== 413) {
    return {
      title: 'The outcome of the plugin operation is unknown',
      message: `${err.message}\nIt may still be running; the page refreshes to show its state.`,
    }
  }
  if (err.status >= 500) return { title: 'The plugin operation failed', message: `${err.message}${details}` }
  return { title: 'The plugin operation was refused', message: `${err.message}${details}` }
}

type Dialog =
  | { kind: 'install'; entry: PluginEntry; restoreCount: number }
  | { kind: 'update'; entry: PluginEntry }
  | { kind: 'uninstall'; entry: PluginEntry; keptOnly?: boolean }
  | { kind: 'offline'; restoreCount?: number }
  | null

export function PluginsPageClient() {
  const { data, isLoading, isError, error, refetch } = usePluginsPage()
  const action = usePluginAction()
  const { confirm, alertError } = useAlertModal()
  const [dialog, setDialog] = useState<Dialog>(null)
  const [details, setDetails] = useState<string | null>(null)

  const run = async (path: string, body?: unknown, form?: FormData): Promise<unknown | null> => {
    try {
      return await action.mutateAsync({ path, body, form })
    } catch (e) {
      const err = e instanceof PluginApiError ? e : new PluginApiError(errorMessage(e, 'The plugin operation failed'), 'client_error', 0)
      // A reinstall that finds approved versions: ask, then try again with the answer.
      if (err.code === 'restore_choice_required' && (dialog?.kind === 'install' || dialog?.kind === 'offline')) {
        setDialog({ ...dialog, restoreCount: Number(err.details?.[0] ?? 1) })
        return null
      }
      const { title, message } = operationFailure(err)
      await alertError(message, title)
      return null
    }
  }

  const onAction = async (a: CardAction, entry: PluginEntry) => {
    const base = `/api/plugins/${entry.id}`
    if (a === 'install') setDialog({ kind: 'install', entry, restoreCount: 0 })
    else if (a === 'update') setDialog({ kind: 'update', entry })
    else if (a === 'uninstall') setDialog({ kind: 'uninstall', entry })
    else if (a === 'deleteKept') setDialog({ kind: 'uninstall', entry, keptOnly: true })
    else if (a === 'details') setDetails(entry.id)
    else if (a === 'enable') await run(`${base}/enable`)
    else if (a === 'disable') {
      const ok = await confirm(
        `${entry.displayName} stops for every user: its actions and screens disappear and its approved skill versions stop applying from the next message. Its code and data stay, so enabling it again restores everything. Skills that people saved from its proposals as their own stay and keep working, unless the catalog revokes the version that made them.`,
        `Disable ${entry.displayName}?`,
        { confirmLabel: 'Disable' },
      )
      if (ok) await run(`${base}/disable`)
    }
  }

  const onRollback = async (pluginId: string, toVersion: string) => {
    const ok = await confirm(
      `Version ${toVersion} becomes active again for every user. If the newer version moved the data, its down migration takes it back first; nothing changes if any of it fails.`,
      `Roll back to ${toVersion}?`,
      { confirmLabel: 'Roll back' },
    )
    if (ok) await run(`/api/plugins/${pluginId}/rollback`, { toVersion })
  }

  if (isLoading) {
    return (
      <div className={styles.page} data-testid="plugins-loading">
        <div className="skeleton skeletonTitle" />
        <div className={styles.grid}>
          {[0, 1, 2].map((i) => (
            <div key={i} className="skeleton skeletonCard" />
          ))}
        </div>
      </div>
    )
  }
  if (isError || !data) {
    return (
      <div className={styles.page}>
        <div className="alert alertError">
          <div className="alertContent">
            <div className="alertTitle">The Plugins page could not be loaded.</div>
            {error && <div className="alertMessage">{errorMessage(error, 'The Plugins page could not be loaded')}</div>}
            <button type="button" className="secondaryButton" onClick={() => refetch()}>
              Try again
            </button>
          </div>
        </div>
      </div>
    )
  }

  const busy = action.isPending
  const close = () => setDialog(null)
  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <div className={styles.titleRow}>
            <h1 className={styles.title}>Plugins</h1>
            <WikiInfoButton target="plugins" title="Open Plugins wiki page" size={15} />
          </div>
          <p className={styles.subtitle}>
            Optional features installed from the RedAmon plugin catalog:{' '}
            <a className={styles.catalogLink} href={CATALOG_REPO_URL} target="_blank" rel="noopener noreferrer">
              github.com/samugit83/redamon-plugins
              <ExternalLink size={12} />
            </a>
          </p>
          <div className={styles.platform}>RedAmon plugin platform {data.platformVersion}</div>
        </div>
        {data.managesPlugins && (
          <button type="button" className="secondaryButton" onClick={() => setDialog({ kind: 'offline' })} disabled={busy}>
            <Upload size={14} /> Install from file
          </button>
        )}
      </div>
      <div className={styles.status}>
        <RunnerStatusBanner />
        <CatalogStatus catalog={data.catalog} />
      </div>
      <PluginNavLinks />
      {data.plugins.length === 0 && data.catalog.state !== 'ok' ? (
        <div className="emptyState">
          <div className="emptyStateTitle">No plugins installed</div>
          <div className="emptyStateDescription">
            The catalog&apos;s plugins appear here once it can be read; until then an admin can use Install from file.
          </div>
        </div>
      ) : data.plugins.length === 0 ? (
        <div className="emptyState">
          <div className="emptyStateTitle">No plugins available</div>
          <div className="emptyStateDescription">The catalog lists no plugin for this RedAmon yet.</div>
        </div>
      ) : (
        <div className={styles.grid}>
          {data.plugins.map((p) => (
            <PluginCard key={p.id} entry={p} manages={data.managesPlugins} busy={busy} onAction={onAction} />
          ))}
        </div>
      )}

      {(dialog?.kind === 'install' || dialog?.kind === 'update') && dialog.entry.available && (
        <ConsentDialog
          isOpen
          mode={dialog.kind}
          pluginName={dialog.entry.displayName}
          version={dialog.kind === 'update' ? dialog.entry.update!.version : dialog.entry.available.version}
          permissions={dialog.entry.available.permissions}
          newPermissions={dialog.kind === 'update' ? dialog.entry.update?.newPermissions : undefined}
          migratesData={dialog.kind === 'update' ? dialog.entry.update?.migratesData : false}
          restoreCount={dialog.kind === 'install' ? dialog.restoreCount : 0}
          busy={busy}
          onCancel={close}
          onConfirm={async ({ restoreOverrides }) => {
            const e = dialog.entry
            const version = dialog.kind === 'update' ? e.update!.version : e.available!.version
            const body = {
              version,
              acceptedPermissions: e.available!.permissions.map((p) => p.id),
              ...(restoreOverrides !== undefined ? { restoreOverrides } : {}),
            }
            const out = await run(`/api/plugins/${e.id}/${dialog.kind}`, body)
            if (out) close()
          }}
        />
      )}
      {dialog?.kind === 'uninstall' && (
        <UninstallDialog
          isOpen
          pluginId={dialog.entry.id}
          pluginName={dialog.entry.displayName}
          busy={busy}
          keptOnly={dialog.keptOnly}
          onCancel={close}
          onConfirm={async (mode) => {
            const out = await run(`/api/plugins/${dialog.entry.id}/uninstall`, { mode, confirm: dialog.entry.id })
            if (out) close()
          }}
        />
      )}
      {details && (
        <PluginDetailsDrawer pluginId={details} isOpen busy={busy} onClose={() => setDetails(null)} onRollback={onRollback} />
      )}
      {dialog?.kind === 'offline' && (
        <OfflineInstallDialog
          isOpen
          busy={busy}
          installed={Object.fromEntries(
            data.plugins.flatMap((p) =>
              p.installed?.version
                ? [[p.id, { version: p.installed.version, dataVersion: p.installed.dataVersion, grantedPermissions: p.installed.grantedPermissions }]]
                : [],
            ),
          )}
          restoreCount={dialog.restoreCount ?? 0}
          onCancel={close}
          onSubmit={async (form) => {
            const out = await run('/api/plugins/offline-install', undefined, form)
            if (out) close()
          }}
        />
      )}
    </div>
  )
}
