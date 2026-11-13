'use client'

import { useCallback, useEffect, useState } from 'react'
import { useAlertModal, useToast } from '@/components/ui'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { readApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import { Panel } from './Panel'
import styles from './instance.module.css'

interface Template {
  id: string
  name: string
  severity: string
  path: string
  ownership: 'own' | 'instance' | 'other'
  owner?: string | null
}

type View =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'denied'; permission: string }
  | { kind: 'ready'; templates: Template[] }

const TEMPLATES_URL = '/api/nuclei-templates'
const LOAD_FAILED = "Couldn't load the Nuclei templates"
const MANAGE_ALL = 'platform:nuclei_templates'

function ownerText(t: Template): string {
  if (t.ownership === 'instance') return 'Instance'
  if (t.ownership === 'own') return 'You'
  return t.owner ?? 'A deleted account'
}

/**
 * The custom Nuclei templates (step 1.12, HD-08) for whoever manages every one
 * (platform:nuclei_templates): the instance templates every project may select, and each account's
 * own. A template becomes an instance template (PATCH, promote) or is deleted (DELETE); both are
 * the templates route's, which checks the permission and audits each change. Uploading stays in a
 * project's Nuclei settings.
 */
export function NucleiTemplatesPanel() {
  const toast = useToast()
  const alerts = useAlertModal()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [busy, setBusy] = useState<string | null>(null)

  const adopt = useCallback((body: { templates?: Template[]; canManageAll?: boolean }) => {
    setView(body.canManageAll === true
      ? { kind: 'ready', templates: body.templates ?? [] }
      : { kind: 'denied', permission: MANAGE_ALL })
  }, [])

  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const res = await fetch(TEMPLATES_URL, { cache: 'no-store' })
      if (!res.ok) throw await readApiError(res, LOAD_FAILED)
      adopt(await res.json())
    } catch (err) {
      setView({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [adopt])

  useEffect(() => { load() }, [load])

  const act = useCallback(async (t: Template, action: 'promote' | 'delete') => {
    const ok = action === 'promote'
      ? await alerts.confirm(
        `"${t.path}" becomes an instance template: every project on the instance may select it, and it no longer belongs to ${ownerText(t) === 'You' ? 'you' : ownerText(t)}.`,
        'Make it an instance template?',
        { confirmLabel: 'Make it an instance template' },
      )
      : await alerts.dangerConfirm(
        `"${t.path}" is deleted from the templates folder. Projects that selected it stop using it at their next scan.`,
        'Delete this template?',
        { confirmLabel: 'Delete' },
      )
    if (!ok) return
    setBusy(t.path)
    try {
      const res = action === 'promote'
        ? await fetch(TEMPLATES_URL, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: t.path, promote: true }) })
        : await fetch(`${TEMPLATES_URL}?path=${encodeURIComponent(t.path)}`, { method: 'DELETE' })
      const failure = action === 'promote' ? 'The template was not made an instance template' : 'The template was not deleted'
      if (!res.ok) {
        const err = await readApiError(res, failure)
        const permission = forbiddenPermission(err)
        await alerts.alertError(permission ? `${failure}: it needs ${permission}.` : err.message)
        return
      }
      adopt(await res.json())
      toast.success(action === 'promote' ? 'Template made an instance template' : 'Template deleted')
    } catch (err) {
      await alerts.alertError(failureText(action === 'promote' ? 'The template was not made an instance template' : 'The template was not deleted', err))
    } finally {
      setBusy(null)
    }
  }, [alerts, toast, adopt])

  const lead = 'Custom templates in the shared templates folder. An instance template is selectable in every project; any other belongs to the account that uploaded it.'
  let body
  if (view.kind === 'loading') body = <p className={styles.state} role="status">Loading the templates…</p>
  else if (view.kind === 'denied') body = <ForbiddenNotice permission={view.permission} />
  else if (view.kind === 'error') {
    body = (
      <div className={styles.error} role="alert">
        {view.message}.{' '}
        <button type="button" className="textButton" onClick={load}>Retry</button>
      </div>
    )
  } else if (view.templates.length === 0) {
    body = <p className={styles.state}>No custom template yet. Templates are uploaded from a project&apos;s Nuclei settings.</p>
  } else {
    body = (
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <caption className={styles.note} style={{ textAlign: 'left', captionSide: 'top' }}>{view.templates.length} template(s)</caption>
          <thead>
            <tr><th scope="col">Template</th><th scope="col">Severity</th><th scope="col">Owner</th><th scope="col">Actions</th></tr>
          </thead>
          <tbody>
            {view.templates.map((t) => (
              <tr key={t.path}>
                <td><code>{t.path}</code>{t.name && <><br /><span className={styles.hint}>{t.name}</span></>}</td>
                <td><span className={styles.badge}>{t.severity}</span></td>
                <td>{ownerText(t)}</td>
                <td>
                  <div className={styles.actions}>
                    {t.ownership !== 'instance' && (
                      <button
                        type="button"
                        className="secondaryButton"
                        disabled={busy !== null}
                        aria-label={`Make ${t.path} an instance template`}
                        onClick={() => act(t, 'promote')}
                      >
                        Make instance template
                      </button>
                    )}
                    <button
                      type="button"
                      className="secondaryButton"
                      disabled={busy !== null}
                      aria-label={`Delete ${t.path}`}
                      onClick={() => act(t, 'delete')}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }

  return <Panel id="nuclei" title="Nuclei templates" lead={lead}>{body}</Panel>
}
