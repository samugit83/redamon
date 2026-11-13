'use client'

import { useCallback, useEffect, useState } from 'react'
import { readApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { QUOTA_FIELD_SPECS, type QuotaField } from '@/app/admin/instance/quotaModel'

type Source = { kind: 'user' | 'default' | 'off' | 'root' } | { kind: 'set'; setId: string; setName?: string }

export interface QuotaReportView {
  enforced: boolean
  quota: Record<QuotaField, number | null>
  sources: Record<QuotaField, Source>
  use: Partial<Record<QuotaField, number>>
}

type View =
  | { kind: 'loading' }
  | { kind: 'hidden' }
  | { kind: 'denied'; permission: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; report: QuotaReportView }

const LOAD_FAILED = "Couldn't load the quota"

function fromWords(s: Source, own: boolean): string {
  switch (s.kind) {
    case 'user': return own ? 'Set for you' : 'Set for this account'
    case 'set': return `Permission set ${s.setName ?? s.setId}`
    case 'default': return 'Instance default'
    default: return ''
  }
}

/**
 * One account's quota and use (step 6.8): My account shows the person's own (`own`), the admin user
 * detail another account's. Reads GET /api/users/[id]/quota; with RBAC_GOVERNANCE_ENABLED off that
 * route answers 404 and nothing is shown.
 */
export function QuotaUsage({ userId, own, classes = {} }: {
  userId: string
  own: boolean
  /** The host page's section and heading classes, so the section looks like its neighbours. */
  classes?: { section?: string; title?: string }
}) {
  const [view, setView] = useState<View>({ kind: 'loading' })

  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const res = await fetch(`/api/users/${encodeURIComponent(userId)}/quota`, { cache: 'no-store' })
      if (res.status === 404) {
        setView({ kind: 'hidden' })
        return
      }
      if (!res.ok) {
        const err = await readApiError(res, LOAD_FAILED)
        const permission = forbiddenPermission(err)
        setView(permission ? { kind: 'denied', permission } : { kind: 'error', message: err.message })
        return
      }
      const report = await res.json() as Partial<QuotaReportView> | null
      if (!report || typeof report.quota !== 'object' || typeof report.sources !== 'object' || !report.quota || !report.sources) {
        setView({ kind: 'error', message: `${LOAD_FAILED} (unexpected_answer)` })
        return
      }
      setView({ kind: 'ready', report: { enforced: report.enforced === true, quota: report.quota, sources: report.sources, use: report.use ?? {} } })
    } catch (err) {
      setView({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [userId])

  useEffect(() => { load() }, [load])

  if (view.kind === 'hidden') return null
  return (
    <section className={classes.section} aria-labelledby={`quota-${userId}-title`}>
      <h2 id={`quota-${userId}-title`} className={classes.title}>Quota</h2>
      {view.kind === 'loading' && <p role="status">Loading the quota…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'error' && (
        <div role="alert">
          {view.message}. <button type="button" className="textButton" onClick={load}>Retry</button>
        </div>
      )}
      {view.kind === 'ready' && !view.report.enforced && (
        <p>{view.report.sources.maxProjects?.kind === 'root' ? 'Root is never limited by a quota.' : 'No quota applies.'}</p>
      )}
      {view.kind === 'ready' && view.report.enforced && (
        <table className="table">
          <thead>
            <tr><th scope="col">Limit</th><th scope="col">Value</th><th scope="col">In use</th><th scope="col">From</th></tr>
          </thead>
          <tbody>
            {QUOTA_FIELD_SPECS.map((spec) => {
              const limit = view.report.quota[spec.field]
              const used = view.report.use[spec.field]
              return (
                <tr key={spec.field}>
                  <th scope="row">{spec.label}</th>
                  <td>{limit === null ? 'Unlimited' : `${limit} ${spec.unit}`}</td>
                  <td>{used === undefined ? 'Counted when it starts' : String(used)}</td>
                  <td>{fromWords(view.report.sources[spec.field], own)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </section>
  )
}
