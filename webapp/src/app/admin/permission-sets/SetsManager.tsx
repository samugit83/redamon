'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '@/providers/AuthProvider'
import { useAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { FULL_ADMIN_PROFILE, givableFrom, permissionsUrl, type AccountPermissionsView } from '@/components/admin/permissionModel'
import { ApiError, fetchJson, fetchOk, toApiError } from '@/lib/apiError'
import { groupByArea } from '@/lib/authz/permissionAreas'
import type { PermissionId } from '@/lib/authz/permissions'
import { defaultSetId, type SetKind, type SetListAnswer, type SetRow } from './setModel'
import { SET_WORDS } from './setWords'
import { SetEditor, type EditorMode } from './SetEditor'
import { SetHolders } from './SetHolders'
import { ConsoleHeader } from '../ConsoleHeader'
import { SECTION_ICONS } from '../consoleIcons'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import choiceStyles from '@/components/admin/UserPermissions.module.css'
import styles from './sets.module.css'

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; list: SetListAnswer }

const IN_USE = new Set(['set_in_use', 'profile_in_use'])

/**
 * The permission sets page and the admin profiles page (step 6.3; GV-02, GV-03): built-ins listed
 * read-only with Clone, custom ones with Edit, Clone and Delete, each with its permissions and its
 * holders, all through the Phase 3 API (step 3.11). The editor offers only what the signed-in person
 * may give (what they hold, read from their own permissions; the session's capabilities when that
 * read fails). A delete the server refuses because someone holds the set lists them (SetHolders);
 * any other refusal shows in the app's alert. The console shell (6.1) denies the page to anyone
 * without the section's permission before it renders.
 */
export function SetsManager({ kind }: { kind: SetKind }) {
  const words = SET_WORDS[kind]
  const alerts = useAlertModal()
  const { user: me, capabilities } = useAuth()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [mine, setMine] = useState<ReadonlySet<PermissionId> | null>(null)
  const [editing, setEditing] = useState<EditorMode | null>(null)
  const [holders, setHolders] = useState<{ set: SetRow; refusal?: string; nonce: number } | null>(null)
  const [deletingProfile, setDeletingProfile] = useState<SetRow | null>(null)
  const [notice, setNotice] = useState('')
  const nonce = useRef(0)
  const canWrite = capabilities.has(words.writePermission)
  const selfId = me?.id

  const readList = useCallback(
    () => fetchJson<SetListAnswer>(words.listUrl, { cache: 'no-store' }, `Could not list the ${words.title.toLowerCase()}`),
    [words],
  )

  // The list and what the person may give arrive together, so an editor never opens on a half answer.
  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    const own = selfId
      ? fetchJson<AccountPermissionsView>(permissionsUrl(selfId), { cache: 'no-store' }, 'Could not read your own permissions')
        .then((v) => givableFrom(v.explain), () => null)
      : Promise.resolve(null)
    try {
      const [list, givable] = await Promise.all([readList(), own])
      setMine(givable)
      setView({ kind: 'ready', list })
    } catch (err) {
      const error = toApiError(err, `Could not list the ${words.title.toLowerCase()}`)
      const permission = forbiddenPermission(error)
      setView(permission ? { kind: 'denied', permission } : { kind: 'error', message: error.message })
    }
  }, [readList, selfId, words])

  useEffect(() => { void load() }, [load])

  async function refresh() {
    try {
      setView({ kind: 'ready', list: await readList() })
    } catch (err) {
      setView({ kind: 'error', message: toApiError(err, `Could not list the ${words.title.toLowerCase()}`).message })
    }
  }

  function showHolders(set: SetRow, refusal?: string) {
    nonce.current += 1
    setHolders({ set, refusal, nonce: nonce.current })
  }

  function deleted(set: SetRow) {
    setNotice(`Deleted ${set.name}.`)
    if (holders?.set.id === set.id) setHolders(null)
    void refresh()
  }

  function deleteRefused(set: SetRow, error: ApiError) {
    if (error.code && IN_USE.has(error.code)) {
      showHolders(set, error.reason)
      void refresh()
      return
    }
    void alerts.alertError(error.message, `Delete ${set.name}`)
  }

  async function removeSet(set: SetRow) {
    setNotice('')
    if (kind === 'admin') {
      setDeletingProfile(set)
      return
    }
    const ok = await alerts.dangerConfirm(
      `Delete the ${words.one} ${set.name}? This cannot be undone. The server refuses while anyone holds it.`,
      `Delete ${words.one}`,
      { confirmLabel: 'Delete' },
    )
    if (!ok) return
    try {
      await fetchOk(words.itemUrl(set.id), { method: 'DELETE' }, `Could not delete the ${words.one}`)
      deleted(set)
    } catch (err) {
      deleteRefused(set, toApiError(err, `Could not delete the ${words.one}`))
    }
  }

  async function removeProfile(set: SetRow, stepUpPassword: string) {
    try {
      await fetchOk(words.itemUrl(set.id), {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stepUpPassword }),
      }, `Could not delete the ${words.one}`)
      deleted(set)
    } catch (err) {
      const error = toApiError(err, `Could not delete the ${words.one}`)
      // A conflict is about the profile, not the password: close the dialog and show it on the page.
      if (error.status !== 409) throw error
      deleteRefused(set, error)
    }
  }

  const givable = mine ?? capabilities

  return (
    <div className={consoleStyles.page}>
      <ConsoleHeader
        icon={SECTION_ICONS[kind === 'admin' ? 'admin-profiles' : 'permission-sets']}
        title={words.title}
        lead={words.lead}
        actions={canWrite && view.kind === 'ready' ? (
          <button type="button" className="primaryButton" onClick={() => { setNotice(''); setEditing({ kind: 'create' }) }}>
            {words.newLabel}
          </button>
        ) : undefined}
      />
      {notice && <div className={pageStyles.success} role="status">{notice}</div>}

      {view.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the {words.title.toLowerCase()}…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'error' && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={() => void load()}>Retry</button>
        </div>
      )}
      {view.kind === 'ready' && (
        <>
          {holders && (
            <SetHolders
              key={`${holders.set.id}:${holders.nonce}`}
              kind={kind}
              set={holders.set}
              refusal={holders.refusal}
              onClose={() => setHolders(null)}
            />
          )}
          <SetTable
            kind={kind}
            label={words.builtinLabel}
            rows={view.list.sets.filter((s) => s.builtin)}
            defaultId={kind === 'member' ? defaultSetId(view.list) : null}
            canWrite={canWrite}
            onClone={(s) => { setNotice(''); setEditing({ kind: 'create', source: s }) }}
            onHolders={(s) => showHolders(s)}
          />
          {view.list.sets.some((s) => !s.builtin) ? (
            <SetTable
              kind={kind}
              label={words.customLabel}
              rows={view.list.sets.filter((s) => !s.builtin)}
              defaultId={kind === 'member' ? defaultSetId(view.list) : null}
              canWrite={canWrite}
              onClone={(s) => { setNotice(''); setEditing({ kind: 'create', source: s }) }}
              onEdit={(s) => { setNotice(''); setEditing({ kind: 'edit', set: s }) }}
              onDelete={(s) => void removeSet(s)}
              onHolders={(s) => showHolders(s)}
            />
          ) : (
            <section className={styles.section} aria-label={words.customLabel}>
              <h2 className={styles.sectionTitle}>{words.customLabel}</h2>
              <p className={consoleStyles.state}>{words.emptyCustom}</p>
            </section>
          )}
        </>
      )}

      {editing && (
        <SetEditor
          kind={kind}
          mode={editing}
          givable={givable}
          onClose={() => setEditing(null)}
          onSaved={(message) => { setNotice(message); void refresh() }}
        />
      )}
      {kind === 'admin' && (
        <StepUpModal
          isOpen={deletingProfile !== null}
          title="Delete admin profile"
          message={deletingProfile
            ? `Delete the admin profile ${deletingProfile.name}? This cannot be undone. The server refuses while any admin holds it. Confirm with your password.`
            : ''}
          confirmLabel="Delete"
          onConfirm={async (password) => { if (deletingProfile) await removeProfile(deletingProfile, password) }}
          onClose={() => setDeletingProfile(null)}
        />
      )}
    </div>
  )
}

interface SetTableProps {
  kind: SetKind
  label: string
  rows: SetRow[]
  /** Member sets: the one new members get. */
  defaultId: string | null
  canWrite: boolean
  onClone: (set: SetRow) => void
  onEdit?: (set: SetRow) => void
  onDelete?: (set: SetRow) => void
  onHolders: (set: SetRow) => void
}

function SetTable({ kind, label, rows, defaultId, canWrite, onClone, onEdit, onDelete, onHolders }: SetTableProps) {
  return (
    <section className={styles.section}>
      <h2 className={styles.sectionTitle}>{label}</h2>
      <div className={styles.tableWrap}>
        <table className={pageStyles.table} aria-label={label}>
          <thead>
            <tr>
              <th scope="col" className={pageStyles.th}>Name</th>
              <th scope="col" className={pageStyles.th}>Permissions</th>
              <th scope="col" className={pageStyles.th}>Holders</th>
              <th scope="col" className={pageStyles.th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id} className={pageStyles.tr}>
                <th scope="row" className={`${pageStyles.td} ${styles.nameCell}`}>
                  <span className={pageStyles.cellStack}>
                    <span className={styles.setName}>
                      {s.name}
                      {s.id === defaultId && <span className={choiceStyles.tag}>Default for new members</span>}
                    </span>
                    {s.description && <span className={choiceStyles.description}>{s.description}</span>}
                    {kind === 'admin' && s.id === FULL_ADMIN_PROFILE && (
                      <span className={styles.muted}>Also held by every admin with no profile recorded.</span>
                    )}
                  </span>
                </th>
                <td className={pageStyles.td}><PermissionList permissions={s.permissions} /></td>
                <td className={pageStyles.td}>
                  <button type="button" className={styles.linkButton} aria-label={`Show who holds ${s.name}`} onClick={() => onHolders(s)}>
                    {s.holders} holder{s.holders === 1 ? '' : 's'}
                  </button>
                </td>
                <td className={pageStyles.td}>
                  {canWrite ? (
                    <div className={pageStyles.actions}>
                      {onEdit && (
                        <button type="button" className={pageStyles.actionButton} aria-label={`Edit ${s.name}`} onClick={() => onEdit(s)}>Edit</button>
                      )}
                      <button type="button" className={pageStyles.actionButton} aria-label={`Clone ${s.name}`} onClick={() => onClone(s)}>Clone</button>
                      {onDelete && (
                        <button
                          type="button"
                          className={`${pageStyles.actionButton} ${pageStyles.deleteButton}`}
                          aria-label={`Delete ${s.name}`}
                          onClick={() => onDelete(s)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  ) : (
                    <span className={styles.muted}>{s.builtin ? 'Built-in, read-only' : 'Read-only'}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function PermissionList({ permissions }: { permissions: readonly PermissionId[] }) {
  if (permissions.length === 0) return <span className={styles.muted}>No permissions</span>
  return (
    <details className={styles.permissions}>
      <summary>{permissions.length} permission{permissions.length === 1 ? '' : 's'}</summary>
      <div className={styles.permissionGroups}>
        {groupByArea(permissions.map((permission) => ({ permission }))).map(({ area, items }) => (
          <div key={area.id}>
            <p className={choiceStyles.areaTitle}>{area.title}</p>
            <ul className={styles.permissionList}>
              {items.map(({ permission }) => <li key={permission}><code className={choiceStyles.permission}>{permission}</code></li>)}
            </ul>
          </div>
        ))}
      </div>
    </details>
  )
}
