'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { usePasswordPolicy } from '@/hooks/usePasswordPolicy'
import { useAlertModal } from '@/components/ui'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { UserPermissionsPanel } from '@/components/admin/UserPermissionsPanel'
import { RoleControl } from '@/components/admin/RoleControl'
import { fetchJson, fetchOk, toApiError } from '@/lib/apiError'
import type { DirectoryRow, UserDetail } from '@/lib/authz/userDirectory'
import type { AuditRowView } from '@/lib/authz/auditReader'
import { LastLogin, SetsCell, StatusCell, TypeBadge } from '../UserFacts'
import { UserRowActions } from '../UserRowActions'
import consoleStyles from '../../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from '../users.module.css'

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  | { kind: 'missing' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; detail: UserDetail }

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : null)
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' })

/**
 * One account in the admin console (step 6.2; GV-01, ID-27): its profile and status, its permission
 * sets and overrides with what it holds and why (the Users page's panel), its own and shared
 * projects, its MCP tokens (listed, and revoked by whoever may sign it out), and its latest audit
 * rows as actor or target. The actions are the directory row's. Each section asks its own route,
 * so a section the person may not read says so and the others still show.
 */
export default function AdminUserDetailPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const { user: me } = useAuth()
  const policy = usePasswordPolicy(true)
  const [view, setView] = useState<View>({ kind: 'loading' })

  const load = useCallback(async () => {
    try {
      const detail = await fetchJson<UserDetail>(`/api/admin/users/${encodeURIComponent(id)}`, { cache: 'no-store' }, 'Could not read the account')
      setView({ kind: 'ready', detail })
    } catch (err) {
      const error = toApiError(err, 'Could not read the account')
      const permission = forbiddenPermission(error)
      if (permission) setView({ kind: 'denied', permission })
      else if (error.status === 404) setView({ kind: 'missing' })
      else setView({ kind: 'error', message: error.message })
    }
  }, [id])

  useEffect(() => { void load() }, [load])

  // The directory's "Permissions" link names the section, which exists only once the account is read.
  const ready = view.kind === 'ready'
  useEffect(() => {
    if (ready && window.location.hash === '#permissions') document.getElementById('permissions')?.scrollIntoView?.()
  }, [ready])

  const back = <Link href="/admin/users" className={styles.back}>← All users</Link>
  if (view.kind === 'loading') return <div className={consoleStyles.page}>{back}<p className={consoleStyles.state} role="status">Loading the account…</p></div>
  if (view.kind === 'denied') return <div className={consoleStyles.page}>{back}<ForbiddenNotice permission={view.permission} /></div>
  if (view.kind === 'missing') {
    return <div className={consoleStyles.page}>{back}<p className={consoleStyles.state} role="alert">This account does not exist; it may have been deleted.</p></div>
  }
  if (view.kind === 'error') {
    return (
      <div className={consoleStyles.page}>
        {back}
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={() => { setView({ kind: 'loading' }); void load() }}>Retry</button>
        </div>
      </div>
    )
  }

  const { user, owned, shared, audit } = view.detail
  const reload = () => void load()
  const confirmedRoot = me?.accountType === 'root' && me?.rbac?.root?.confirmed === true

  return (
    <div className={consoleStyles.page}>
      {back}
      <div className={styles.headline}>
        <h1 className={consoleStyles.title}>
          {user.name}{user.self && <span className={pageStyles.selfLabel}>(you)</span>}
        </h1>
        <UserRowActions row={user} policy={policy} permissionsLink={false} onChanged={reload} onDeleted={() => router.push('/admin/users')} />
      </div>

      <section className={styles.section} aria-labelledby="user-profile">
        <h2 id="user-profile" className={styles.sectionTitle}>Profile</h2>
        <IdentityLabel name={user.name} email={user.email} accountType={user.accountType} />
        <dl className={styles.facts}>
          <dt>Type</dt>
          <dd>
            <TypeBadge type={user.accountType} />
            {confirmedRoot && !user.self && user.accountType !== 'root' && (
              <> <RoleControl user={{ id: user.id, name: user.name, role: user.accountType === 'admin' ? 'admin' : 'standard' }} identity className={pageStyles.select} onChanged={reload} /></>
            )}
          </dd>
          <dt>Status</dt>
          <dd><StatusCell status={user.status} mustChange={user.mustChangePassword} /></dd>
          <dt>{user.accountType === 'admin' ? 'Admin profile' : 'Permission sets'}</dt>
          <dd><SetsCell row={user} /></dd>
          <dt>Last sign-in</dt>
          <dd><LastLogin at={user.lastLoginAt} /></dd>
          <dt>Account created</dt>
          <dd>{day(user.createdAt)}</dd>
        </dl>
      </section>

      <section id="permissions" className={styles.section} aria-labelledby="user-permissions">
        <h2 id="user-permissions" className={styles.sectionTitle}>Permissions</h2>
        <PermissionsSection user={user} selfId={me?.id} onChanged={reload} />
      </section>

      <section className={styles.section} aria-labelledby="user-projects">
        <h2 id="user-projects" className={styles.sectionTitle}>Projects</h2>
        <h3 className={pageStyles.label}>Owned ({owned.length})</h3>
        {owned.length === 0 ? <p className={consoleStyles.state}>This account owns no project.</p> : (
          <div className={styles.tableWrap}>
            <table className={pageStyles.table} aria-label="Owned projects">
              <thead>
                <tr>
                  <th scope="col" className={pageStyles.th}>Project</th>
                  {owned.some((p) => p.targetLabel !== undefined) && <th scope="col" className={pageStyles.th}>Scope</th>}
                  <th scope="col" className={pageStyles.th}>Created</th>
                  <th scope="col" className={pageStyles.th}>Updated</th>
                </tr>
              </thead>
              <tbody>
                {owned.map((p) => (
                  <tr key={p.id} className={pageStyles.tr}>
                    <td className={pageStyles.td}>{p.name}</td>
                    {owned.some((o) => o.targetLabel !== undefined) && <td className={pageStyles.td}>{p.targetLabel}</td>}
                    <td className={pageStyles.td}>{day(p.createdAt)}</td>
                    <td className={pageStyles.td}>{day(p.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <h3 className={pageStyles.label}>Shared with this account</h3>
        {shared.state === 'off' && <p className={consoleStyles.state}>Sharing is not in force: no project is shared.</p>}
        {shared.state === 'hidden' && (
          <p className={consoleStyles.state}>Root&apos;s sharing policy does not show administrators the projects shared between accounts.</p>
        )}
        {shared.state === 'listed' && (shared.projects.length === 0 ? <p className={consoleStyles.state}>No project is shared with this account.</p> : (
          <div className={styles.tableWrap}>
            <table className={pageStyles.table} aria-label="Projects shared with this account">
              <thead>
                <tr>
                  <th scope="col" className={pageStyles.th}>Project</th>
                  <th scope="col" className={pageStyles.th}>Owner</th>
                  <th scope="col" className={pageStyles.th}>Level</th>
                  <th scope="col" className={pageStyles.th}>Expires</th>
                </tr>
              </thead>
              <tbody>
                {shared.projects.map((p) => (
                  <tr key={p.id} className={pageStyles.tr}>
                    <td className={pageStyles.td}>{p.name}</td>
                    <td className={pageStyles.td}><IdentityLabel name={p.owner.name} email={p.owner.email} /></td>
                    <td className={pageStyles.td}>{p.access === 'write' ? 'Write' : 'Read'}</td>
                    <td className={pageStyles.td}>{p.expiresAt ? day(p.expiresAt) : 'Never'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </section>

      <section className={styles.section} aria-labelledby="user-tokens">
        <h2 id="user-tokens" className={styles.sectionTitle}>MCP tokens</h2>
        <McpTokensSection user={user} canRevoke={user.self || user.actions.includes('revoke_sessions')} />
      </section>

      <section className={styles.section} aria-labelledby="user-activity">
        <h2 id="user-activity" className={styles.sectionTitle}>Recent activity</h2>
        {'denied' in audit ? <ForbiddenNotice permission={audit.denied} /> : <AuditRows userId={user.id} rows={audit.rows} />}
      </section>
    </div>
  )
}

/** The account's sets, overrides and effective permissions, for whoever may assign them (the Users page's panel). */
function PermissionsSection({ user, selfId, onChanged }: { user: DirectoryRow; selfId: string | undefined; onChanged: () => void }) {
  if (user.accountType === 'root') return <p className={consoleStyles.state}>Root holds every permission; nobody changes Root&apos;s permissions.</p>
  if (user.self) {
    return <p className={consoleStyles.state}>Nobody changes their own permissions. Yours, with the reason for each, are on <Link href="/account">My account</Link>.</p>
  }
  if (user.actions.includes('assign_permissions') && selfId) {
    return <UserPermissionsPanel user={{ id: user.id, name: user.name, email: user.email }} selfId={selfId} onChanged={onChanged} />
  }
  if (user.accountType === 'admin') {
    return (
      <p className={consoleStyles.state}>
        Another admin&apos;s permissions are Root&apos;s to change, or those of an admin holding admins:manage over a narrower profile.
      </p>
    )
  }
  return <ForbiddenNotice permission="users:assign_permissions" />
}

interface TokenRow {
  id: string
  name: string
  tokenPrefix: string
  scopes: string[]
  lastUsedAt: string | null
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string
}

type TokenView =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string | null; message: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; tokens: TokenRow[] }

function tokenState(t: TokenRow): string {
  if (t.revokedAt) return 'Revoked'
  if (t.expiresAt && new Date(t.expiresAt).getTime() <= Date.now()) return 'Expired'
  return 'Active'
}

/**
 * The account's MCP tokens (GET /api/users/[id]/mcp-tokens, open to users:read) and their revocation
 * (DELETE .../[tokenId]: users:revoke_sessions on another account, audited `mcp-token.delete`). Root's
 * tokens are Root's own: the route refuses them, and the refusal is shown.
 */
function McpTokensSection({ user, canRevoke }: { user: DirectoryRow; canRevoke: boolean }) {
  const alerts = useAlertModal()
  const [view, setView] = useState<TokenView>({ kind: 'loading' })
  const base = `/api/users/${encodeURIComponent(user.id)}/mcp-tokens`

  const load = useCallback(async () => {
    try {
      const answer = await fetchJson<{ tokens: TokenRow[] }>(base, { cache: 'no-store' }, 'Could not list the MCP tokens')
      setView({ kind: 'ready', tokens: answer.tokens ?? [] })
    } catch (err) {
      const error = toApiError(err, 'Could not list the MCP tokens')
      setView(error.status === 403 ? { kind: 'denied', permission: forbiddenPermission(error), message: error.message } : { kind: 'error', message: error.message })
    }
  }, [base])

  useEffect(() => { void load() }, [load])

  async function revoke(t: TokenRow) {
    const ok = await alerts.dangerConfirm(
      `Revoke the MCP token "${t.name}" (${t.tokenPrefix}…) of ${user.name}? An agent using it is refused from its next call. This cannot be undone.`,
      'Revoke MCP token',
      { confirmLabel: 'Revoke' },
    )
    if (!ok) return
    try {
      await fetchOk(`${base}/${encodeURIComponent(t.id)}`, { method: 'DELETE' }, 'Could not revoke the token')
    } catch (err) {
      void alerts.alertError(toApiError(err, 'Could not revoke the token').message, 'MCP token')
    }
    await load()
  }

  if (view.kind === 'loading') return <p className={consoleStyles.state} role="status">Loading the tokens…</p>
  if (view.kind === 'denied') return view.permission ? <ForbiddenNotice permission={view.permission} /> : <p className={consoleStyles.state} role="alert">{view.message}</p>
  if (view.kind === 'error') {
    return (
      <div className={pageStyles.errorState}>
        <div className={pageStyles.error} role="alert">{view.message}</div>
        <button type="button" className={pageStyles.actionButton} onClick={() => { setView({ kind: 'loading' }); void load() }}>Retry</button>
      </div>
    )
  }
  if (view.tokens.length === 0) return <p className={consoleStyles.state}>This account has no MCP token.</p>
  return (
    <div className={styles.tableWrap}>
      <table className={pageStyles.table} aria-label="MCP tokens">
        <thead>
          <tr>
            <th scope="col" className={pageStyles.th}>Name</th>
            <th scope="col" className={pageStyles.th}>Prefix</th>
            <th scope="col" className={pageStyles.th}>Scopes</th>
            <th scope="col" className={pageStyles.th}>Last used</th>
            <th scope="col" className={pageStyles.th}>Expires</th>
            <th scope="col" className={pageStyles.th}>State</th>
            {canRevoke && <th scope="col" className={pageStyles.th}>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {view.tokens.map((t) => (
            <tr key={t.id} className={pageStyles.tr}>
              <td className={pageStyles.td}>{t.name}</td>
              <td className={pageStyles.td}><code>{t.tokenPrefix}</code></td>
              <td className={pageStyles.td}>{t.scopes.join(', ')}</td>
              <td className={pageStyles.td}>{when(t.lastUsedAt) ?? 'Never'}</td>
              <td className={pageStyles.td}>{t.expiresAt ? day(t.expiresAt) : 'Never'}</td>
              <td className={pageStyles.td}>{tokenState(t)}</td>
              {canRevoke && (
                <td className={pageStyles.td}>
                  <button
                    type="button"
                    className={`${pageStyles.actionButton} ${pageStyles.deleteButton}`}
                    aria-label={`Revoke the MCP token ${t.name}`}
                    onClick={() => void revoke(t)}
                  >
                    Revoke
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** The latest audit rows about the account: who, what and when; the details are the audit viewer's. */
function AuditRows({ userId, rows }: { userId: string; rows: AuditRowView[] }) {
  if (rows.length === 0) return <p className={consoleStyles.state}>No audit row names this account yet.</p>
  const who = (r: AuditRowView) => (r.actorId === userId ? 'This account' : r.actorEmail ?? (r.actorId ? 'Another account' : 'The system'))
  const target = (r: AuditRowView) => (r.targetType === 'user' && r.targetId === userId ? 'This account' : r.targetType)
  return (
    <div className={styles.tableWrap}>
      <table className={pageStyles.table} aria-label="Recent audit rows">
        <thead>
          <tr>
            <th scope="col" className={pageStyles.th}>When</th>
            <th scope="col" className={pageStyles.th}>Action</th>
            <th scope="col" className={pageStyles.th}>By</th>
            <th scope="col" className={pageStyles.th}>On</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className={pageStyles.tr}>
              <td className={pageStyles.td}><time dateTime={r.createdAt}>{when(r.createdAt)}</time></td>
              <td className={pageStyles.td}><code>{r.action}</code></td>
              <td className={pageStyles.td}>
                {who(r)}
                {r.onBehalfOfUserId && <span className={styles.muted}> (while acting as an account)</span>}
              </td>
              <td className={pageStyles.td}>{target(r)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
