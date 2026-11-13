'use client'

/**
 * The token's opt-in to the projects other people shared with its user (step 4.10, SH-42): off,
 * the token reaches only its user's own projects, as every token did before sharing. On, it also
 * reaches the shared ones, all of them or only those ticked. Shown only while sharing is in force
 * (/api/auth/me), so with the switch off the token screen is the one before sharing.
 *
 * The list is the user's own project list (`/api/projects`), whose rows say which are shared with
 * them (`myAccess.via`), so it never names a project the user could not open in the app.
 */
import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import styles from './McpTokensTab.module.css'

interface SharedProject {
  id: string
  name: string
  owner: string | null
}

interface Props {
  idPrefix: string
  include: boolean
  allowlist: readonly string[]
  disabled?: boolean
  onChange: (include: boolean, allowlist: string[]) => void
}

interface ProjectRow {
  id?: unknown
  name?: unknown
  myAccess?: { via?: unknown; owner?: { name?: unknown; email?: unknown } }
}

function sharedOf(rows: unknown): SharedProject[] {
  if (!Array.isArray(rows)) return []
  return (rows as ProjectRow[])
    .filter(r => typeof r.id === 'string' && r.myAccess?.via === 'share')
    .map(r => {
      const owner = r.myAccess?.owner
      const ownerName = typeof owner?.name === 'string' && owner.name ? owner.name
        : typeof owner?.email === 'string' ? owner.email : null
      return { id: r.id as string, name: typeof r.name === 'string' ? r.name : (r.id as string), owner: ownerName }
    })
}

export default function SharedProjectsField({ idPrefix, include, allowlist, disabled, onChange }: Props) {
  const [projects, setProjects] = useState<SharedProject[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!include || projects !== null) return
    let cancelled = false
    void (async () => {
      try {
        const r = await fetch('/api/projects')
        if (!r.ok) throw new Error(String(r.status))
        const rows = await r.json()
        if (!cancelled) setProjects(sharedOf(rows))
      } catch {
        if (!cancelled) setError('Could not load the projects shared with you.')
      }
    })()
    return () => { cancelled = true }
  }, [include, projects])

  // An allowlisted id no longer shared stays listed, so unticking it can still narrow the token.
  const listed = projects
    ? [...projects, ...allowlist.filter(id => !projects.some(p => p.id === id)).map(id => ({ id, name: id, owner: null }))]
    : []

  const toggle = (id: string) => {
    onChange(true, allowlist.includes(id) ? allowlist.filter(x => x !== id) : [...allowlist, id])
  }

  return (
    <fieldset className={styles.scopes} disabled={disabled}>
      <legend className="formLabel">Shared projects</legend>
      <label className={`${styles.scopeRow} ${include ? styles.scopeChecked : ''}`}>
        <input
          id={`${idPrefix}SharedInclude`}
          type="checkbox"
          className={styles.scopeCheckbox}
          checked={include}
          onChange={e => onChange(e.target.checked, e.target.checked ? [...allowlist] : [])}
        />
        <span className={styles.scopeText}>
          <span className={styles.scopeLabel}>Include projects shared with me</span>
          <span className={styles.scopeBlurb}>
            Off, the token reaches only your own projects. On, it can also read the projects other
            people shared with you, at the access they gave you: read tools only, never a change,
            a scan or a question that spends their model key. Turning it on asks for your password.
          </span>
        </span>
      </label>

      {include && (
        <div className={styles.scopeList} role="group" aria-label="Limit to these shared projects">
          {projects === null && !error && (
            <span className="formHint"><Loader2 size={12} className={styles.spin} /> Loading the projects shared with you…</span>
          )}
          {error && <span className="formHint">{error}</span>}
          {projects !== null && listed.length === 0 && (
            <span className="formHint">No project is shared with you yet. The token will reach the ones shared later.</span>
          )}
          {listed.length > 0 && (
            <span className="formHint">
              Tick projects to limit the token to them; with none ticked it reaches every project
              shared with you, now and later.
            </span>
          )}
          {listed.map(p => (
            <label key={p.id} className={`${styles.scopeRow} ${allowlist.includes(p.id) ? styles.scopeChecked : ''}`}>
              <input
                type="checkbox"
                className={styles.scopeCheckbox}
                checked={allowlist.includes(p.id)}
                onChange={() => toggle(p.id)}
              />
              <span className={styles.scopeText}>
                <span className={styles.scopeLabel}>{p.name}</span>
                {p.owner && <span className={styles.scopeBlurb}>Shared by {p.owner}</span>}
              </span>
            </label>
          ))}
        </div>
      )}
    </fieldset>
  )
}
