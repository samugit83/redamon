'use client'

/**
 * "<person> is running <kind> on this project" (step 5.11, SH-40): the strip a project page shows
 * while someone else writes the project, from GET /api/projects/[id]/writers, so a collaborator
 * knows why a start is refused (or, once E10 allows it, who they are writing beside) before
 * pressing it. The person's own runs are never listed: the page already shows them.
 *
 * Asked only when the open project's `myAccess` is the owner's or a write share's: with sharing
 * off there is no `myAccess` and nothing is fetched (DV-30); a Read share starts nothing. Polled
 * while the tab is visible. Loading, a failed read and a refused one show nothing: the strip only
 * informs, and the start route decides.
 */

import { useEffect, useState } from 'react'
import { Users } from 'lucide-react'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { useProjectAccess } from '@/hooks/useRefusal'
import type { OtherWritersView, WriterPerson } from '@/lib/authz/projectWriters'
import styles from './ProjectWriters.module.css'

export const WRITERS_POLL_MS = 30_000

function Person({ person }: { person: WriterPerson }) {
  if (person.deleted || !person.email) return <span className={styles.deleted}>a deleted account</span>
  return <IdentityLabel name={person.name} email={person.email} accountType={person.accountType ?? undefined} />
}

export function ProjectWriters({ projectId }: { projectId: string | null }) {
  const access = useProjectAccess(projectId)
  const asks = !!projectId && (access?.level === 'owner' || access?.level === 'write')
  const [view, setView] = useState<OtherWritersView | null>(null)

  useEffect(() => {
    setView(null)
    if (!asks || !projectId) return
    let live = true
    const read = async () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
      try {
        const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/writers`, { cache: 'no-store' })
        const body = res.ok ? await res.json().catch(() => null) as OtherWritersView | null : null
        if (live) setView(body && Array.isArray(body.writers) ? body : null)
      } catch {
        if (live) setView(null)
      }
    }
    void read()
    const timer = setInterval(read, WRITERS_POLL_MS)
    const onVisible = () => { if (document.visibilityState === 'visible') void read() }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      live = false
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [asks, projectId])

  if (!view || view.writers.length === 0) return null
  return (
    <div className={styles.banner} role="status" aria-live="polite" data-testid="project-writers">
      <Users size={14} className={styles.icon} aria-hidden="true" />
      <div className={styles.text}>
        {view.writers.map((w, i) => (
          <p key={`${i}|${w.kind}`} className={styles.line}>
            <Person person={w.person} /> is running {w.phrase} on this project.
          </p>
        ))}
        <span className={styles.hint}>
          {view.startsRefused
            ? 'You can start a scan or an agent run here once they finish.'
            : 'Your scans and agent runs write the same graph alongside theirs.'}
          {view.unverified ? ' Some writers could not be checked just now.' : ''}
        </span>
      </div>
    </div>
  )
}

export default ProjectWriters
