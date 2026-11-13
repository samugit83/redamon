'use client'

import Link from 'next/link'
import { useParams } from 'next/navigation'
import { ActivityFeed } from './ActivityFeed'
import styles from './page.module.css'

/** /projects/[id]/activity (step 4.13): the project's activity feed, reached from its settings page. */
export default function ProjectActivityPage() {
  const projectId = useParams().id as string
  return (
    <main className={styles.page}>
      <Link className={styles.back} href={`/projects/${encodeURIComponent(projectId)}/settings`}>Back to the project settings</Link>
      <ActivityFeed projectId={projectId} />
    </main>
  )
}
