'use client'

import { citationUrlAllowed } from '@/lib/navigator/events'
import type { CitationView } from './useNavigatorChat'
import styles from './Navigator.module.css'

/** The Sources list under an answer: "Page › Section", a docs link and the GitHub wiki link (§9.9). */
export function SourcesList({ citations }: { citations: readonly CitationView[] }) {
  const shown = citations.filter((c) => citationUrlAllowed(c.url) && citationUrlAllowed(c.mirror_url))
  if (!shown.length) return null
  return (
    <div className={styles.sources}>
      <div className={styles.sourcesTitle}>Sources</div>
      <ol>
        {shown.map((c) => (
          <li key={c.id}>
            <span className={styles.sourceId}>{c.id}</span> {c.title}{c.heading && c.heading !== c.title ? ` › ${c.heading}` : ''}
            {' · '}
            <a href={c.url} target="_blank" rel="noopener noreferrer">{c.url.startsWith('https://www.redamon.org') ? 'docs' : 'wiki'}</a>
            {c.url !== c.mirror_url && (
              <>{' · '}<a href={c.mirror_url} target="_blank" rel="noopener noreferrer">GitHub</a></>
            )}
          </li>
        ))}
      </ol>
    </div>
  )
}
