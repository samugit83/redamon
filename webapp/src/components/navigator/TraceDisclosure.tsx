'use client'

import type { TraceView } from './useNavigatorChat'
import styles from './Navigator.module.css'

/** "How I got this": what each tool did, and the Cypher it ran. Never a tool's result. */
export function TraceDisclosure({ trace }: { trace: readonly TraceView[] }) {
  const steps = trace.filter((t) => t.tool !== 'handoff' && t.tool !== 'refused_route' && t.status !== 'start')
  if (!steps.length) return null
  return (
    <details className={styles.trace}>
      <summary>How I got this</summary>
      <ol>
        {steps.map((t, i) => (
          <li key={i} className={t.status === 'error' ? styles.traceError : undefined}>
            {t.summary}
            {t.detail && <pre className={styles.traceDetail}>{t.detail}</pre>}
          </li>
        ))}
      </ol>
    </details>
  )
}
