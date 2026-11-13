'use client'

import { GuardedLink } from '@/components/GuardedLink'
import { useConsoleSections } from './AdminConsole'
import styles from './admin.module.css'

/** The console's overview: the sections the person may open (the console shows the rest as denied). */
export default function AdminIndexPage() {
  const sections = useConsoleSections()
  return (
    <div className={styles.page}>
      <h1 className={styles.title}>Admin console</h1>
      {sections.length === 0 ? (
        <p className={styles.state}>No section of the console is open to you.</p>
      ) : (
        <>
          <p className={styles.lead}>The sections your permissions open.</p>
          <ul className={styles.cards} aria-label="Sections">
            {sections.map((s) => (
              <li key={s.id}>
                <GuardedLink href={s.href} className={styles.card}>
                  <span className={styles.cardTitle}>{s.label}</span>
                  <span className={styles.cardText}>{s.description}</span>
                </GuardedLink>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
