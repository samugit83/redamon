import Link from 'next/link'
import styles from './page.module.css'

export default function Home() {
  return (
    <main className={styles.main}>
      <div className={styles.hero}>
        <h1 className={styles.title}>RedAmon</h1>
        <p className={styles.subtitle}>
          Security Reconnaissance Dashboard
        </p>
      </div>

      <div className={styles.grid}>
        <Link href="/dashboard" className={styles.card}>
          <h2>Dashboard</h2>
          <p>View reconnaissance data and scan results</p>
        </Link>

        <Link href="/targets" className={styles.card}>
          <h2>Targets</h2>
          <p>Manage and explore target information</p>
        </Link>

        <Link href="/scans" className={styles.card}>
          <h2>Scans</h2>
          <p>View vulnerability scan results</p>
        </Link>

        <Link href="/graph" className={styles.card}>
          <h2>Graph View</h2>
          <p>Visualize relationships in Neo4j</p>
        </Link>
      </div>
    </main>
  )
}
