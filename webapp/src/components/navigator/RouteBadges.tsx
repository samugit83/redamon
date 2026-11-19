'use client'

import { ROUTE_BADGES } from './messages'
import styles from './Navigator.module.css'

export function RouteBadges({ routes }: { routes: readonly string[] }) {
  const shown = routes.filter((r) => ROUTE_BADGES[r])
  if (!shown.length) return null
  return (
    <div className={styles.badges}>
      {shown.map((r) => (
        <span key={r} className={styles.badge} data-route={r}>{ROUTE_BADGES[r].icon} {ROUTE_BADGES[r].label}</span>
      ))}
    </div>
  )
}
