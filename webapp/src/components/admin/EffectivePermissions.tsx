'use client'

import { useId, useState } from 'react'
import { PERMISSIONS, type PermissionId } from '@/lib/authz/permissions'
import { groupByArea } from '@/lib/authz/permissionAreas'
import { reasonText, type ExplanationView } from './permissionModel'
import styles from './UserPermissions.module.css'

interface EffectivePermissionsProps {
  /** Every permission with its reasons (`explain` of GET /api/users/[id]/permissions). */
  explain: readonly ExplanationView[]
  /** The line shown when nothing is held. */
  emptyText?: string
  /**
   * A preview against what is saved: the permissions a change adds are tagged, and the ones it takes
   * away stay listed (tagged) even while the permissions not held are hidden.
   */
  changes?: { gained: ReadonlySet<PermissionId>; lost: ReadonlySet<PermissionId> }
}

const capitalized = (text: string) => text.charAt(0).toUpperCase() + text.slice(1)

/**
 * What an account holds now, by area, each permission with its "because" lines (PE-16, UI-12):
 * the set, override, legacy grant or Root standing that gives it, and an override's expiry and
 * reason. "Show the permissions not held" adds the others with why not (no set in force holds it,
 * a deny, an instance switch, the account's status).
 */
export function EffectivePermissions({ explain, emptyText = 'This account holds no permission.', changes }: EffectivePermissionsProps) {
  const toggleId = useId()
  const [showAll, setShowAll] = useState(false)
  const held = explain.filter((e) => e.held)
  const shown = showAll ? explain : explain.filter((e) => e.held || changes?.lost.has(e.permission))
  const groups = groupByArea(shown)

  return (
    <div className={styles.section}>
      <label className={styles.choice} htmlFor={toggleId}>
        <input id={toggleId} type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
        Show the permissions not held
      </label>
      {held.length === 0 && <p className={styles.description} role="status">{emptyText}</p>}
      <div className={styles.scroll}>
        {groups.map(({ area, items }) => (
          <section key={area.id} className={styles.area} aria-label={area.title}>
            <h4 className={styles.areaTitle}>{area.title}</h4>
            <ul className={styles.list}>
              {items.map((e) => (
                <li
                  key={e.permission}
                  className={`${styles.item}${changes?.gained.has(e.permission) ? ` ${styles.itemGained}` : ''}${changes?.lost.has(e.permission) ? ` ${styles.itemLost}` : ''}`}
                  aria-label={`${e.permission} ${e.held ? 'held' : 'not held'}`}
                >
                  <span>
                    <code className={styles.permission}>{e.permission}</code>
                    {changes?.gained.has(e.permission) && <span className={`${styles.tag} ${styles.tagGained}`}>added</span>}
                    {changes?.lost.has(e.permission) && <span className={`${styles.tag} ${styles.tagLost}`}>removed</span>}
                    {!e.held && !changes?.lost.has(e.permission) && <span className={styles.tag}>not held</span>}
                  </span>
                  <span className={styles.description}>{PERMISSIONS[e.permission].description}</span>
                  {e.reasons.length > 0 && (
                    <ul className={styles.because}>
                      {e.reasons.map((r, i) => (
                        <li key={i} className={r.effect === 'deny' ? styles.deny : undefined}>
                          {e.held ? `Because ${reasonText(r)}` : capitalized(reasonText(r))}
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </div>
  )
}

export default EffectivePermissions
