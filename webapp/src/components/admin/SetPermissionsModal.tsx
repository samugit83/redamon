'use client'

import { Modal } from '@/components/ui'
import { PERMISSIONS } from '@/lib/authz/permissions'
import { groupByArea } from '@/lib/authz/permissionAreas'
import { setRelations, type SetOption } from './permissionModel'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './UserPermissions.module.css'

interface SetPermissionsModalProps {
  /** The set or admin profile shown; null keeps the dialog closed. */
  set: SetOption | null
  /** Every set of the list, to say which ones this one contains, sits inside or equals. */
  all: readonly SetOption[]
  onClose: () => void
}

const names = (sets: readonly SetOption[]) => sets.map((s) => s.name).join(', ')

/**
 * One permission set's contents, by area, opened from the permission panel. Sets only grant, and an
 * account holds every permission of every set ticked, so the dialog also says how this set overlaps
 * the others: the ones it contains whole, the ones it sits inside, and the ones identical to it.
 *
 * Rendered from inside another dialog: Escape closes this one only (Modal's key handler would
 * otherwise bubble through the React tree to the dialog that opened it).
 */
export function SetPermissionsModal({ set, all, onClose }: SetPermissionsModalProps) {
  const relations = set ? setRelations(set, all) : null
  const groups = set ? groupByArea(set.permissions.map((permission) => ({ permission }))) : []
  const what = set?.kind === 'admin' ? 'profile' : 'set'

  return (
    <div className={styles.portalHost} onKeyDown={(e) => { if (e.key === 'Escape') e.stopPropagation() }}>
      <Modal
        isOpen={set !== null}
        onClose={onClose}
        title={set ? `${set.name}: ${set.permissions.length} permission${set.permissions.length === 1 ? '' : 's'}` : ''}
        size="large"
        footer={<button type="button" className="secondaryButton" onClick={onClose}>Close</button>}
      >
        {set && relations && (
          <div className={styles.panel}>
            <div className={styles.setSummary}>
              {set.description && <p className={pageStyles.message}>{set.description}</p>}
              <div className={styles.tags}>
                <span className={styles.tag}>{set.builtin ? 'built-in' : 'custom'}</span>
                {set.instanceDefault && <span className={styles.tag}>instance default</span>}
              </div>
            </div>

            {(relations.same.length > 0 || relations.includes.length > 0 || relations.within.length > 0) && (
              <ul className={styles.relations} aria-label="How it overlaps the other sets">
                {relations.same.length > 0 && (
                  <li><strong>Identical to</strong> {names(relations.same)}: ticking both gives nothing more.</li>
                )}
                {relations.includes.length > 0 && (
                  <li><strong>Contains everything in</strong> {names(relations.includes)}: ticking those with this {what} adds nothing.</li>
                )}
                {relations.within.length > 0 && (
                  <li><strong>Fully inside</strong> {names(relations.within)}: with one of those ticked, this {what} adds nothing.</li>
                )}
              </ul>
            )}

            {set.permissions.length === 0 ? (
              <p className={pageStyles.hint}>
                This {what} grants nothing. Ticked alone it leaves the account without permissions; ticked with other
                sets it changes nothing, because sets only add.
              </p>
            ) : (
              <div className={styles.areas}>
                {groups.map(({ area, items }) => (
                  <section key={area.id} className={styles.area} aria-label={area.title}>
                    <h4 className={styles.areaTitle}>{area.title} <span className={styles.areaCount}>{items.length}</span></h4>
                    <ul className={styles.list}>
                      {items.map(({ permission }) => (
                        <li key={permission} className={styles.item}>
                          <span>
                            <code className={styles.permission}>{permission}</code>
                            {PERMISSIONS[permission].level === 'W+X' && <span className={`${styles.tag} ${styles.tagDanger}`}>exploitation</span>}
                            {PERMISSIONS[permission].crossTenant && <span className={`${styles.tag} ${styles.tagDanger}`}>platform tool</span>}
                          </span>
                          <span className={styles.description}>{PERMISSIONS[permission].description}</span>
                        </li>
                      ))}
                    </ul>
                  </section>
                ))}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

export default SetPermissionsModal
