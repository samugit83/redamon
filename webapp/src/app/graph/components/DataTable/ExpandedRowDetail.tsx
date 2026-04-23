'use client'

import { memo, useMemo } from 'react'
import { NODE_COLORS } from '../../config'
import { renderPropertyValue } from '../../utils/renderPropertyValue'
import type { TableRow } from '../../hooks/useTableData'
import styles from './ExpandedRowDetail.module.css'

interface ExpandedRowDetailProps {
  row: TableRow
}

const HIDDEN_KEYS = new Set(['project_id', 'user_id'])

export const ExpandedRowDetail = memo(function ExpandedRowDetail({ row }: ExpandedRowDetailProps) {
  const properties = Object.entries(row.node.properties)
    .filter(([key]) => !HIDDEN_KEYS.has(key))
    .sort(([a], [b]) => a.localeCompare(b))

  // Lazy BFS: computed on first expand, cached thereafter
  const level2 = useMemo(() => row.getLevel2(), [row])
  const level3 = useMemo(() => row.getLevel3(), [row])

  return (
    <div className={styles.detail}>
      <div className={styles.sections}>
        {/* Properties */}
        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>Properties</h4>
          {properties.length === 0 ? (
            <p className={styles.empty}>No properties</p>
          ) : (
            <div className={styles.propsGrid}>
              {properties.map(([key, value]) => (
                <div key={key} className={styles.propRow}>
                  <span className={styles.propKey}>{key}</span>
                  <span className={styles.propValue}>{renderPropertyValue(value)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Connections In */}
        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Connections In
            <span className={styles.connCount}>{row.connectionsIn.length}</span>
          </h4>
          {row.connectionsIn.length === 0 ? (
            <p className={styles.empty}>No incoming connections</p>
          ) : (
            <div className={styles.connList}>
              {row.connectionsIn.map((conn, i) => (
                <div key={`${conn.nodeId}-${conn.relationType}-${i}`} className={styles.connItem}>
                  <span
                    className={styles.connDot}
                    style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }}
                  />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                  <span className={styles.connRel}>{conn.relationType}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Connections Out */}
        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Connections Out
            <span className={styles.connCount}>{row.connectionsOut.length}</span>
          </h4>
          {row.connectionsOut.length === 0 ? (
            <p className={styles.empty}>No outgoing connections</p>
          ) : (
            <div className={styles.connList}>
              {row.connectionsOut.map((conn, i) => (
                <div key={`${conn.nodeId}-${conn.relationType}-${i}`} className={styles.connItem}>
                  <span
                    className={styles.connDot}
                    style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }}
                  />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                  <span className={styles.connRel}>{conn.relationType}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Level 2 */}
        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Level 2 (2 hops)
            <span className={styles.connCount}>{level2.length}</span>
          </h4>
          {level2.length === 0 ? (
            <p className={styles.empty}>No 2nd-level connections</p>
          ) : (
            <div className={styles.connList}>
              {level2.map((conn, i) => (
                <div key={`l2-${conn.nodeId}-${i}`} className={styles.connItem}>
                  <span
                    className={styles.connDot}
                    style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }}
                  />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Level 3 */}
        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Level 3 (3 hops)
            <span className={styles.connCount}>{level3.length}</span>
          </h4>
          {level3.length === 0 ? (
            <p className={styles.empty}>No 3rd-level connections</p>
          ) : (
            <div className={styles.connList}>
              {level3.map((conn, i) => (
                <div key={`l3-${conn.nodeId}-${i}`} className={styles.connItem}>
                  <span
                    className={styles.connDot}
                    style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }}
                  />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
})
