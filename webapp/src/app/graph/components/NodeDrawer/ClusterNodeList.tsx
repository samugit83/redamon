'use client'

import { useMemo, useState } from 'react'
import { ChevronRight, Search } from 'lucide-react'
import { GraphNode } from '../../types'
import { getNodeColor } from '../../utils'
import styles from './ClusterNodeList.module.css'

interface ClusterNodeListProps {
  cluster: GraphNode
  onSelectChild: (child: GraphNode) => void
}

function subtitleFor(node: GraphNode): string {
  const p = node.properties || {}
  const candidates = ['url', 'path', 'ip', 'port', 'service', 'severity', 'source']
  for (const k of candidates) {
    const v = p[k]
    if (v != null && v !== '') return `${k}: ${String(v)}`
  }
  return node.id
}

export function ClusterNodeList({ cluster, onSelectChild }: ClusterNodeListProps) {
  const children = cluster.clusterChildren ?? []
  const childType = cluster.clusterChildType ?? ''
  const [query, setQuery] = useState('')

  const filtered = useMemo(() => {
    if (!query) return children
    const q = query.toLowerCase()
    return children.filter(c =>
      c.name?.toLowerCase().includes(q) ||
      c.id.toLowerCase().includes(q),
    )
  }, [children, query])

  const color = cluster.clusterColor ?? getNodeColor(cluster)

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <span
          className={styles.typeBadge}
          style={{ backgroundColor: color }}
        >
          {childType}
        </span>
        <span className={styles.countText}>
          {children.length} node{children.length === 1 ? '' : 's'} in this cluster
        </span>
      </div>

      <div className={styles.searchWrap}>
        <Search size={14} className={styles.searchIcon} />
        <input
          className={styles.search}
          type="text"
          placeholder="Filter..."
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
      </div>

      <div className={styles.list}>
        {filtered.map(child => (
          <button
            key={child.id}
            className={styles.row}
            onClick={() => onSelectChild(child)}
          >
            <span className={styles.rowDot} style={{ backgroundColor: color }} />
            <span className={styles.rowText}>
              <span className={styles.rowName}>{child.name}</span>
              <span className={styles.rowSubtitle}>{subtitleFor(child)}</span>
            </span>
            <ChevronRight size={14} className={styles.rowChevron} />
          </button>
        ))}
        {filtered.length === 0 && (
          <p className={styles.empty}>No nodes match the filter</p>
        )}
      </div>
    </div>
  )
}
