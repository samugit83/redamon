'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, Search, Folder } from 'lucide-react'
import { GraphNode } from '../../types'
import { badgeColors, getNodeColor } from '../../utils'
import styles from './ClusterNodeList.module.css'

interface ClusterNodeListProps {
  cluster: GraphNode
  onSelectChild: (child: GraphNode) => void
}

const ROW_HEIGHT = 44
const OVERSCAN = 6

function subtitleFor(node: GraphNode): string {
  if (node.isCluster) {
    const size = (node.properties?.cluster_size as number | undefined) ?? node.clusterChildren?.length ?? 0
    return `${size} item${size === 1 ? '' : 's'}`
  }
  const p = node.properties || {}
  const candidates = ['url', 'path', 'ip', 'port', 'service', 'severity', 'source', 'name', 'value']
  for (const k of candidates) {
    const v = p[k]
    if (v != null && v !== '') {
      const s = String(v)
      return `${k}: ${s.length > 60 ? s.slice(0, 60) + '...' : s}`
    }
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

  const scrollRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportHeight, setViewportHeight] = useState(400)

  // A new cluster or query starts the list from the top.
  const [listFor, setListFor] = useState({ clusterId: cluster.id, query })
  if (listFor.clusterId !== cluster.id || listFor.query !== query) {
    setListFor({ clusterId: cluster.id, query })
    setScrollTop(0)
  }
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 })
  }, [cluster.id, query])

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const ro = new ResizeObserver(() => setViewportHeight(el.clientHeight))
    ro.observe(el)
    setViewportHeight(el.clientHeight)
    return () => ro.disconnect()
  }, [])

  const totalHeight = filtered.length * ROW_HEIGHT
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2
  const endIndex = Math.min(filtered.length, startIndex + visibleCount)
  const offsetY = startIndex * ROW_HEIGHT

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <span
          className={styles.typeBadge}
          style={badgeColors(color)}
        >
          {childType}
        </span>
        <span className={styles.countText}>
          {children.length} node{children.length === 1 ? '' : 's'} in this cluster
          {filtered.length !== children.length && ` · ${filtered.length} match filter`}
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

      <div
        ref={scrollRef}
        className={styles.virtualScroll}
        onScroll={e => setScrollTop((e.target as HTMLDivElement).scrollTop)}
      >
        {filtered.length === 0 ? (
          <p className={styles.empty}>No nodes match the filter</p>
        ) : (
          <div className={styles.virtualSpacer} style={{ height: totalHeight }}>
            <div className={styles.virtualWindow} style={{ transform: `translateY(${offsetY}px)` }}>
              {filtered.slice(startIndex, endIndex).map(child => {
                const isNested = !!child.isCluster
                const dotColor = isNested ? (child.clusterColor ?? getNodeColor(child)) : color
                return (
                  <button
                    key={child.id}
                    className={styles.row}
                    style={{ height: ROW_HEIGHT }}
                    onClick={() => onSelectChild(child)}
                  >
                    {isNested ? (
                      <Folder size={12} className={styles.rowIcon} style={{ color: dotColor }} />
                    ) : (
                      <span className={styles.rowDot} style={{ backgroundColor: dotColor }} />
                    )}
                    <span className={styles.rowText}>
                      <span className={styles.rowName}>
                        {isNested && <span className={styles.nestedTag}>cluster</span>}
                        {child.name}
                      </span>
                      <span className={styles.rowSubtitle}>{subtitleFor(child)}</span>
                    </span>
                    <ChevronRight size={14} className={styles.rowChevron} />
                  </button>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
