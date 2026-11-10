'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Loader2, ArrowRight, Plus, Minus, RefreshCw, ShieldAlert, Download, X } from 'lucide-react'
import type { ScanVersionSummary } from '../../hooks/useScanVersions'
import type { GraphNode, DeltaState } from '../../types'
import { SecretValue, WikiInfoButton } from '@/components/ui'
import { readApiError, toApiError } from '@/lib/apiError'
import { GraphCanvas } from '../GraphCanvas'
import { useDimensions } from '../../hooks'
import styles from './ReconDeltaTable.module.css'
import {
  UpdatedAtCell,
  UpdatedAtTh,
  nodeUpdatedAt,
  sortByUpdatedAt,
  useUpdatedAtSortDir,
  type SortDir,
} from '../RedZoneTables/updatedAt'
import { NodeIdCell, NodeIdTh } from '../RedZoneTables/nodeId'
import { isSecretValueProp } from '@/lib/secrets/secretProps'
import { secretTail } from '@/lib/secrets/secretTail'

interface FieldChange { field: string; from: unknown; to: unknown }
interface DeltaNode {
  key: string; type: string; name: string; properties: Record<string, unknown>
  /** The live graph's id for this asset; null for a node only a stored version has. */
  nodeId?: string | null
}
interface ChangedNode extends DeltaNode { changes: FieldChange[] }
interface TypeScore { type: string; added: number; removed: number; changed: number; fromCount: number; toCount: number }
interface DeltaLink { type: string; sourceName: string; targetName: string }

export interface ReconDeltaResponse {
  from: { versionId: string; label: string }
  to: { versionId: string; label: string }
  addedNodes: DeltaNode[]
  removedNodes: DeltaNode[]
  changedNodes: ChangedNode[]
  addedLinks: DeltaLink[]
  removedLinks: DeltaLink[]
  scorecard: TypeScore[]
  totals: {
    fromNodes: number; toNodes: number; added: number; removed: number
    changed: number; stable: number; addedLinks: number; removedLinks: number
  }
  lenses: {
    newlyExposedPorts: DeltaNode[]
    closedPorts: DeltaNode[]
    newVulnerabilities: DeltaNode[]
    resolvedVulnerabilities: DeltaNode[]
    newCves: DeltaNode[]
    technologyVersionChanges: ChangedNode[]
    certificateChanges: DeltaNode[]
    newParameters: DeltaNode[]
  }
  coverage?: {
    sources: string[]
    skippedHosts: number
    nucleiTruncated: boolean
  } | null
}

interface OverlayPayload {
  nodes: Array<GraphNode & { deltaState: DeltaState }>
  links: Array<{ source: string; target: string; type: string }>
}

interface ReconDeltaTableProps {
  projectId: string | null
  versions: ScanVersionSummary[]
  isDark?: boolean
}

type Section = 'added' | 'removed' | 'changed' | 'links' | 'security' | 'overlay'

const CURRENT = 'current'

function renderValue(v: unknown): string {
  if (v === null || v === undefined) return '-'
  if (Array.isArray(v)) return v.join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

/** A compact, readable identity for a node row. */
function describe(n: DeltaNode): string {
  return n.name || n.key.split('::')[1] || n.key
}

/**
 * Scan Timeline - Recon Delta (Section 6.2).
 *
 * MVP surface first: new / removed / changed nodes with per-field old → new, plus
 * the change scorecard. The security lenses (newly exposed ports, new and
 * resolved vulns, technology drift, certificate changes, new parameters) are
 * derived from the same diff, so they cost nothing extra to show.
 */
export function ReconDeltaTable({ projectId, versions, isDark = true }: ReconDeltaTableProps) {
  const current = versions.find(v => v.isCurrent)
  const comparable = useMemo(
    () => versions.filter(v => v.isCurrent || v.activatable),
    [versions]
  )
  const defaultFrom = comparable.find(v => !v.isCurrent)?.id ?? CURRENT

  const [from, setFrom] = useState<string>(defaultFrom)
  const [to, setTo] = useState<string>(CURRENT)
  const [data, setData] = useState<ReconDeltaResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [section, setSection] = useState<Section>('added')
  const { sortDir, toggleSort } = useUpdatedAtSortDir()
  // Overlay (Section 6.3) is fetched separately and only when opened - it returns
  // the union of both versions, which is up to twice the render set.
  const [overlay, setOverlay] = useState<OverlayPayload | null>(null)
  const [overlayLoading, setOverlayLoading] = useState(false)
  const [overlayError, setOverlayError] = useState<string | null>(null)
  // Which (project, from, to) the overlay has already been attempted for. A ref,
  // not state, precisely so the fetch effect does not depend on anything it sets.
  const overlayAttemptRef = useRef<string | null>(null)
  const [changesOnly, setChangesOnly] = useState(true)
  const [selectedNode, setSelectedNode] = useState<(GraphNode & { deltaState: DeltaState }) | null>(null)

  useEffect(() => { setFrom(defaultFrom) }, [defaultFrom])
  // A new comparison invalidates whatever overlay was on screen.
  useEffect(() => {
    setOverlay(null)
    setOverlayError(null)
    setSelectedNode(null)
    overlayAttemptRef.current = null
  }, [from, to, projectId])

  // The overlay returns the UNION of both versions, so it is fetched separately
  // and only when its tab is opened. The dependency list deliberately contains
  // NOTHING this effect sets: including `overlayLoading` made the effect re-run on
  // its own setState, and the cleanup then cancelled the in-flight request, so the
  // response was always discarded and the overlay never appeared.
  useEffect(() => {
    if (section !== 'overlay' || !projectId || from === to) return
    const attempt = `${projectId}|${from}|${to}`
    if (overlayAttemptRef.current === attempt) return
    overlayAttemptRef.current = attempt

    let cancelled = false
    setOverlayLoading(true)
    setOverlayError(null)
    fetch(`/api/projects/${projectId}/delta?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&overlay=1`)
      .then(async res => {
        if (!res.ok) {
          const failure = await readApiError(res, 'Failed to load the graph overlay')
          if (!cancelled) setOverlayError(failure.message)
          return
        }
        const body = await res.json().catch(() => ({}))
        if (cancelled) return
        setOverlay(body.overlay ?? { nodes: [], links: [] })
      })
      .catch(err => { if (!cancelled) setOverlayError(toApiError(err, 'Failed to load the graph overlay').message) })
      .finally(() => { if (!cancelled) setOverlayLoading(false) })
    return () => { cancelled = true }
  }, [section, projectId, from, to])

  useEffect(() => {
    if (!projectId || from === to) { setData(null); return }
    let cancelled = false
    setLoading(true)
    setError(null)
    fetch(`/api/projects/${projectId}/delta?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
      .then(async res => {
        if (!res.ok) {
          const failure = await readApiError(res, 'Failed to compare versions')
          if (!cancelled) { setError(failure.message); setData(null) }
          return
        }
        const body = await res.json()
        if (cancelled) return
        setData(body)
      })
      .catch(err => { if (!cancelled) setError(toApiError(err, 'Failed to compare versions').message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [projectId, from, to])

  const exportJson = () => {
    if (!data) return
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `recon-delta-${data.from.label}-to-${data.to.label}.json`.replace(/[^\w.-]+/g, '_')
    a.click()
    URL.revokeObjectURL(url)
  }

  if (comparable.length < 2) {
    return (
      <div className={styles.empty}>
        <p>Recon Delta needs at least two versions to compare.</p>
        <p className={styles.emptyNote}>
          Run another scan with “Create a new version”, or save the current graph as a version
          from the version manager.
        </p>
      </div>
    )
  }

  const options = [
    ...(current ? [{ id: CURRENT, label: `${current.label} (current)` }] : [{ id: CURRENT, label: 'Current' }]),
    ...comparable.filter(v => !v.isCurrent).map(v => ({ id: v.id, label: v.label })),
  ]

  const lenses = data?.lenses
  const securityCount = lenses
    ? lenses.newlyExposedPorts.length + lenses.newVulnerabilities.length +
      lenses.resolvedVulnerabilities.length + lenses.technologyVersionChanges.length +
      lenses.newCves.length + lenses.certificateChanges.length + lenses.newParameters.length
    : 0

  return (
    <div className={styles.wrap}>
      <div className={styles.controls}>
        <label className={styles.selectLabel}>
          From
          <select className={styles.select} value={from} onChange={e => setFrom(e.target.value)}>
            {options.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
          </select>
        </label>
        <ArrowRight size={14} className={styles.arrow} />
        <label className={styles.selectLabel}>
          To
          <select className={styles.select} value={to} onChange={e => setTo(e.target.value)}>
            {options.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
          </select>
        </label>
        {loading && <Loader2 size={14} className={styles.spinner} />}
        {data && (
          <div className={styles.totalsBar}>
            <span className={styles.totalAdded}><Plus size={12} />{data.totals.added} added</span>
            <span className={styles.totalRemoved}><Minus size={12} />{data.totals.removed} removed</span>
            <span className={styles.totalChanged}><RefreshCw size={12} />{data.totals.changed} changed</span>
            <span className={styles.totalStable}>{data.totals.stable} unchanged</span>
            <span className={styles.totalStable}>{data.totals.fromNodes} → {data.totals.toNodes} nodes</span>
          </div>
        )}
        {data && section === 'overlay' && (
          <label className={styles.showUnchanged}>
            <input
              type="checkbox"
              checked={!changesOnly}
              onChange={e => setChangesOnly(!e.target.checked)}
            />
            Show unchanged
          </label>
        )}
        {data && (
          <button className={styles.exportBtn} onClick={exportJson} title="Export this diff as JSON">
            <Download size={12} /> JSON
          </button>
        )}
        {/* Recon Delta has no section heading of its own, so the wiki link anchors
            to the right edge of the controls bar. */}
        <WikiInfoButton
          target="ReconDelta"
          title="Open the Recon Delta wiki page"
          className={styles.wikiLink}
        />
      </div>

      {from === to && <div className={styles.note}>Pick two different versions to compare.</div>}
      {error && <div className={styles.error}>{error}</div>}

      {data && data.coverage && data.coverage.sources.length > 0 && (
        <div className={styles.coverageBanner}>
          Coverage was partial in the newer version: {data.coverage.sources.join(', ')};
          removed counts may include skipped work.
        </div>
      )}

      {data && (
        <>
          <div className={styles.scorecard}>
            <div className={styles.chips}>
              {data.scorecard
                .filter(s => s.added || s.removed || s.changed)
                .map(s => (
                  <span key={s.type} className={styles.chip}>
                    <strong>{s.type}</strong>
                    {s.added > 0 && <span className={styles.chipAdded}>+{s.added}</span>}
                    {s.removed > 0 && <span className={styles.chipRemoved}>−{s.removed}</span>}
                    {s.changed > 0 && <span className={styles.chipChanged}>~{s.changed}</span>}
                  </span>
                ))}
              {data.scorecard.every(s => !s.added && !s.removed && !s.changed) && (
                <span className={styles.chip}>No differences</span>
              )}
            </div>
          </div>

          <div className={styles.tabs} role="tablist">
            {([
              ['added', `New (${data.totals.added})`],
              ['removed', `Removed (${data.totals.removed})`],
              ['changed', `Changed (${data.totals.changed})`],
              ['links', `Relationships (${data.totals.addedLinks + data.totals.removedLinks})`],
              ['security', `Security (${securityCount})`],
              ['overlay', 'Graph overlay'],
            ] as Array<[Section, string]>).map(([id, label]) => (
              <button
                key={id}
                role="tab"
                aria-selected={section === id}
                className={`${styles.tab} ${section === id ? styles.tabActive : ''}`}
                onClick={() => setSection(id)}
              >
                {label}
              </button>
            ))}
          </div>

          <div className={styles.tableWrap}>
            {section === 'added' && <NodeList nodes={data.addedNodes} kind="added" sortDir={sortDir} onToggleSort={toggleSort} />}
            {section === 'removed' && <NodeList nodes={data.removedNodes} kind="removed" sortDir={sortDir} onToggleSort={toggleSort} />}
            {section === 'changed' && <ChangedList nodes={data.changedNodes} sortDir={sortDir} onToggleSort={toggleSort} />}
            {section === 'links' && (
              <table className={styles.table}>
                <thead>
                  <tr><th></th><th>Relationship</th><th>From</th><th>To</th></tr>
                </thead>
                <tbody>
                  {data.addedLinks.map((l, i) => (
                    <tr key={`a${i}`}>
                      <td className={styles.added}>+</td><td>{l.type}</td><td>{l.sourceName}</td><td>{l.targetName}</td>
                    </tr>
                  ))}
                  {data.removedLinks.map((l, i) => (
                    <tr key={`r${i}`}>
                      <td className={styles.removed}>−</td><td>{l.type}</td><td>{l.sourceName}</td><td>{l.targetName}</td>
                    </tr>
                  ))}
                  {data.addedLinks.length + data.removedLinks.length === 0 && (
                    <tr><td colSpan={4} className={styles.emptyRow}>No relationship changes.</td></tr>
                  )}
                </tbody>
              </table>
            )}
            {section === 'overlay' && (
              <DeltaOverlay
                data={overlay}
                loading={overlayLoading}
                error={overlayError}
                changesOnly={changesOnly}
                isDark={isDark}
                selectedNode={selectedNode}
                onSelectNode={setSelectedNode}
                changedByKey={new Map(data.changedNodes.map(n => [n.key, n]))}
              />
            )}
            {section === 'security' && lenses && (
              <div className={styles.lenses}>
                <Lens title="Newly exposed ports" icon nodes={lenses.newlyExposedPorts} tone="bad" />
                <Lens title="New vulnerabilities" icon nodes={lenses.newVulnerabilities} tone="bad" />
                <Lens title="New CVEs" icon nodes={lenses.newCves} tone="bad" />
                <Lens title="Resolved vulnerabilities" nodes={lenses.resolvedVulnerabilities} tone="good" />
                <Lens title="Closed ports" nodes={lenses.closedPorts} tone="good" />
                <Lens title="New parameters / inputs" nodes={lenses.newParameters} tone="neutral" />
                <Lens title="Certificate changes" nodes={lenses.certificateChanges} tone="neutral" />
                <div className={styles.lens}>
                  <h4 className={styles.lensTitle}>Technology version changes</h4>
                  {lenses.technologyVersionChanges.length === 0 ? (
                    <p className={styles.lensEmpty}>None</p>
                  ) : (
                    <ul className={styles.lensList}>
                      {lenses.technologyVersionChanges.map(t => {
                        const v = t.changes.find(c => c.field === 'version')
                        return (
                          <li key={t.key}>
                            {describe(t)}: {renderValue(v?.from)} → <strong>{renderValue(v?.to)}</strong>
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function NodeList({ nodes, kind, sortDir, onToggleSort }: {
  nodes: DeltaNode[]; kind: 'added' | 'removed'; sortDir: SortDir; onToggleSort: () => void
}) {
  if (nodes.length === 0) {
    return <p className={styles.emptyRow}>Nothing {kind}.</p>
  }
  return (
    <table className={styles.table}>
      <thead><tr><th></th><NodeIdTh /><th>Type</th><th>Asset</th><th>Details</th>
        <UpdatedAtTh dir={sortDir} onToggle={onToggleSort} />
      </tr></thead>
      <tbody>
        {sortByUpdatedAt(nodes, sortDir, n => nodeUpdatedAt(n.properties)).map(n => (
          <tr key={n.key}>
            <td className={kind === 'added' ? styles.added : styles.removed}>
              {kind === 'added' ? '+' : '−'}
            </td>
            <td><NodeIdCell value={n.nodeId} /></td>
            <td>{n.type}</td>
            <td>{describe(n)}</td>
            <td className={styles.props}>
              {Object.entries(n.properties)
                .filter(([k]) => !['project_id', 'user_id'].includes(k))
                .slice(0, 6)
                .map(([k, v]) => `${k}=${isSecretValueProp(k, n.type) ? secretTail(String(v ?? '')) : renderValue(v)}`)
                .join('  ')}
            </td>
            <td><UpdatedAtCell value={nodeUpdatedAt(n.properties)} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function ChangedList({ nodes, sortDir, onToggleSort }: {
  nodes: ChangedNode[]; sortDir: SortDir; onToggleSort: () => void
}) {
  if (nodes.length === 0) return <p className={styles.emptyRow}>Nothing changed.</p>
  return (
    <table className={styles.table}>
      <thead><tr><NodeIdTh /><th>Type</th><th>Asset</th><th>Field</th><th>Before</th><th>After</th>
        <UpdatedAtTh dir={sortDir} onToggle={onToggleSort} />
      </tr></thead>
      <tbody>
        {sortByUpdatedAt(nodes, sortDir, n => nodeUpdatedAt(n.properties)).flatMap(n =>
          n.changes.map((c, i) => (
            <tr key={`${n.key}:${c.field}`}>
              <td>{i === 0 ? <NodeIdCell value={n.nodeId} /> : null}</td>
              <td>{i === 0 ? n.type : ''}</td>
              <td>{i === 0 ? describe(n) : ''}</td>
              <td className={styles.field}>{c.field}</td>
              <td className={styles.removed}>
                {isSecretValueProp(c.field, n.type) ? <SecretValue value={c.from == null ? '' : String(c.from)} /> : renderValue(c.from)}
              </td>
              <td className={styles.added}>
                {isSecretValueProp(c.field, n.type) ? <SecretValue value={c.to == null ? '' : String(c.to)} /> : renderValue(c.to)}
              </td>
              {/* One node spans several change rows; stamp only its first. */}
              <td>{i === 0 ? <UpdatedAtCell value={nodeUpdatedAt(n.properties)} /> : null}</td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  )
}

function Lens({
  title, nodes, tone, icon,
}: { title: string; nodes: DeltaNode[]; tone: 'bad' | 'good' | 'neutral'; icon?: boolean }) {
  return (
    <div className={styles.lens}>
      <h4 className={`${styles.lensTitle} ${tone === 'bad' ? styles.lensBad : tone === 'good' ? styles.lensGood : ''}`}>
        {icon && <ShieldAlert size={12} />} {title}
      </h4>
      {nodes.length === 0 ? (
        <p className={styles.lensEmpty}>None</p>
      ) : (
        <ul className={styles.lensList}>
          {nodes.map(n => <li key={n.key}>{describe(n)}</li>)}
        </ul>
      )}
    </div>
  )
}

interface DeltaOverlayProps {
  data: OverlayPayload | null
  loading: boolean
  error: string | null
  changesOnly: boolean
  isDark: boolean
  selectedNode: (GraphNode & { deltaState: DeltaState }) | null
  onSelectNode: (n: (GraphNode & { deltaState: DeltaState }) | null) => void
  changedByKey: Map<string, ChangedNode>
}

/**
 * Section 6.3 - the two versions merged on the identity key and rendered through
 * the normal canvas, colored by delta state. Clicking a node shows its changed
 * fields old → new. The legend/counts + "show unchanged" toggle live on the Recon
 * Delta controls bar (one bar less here).
 */
function DeltaOverlay({
  data, loading, error, changesOnly,
  isDark, selectedNode, onSelectNode, changedByKey,
}: DeltaOverlayProps) {
  // Measure the canvas HERE, not in the parent: the ref only exists while the
  // overlay tab is open, so a useDimensions() call in ReconDeltaTable would set up
  // its ResizeObserver on a null ref and the canvas would stay stuck at the 800x600
  // default. Mounting the hook with the div makes it observe the real box.
  const containerRef = useRef<HTMLDivElement>(null)
  const size = useDimensions(containerRef)

  const filtered = useMemo(() => {
    if (!data) return null
    if (!changesOnly) return data
    const keep = new Set(data.nodes.filter(n => n.deltaState !== 'stable').map(n => n.id))
    return {
      nodes: data.nodes.filter(n => keep.has(n.id)),
      links: data.links.filter(l => keep.has(l.source) && keep.has(l.target)),
    }
  }, [data, changesOnly])

  // The parent re-renders on every recon-status poll (~5s). Force-graph re-heats
  // its D3 simulation whenever the `graphData` object IDENTITY changes, so an inline
  // `{ ...filtered, projectId: '' }` here made the overlay jitter every few seconds
  // even though nothing actually changed. Memoize it (and the click handler) so the
  // canvas gets a stable reference and the layout stays put between real updates.
  const overlayData = useMemo(
    () => (filtered ? { ...filtered, projectId: '' } : undefined),
    [filtered]
  )
  const handleNodeClick = useCallback(
    (n: GraphNode) => onSelectNode(n as GraphNode & { deltaState: DeltaState }),
    [onSelectNode]
  )

  const changes = selectedNode ? changedByKey.get(selectedNode.id)?.changes ?? [] : []

  if (error) return <div className={styles.error}>{error}</div>

  return (
    <div className={styles.overlayWrap}>
      {/* The legend (from→to, per-state counts, "show unchanged") lives on the
          Recon Delta controls bar now, not as a separate row here - one bar less,
          more vertical room for the canvas. */}
      <div className={styles.overlayBody}>
        <div ref={containerRef} className={styles.overlayCanvas}>
          {loading ? (
            <div className={styles.overlayLoading}><Loader2 size={18} className={styles.spinner} /></div>
          ) : (
            <GraphCanvas
              data={overlayData}
              isLoading={loading}
              error={null}
              projectId=""
              is3D={false}
              width={size.width}
              height={size.height}
              showLabels={false}
              selectedNode={selectedNode}
              onNodeClick={handleNodeClick}
              isDark={isDark}
            />
          )}
        </div>
        {selectedNode && (
          <aside className={styles.overlayPanel}>
            <div className={styles.overlayPanelHead}>
              <span>{selectedNode.name || selectedNode.type}</span>
              <button className={styles.overlayPanelClose} onClick={() => onSelectNode(null)} title="Close">
                <X size={13} />
              </button>
            </div>
            <p className={styles.overlayPanelState}>
              {selectedNode.type} · <strong>{selectedNode.deltaState}</strong>
            </p>
            {changes.length > 0 ? (
              <table className={styles.table}>
                <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
                <tbody>
                  {changes.map(c => (
                    <tr key={c.field}>
                      <td className={styles.field}>{c.field}</td>
                      <td className={styles.removed}>{renderValue(c.from)}</td>
                      <td className={styles.added}>{renderValue(c.to)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className={styles.lensEmpty}>No field-level changes.</p>
            )}
          </aside>
        )}
      </div>
    </div>
  )
}

export default ReconDeltaTable
