'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Network, PanelRightOpen, Copy, Settings } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useAuth } from '@/providers/AuthProvider'
import { Drawer, useToast, useAlertModal, WikiInfoButton } from '@/components/ui'
import { TrafficCaptureStatus } from '@/components/traffic/TrafficCaptureStatus'
import { TrafficMindSettingsModal } from '@/components/traffic/TrafficMindSettingsModal'
import { isHttpUrl } from '@/lib/url-utils'
import {
  useTrafficList,
  useTrafficFacets,
  useTrafficDetail,
  useDeleteTraffic,
  trafficFiltersToQuery,
  trafficFilterPayload,
  DEFAULT_FILTERS,
  type TrafficFilters,
  type TrafficRow,
  type TrafficDetail,
} from './hooks/useTrafficData'
import styles from './page.module.css'

const SORT_COLUMNS = new Set(['startedAt', 'statusCode', 'host', 'tool', 'method', 'respBodySize', 'responseTimeMs', 'source'])

function statusClassName(code: number | null): string {
  if (code == null) return ''
  if (code >= 500) return styles.status5xx
  if (code >= 400) return styles.status4xx
  if (code >= 300) return styles.status3xx
  if (code >= 200) return styles.status2xx
  return ''
}

function fmtTime(iso: string): string {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

function fullUrl(d: TrafficDetail): string {
  return `${d.scheme}://${d.host}${d.port && d.port !== 80 && d.port !== 443 ? ':' + d.port : ''}${d.path}${d.query || ''}`
}

function toCurl(d: TrafficDetail): string {
  const url = fullUrl(d)
  const parts = [`curl -i -X ${d.method}`]
  const headers = d.reqHeaders && typeof d.reqHeaders === 'object' ? d.reqHeaders : {}
  for (const [k, v] of Object.entries(headers)) {
    parts.push(`-H '${k}: ${String(v).replace(/'/g, "'\\''")}'`)
  }
  if (d.reqBody) parts.push(`--data-raw '${d.reqBody.replace(/'/g, "'\\''")}'`)
  parts.push(`'${url.replace(/'/g, "'\\''")}'`)
  return parts.join(' \\\n  ')
}

export default function TrafficPage() {
  const { projectId, userId, currentProject, isLoading: projectLoading } = useProject()
  const { isAdmin } = useAuth()
  const router = useRouter()
  const toast = useToast()

  const [filters, setFilters] = useState<TrafficFilters>(DEFAULT_FILTERS)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [settingsOpen, setSettingsOpen] = useState(false)

  const list = useTrafficList(projectId, filters)
  const facets = useTrafficFacets(projectId)
  const detail = useTrafficDetail(projectId, selectedId)
  const del = useDeleteTraffic(projectId)

  const copyText = useCallback((text: string, what: string) => {
    navigator.clipboard.writeText(text || '')
    toast.success(`Copied ${what}`)
  }, [toast])
  const { dangerConfirm } = useAlertModal()

  const toggleSelect = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }, [])

  const exportUrl = useCallback((format: 'csv' | 'json') =>
    `/api/traffic/${projectId}/export?format=${format}&${trafficFiltersToQuery(filters)}`, [projectId, filters])

  const handleDeleteSelected = useCallback(async () => {
    if (selected.size === 0) return
    const ok = await dangerConfirm(`Delete ${selected.size} selected transaction(s)? This cannot be undone.`, 'Delete traffic')
    if (!ok) return
    try {
      const r = await del.mutateAsync({ ids: [...selected] })
      setSelected(new Set())
      toast.success(`Deleted ${r.deleted} transaction(s)`)
    } catch { toast.error('Delete failed') }
  }, [selected, dangerConfirm, del, toast])

  const handleDeleteAllMatching = useCallback(async () => {
    const ok = await dangerConfirm('Delete ALL transactions matching the current filters? This cannot be undone.', 'Delete all matching')
    if (!ok) return
    try {
      const r = await del.mutateAsync({ filter: trafficFilterPayload(filters) })
      setSelected(new Set())
      toast.success(`Deleted ${r.deleted} transaction(s)`)
    } catch { toast.error('Delete failed') }
  }, [filters, dangerConfirm, del, toast])

  // Any filter change resets to the first page.
  const patch = useCallback((p: Partial<TrafficFilters>) => {
    setFilters(prev => ({ ...prev, ...p, page: 'page' in p ? (p.page as number) : 0 }))
  }, [])

  const toggleSort = useCallback((col: string) => {
    if (!SORT_COLUMNS.has(col)) return
    setFilters(prev => ({
      ...prev,
      sort: col,
      dir: prev.sort === col && prev.dir === 'desc' ? 'asc' : 'desc',
      page: 0,
    }))
  }, [])

  const rows = list.data?.rows ?? []
  const total = list.data?.total ?? 0
  const pageCount = Math.max(1, Math.ceil(total / filters.pageSize))

  const activeFilterCount = useMemo(() => {
    let n = 0
    if (filters.from) n++
    if (filters.to) n++
    if (filters.source !== 'both') n++
    if (filters.tool.length) n++
    if (filters.host) n++
    if (filters.method) n++
    if (filters.statusClass) n++
    if (filters.q) n++
    if (filters.bodyq) n++
    if (filters.runId) n++
    if (filters.sessionId) n++
    if (filters.hasSetCookie) n++
    if (filters.reflected) n++
    if (filters.only5xx) n++
    return n
  }, [filters])

  if (!projectLoading && !projectId) {
    return (
      <div className={styles.page}>
        <div className={styles.noProject}>
          <Network size={48} strokeWidth={1.5} />
          <div className={styles.noProjectTitle}>No Project Selected</div>
          <div className={styles.noProjectText}>
            Select a project from the header to view captured HTTP traffic.
          </div>
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div className={styles.title}>
          <Network size={18} /> TrafficMind
        </div>
        <span className={styles.subtitle}>Captured HTTP transactions</span>
        <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/TrafficMind" title="Open TrafficMind wiki page" />
        <div className={styles.spacer} />
        {projectId && (
          <TrafficCaptureStatus projectId={projectId} projectName={currentProject?.name} />
        )}
        <span className={styles.count}>{total.toLocaleString()} transactions</span>
        <a className={styles.pageBtn} href={exportUrl('csv')}>Export CSV</a>
        <a className={styles.pageBtn} href={exportUrl('json')}>Export JSON</a>
        {selected.size > 0 && (
          <button className={styles.clearBtn} onClick={handleDeleteSelected}>Delete selected ({selected.size})</button>
        )}
        {total > 0 && (
          <button className={styles.clearBtn} onClick={handleDeleteAllMatching}>Delete all matching</button>
        )}
        {isAdmin && (
          <button className={styles.settingsBtn} onClick={() => setSettingsOpen(true)} title="TrafficMind global settings (admin)">
            <Settings size={15} /> Settings
          </button>
        )}
      </div>

      <TrafficMindSettingsModal isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} userId={userId} />

      {/* Filters */}
      <div className={styles.filters}>
        <div className={styles.field}>
          <label>From</label>
          <input className={styles.input} type="date" value={filters.from}
            onChange={e => patch({ from: e.target.value })} />
        </div>
        <div className={styles.field}>
          <label>To</label>
          <input className={styles.input} type="date" value={filters.to}
            onChange={e => patch({ to: e.target.value })} />
        </div>
        <div className={styles.field}>
          <label>Source</label>
          <select className={styles.select} value={filters.source}
            onChange={e => patch({ source: e.target.value })}>
            <option value="both">Both</option>
            <option value="recon">Recon</option>
            <option value="agent">Agent</option>
            <option value="operator">Operator</option>
          </select>
        </div>
        <div className={styles.field}>
          <label>Tool</label>
          <select className={styles.select} value={filters.tool[0] || ''}
            onChange={e => patch({ tool: e.target.value ? [e.target.value] : [] })}>
            <option value="">All</option>
            {(facets.data?.tools ?? []).map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className={styles.field}>
          <label>Host</label>
          <select className={styles.select} value={filters.host}
            onChange={e => patch({ host: e.target.value })}>
            <option value="">All</option>
            {(facets.data?.hosts ?? []).map(h => <option key={h} value={h}>{h}</option>)}
          </select>
        </div>
        <div className={styles.field}>
          <label>Method</label>
          <select className={styles.select} value={filters.method}
            onChange={e => patch({ method: e.target.value })}>
            <option value="">All</option>
            {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        <div className={styles.field}>
          <label>Status</label>
          <select className={styles.select} value={filters.statusClass}
            onChange={e => patch({ statusClass: e.target.value })}>
            <option value="">All</option>
            <option value="2xx">2xx</option>
            <option value="3xx">3xx</option>
            <option value="4xx">4xx</option>
            <option value="5xx">5xx</option>
          </select>
        </div>
        <div className={styles.field}>
          <label>Run</label>
          <select className={styles.select} value={filters.runId}
            onChange={e => patch({ runId: e.target.value })}>
            <option value="">All</option>
            {(facets.data?.runs ?? []).map(r => <option key={r} value={r}>{r.slice(0, 8)}</option>)}
          </select>
        </div>
        <div className={styles.field}>
          <label>Search URL</label>
          <input className={styles.input} type="text" placeholder="host / path"
            value={filters.q} onChange={e => patch({ q: e.target.value })} />
        </div>
        <div className={styles.field}>
          <label>Search bodies</label>
          <input className={styles.input} type="text" placeholder="stack trace, AKIA…"
            value={filters.bodyq} onChange={e => patch({ bodyq: e.target.value })}
            title="Full-text search over response bodies (Google-style: quotes, -exclude)" />
        </div>

        <div className={styles.toggles}>
          <label className={styles.toggleItem}>
            <input type="checkbox" checked={filters.hasSetCookie}
              onChange={e => patch({ hasSetCookie: e.target.checked })} /> Set-Cookie
          </label>
          <label className={styles.toggleItem}>
            <input type="checkbox" checked={filters.only5xx}
              onChange={e => patch({ only5xx: e.target.checked, statusClass: '' })} /> 5xx only
          </label>
        </div>

        {activeFilterCount > 0 && (
          <button className={styles.clearBtn} onClick={() => setFilters(DEFAULT_FILTERS)}>
            Clear ({activeFilterCount})
          </button>
        )}
      </div>

      {/* Table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>
                <input type="checkbox"
                  checked={rows.length > 0 && rows.every(r => selected.has(r.id))}
                  onChange={e => setSelected(prev => {
                    const next = new Set(prev)
                    if (e.target.checked) rows.forEach(r => next.add(r.id))
                    else rows.forEach(r => next.delete(r.id))
                    return next
                  })} />
              </th>
              <th className={styles.sortable} onClick={() => toggleSort('startedAt')}>Time{filters.sort === 'startedAt' ? (filters.dir === 'desc' ? ' ↓' : ' ↑') : ''}</th>
              <th className={styles.sortable} onClick={() => toggleSort('source')}>Source</th>
              <th className={styles.sortable} onClick={() => toggleSort('tool')}>Tool</th>
              <th className={styles.sortable} onClick={() => toggleSort('method')}>Method</th>
              <th className={styles.sortable} onClick={() => toggleSort('host')}>Host</th>
              <th>Path</th>
              <th className={styles.sortable} onClick={() => toggleSort('statusCode')}>Status</th>
              <th className={styles.sortable} onClick={() => toggleSort('respBodySize')}>Length</th>
              <th className={styles.sortable} onClick={() => toggleSort('responseTimeMs')}>Time (ms)</th>
              <th>Flags</th>
              <th aria-label="Details"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r: TrafficRow) => (
              <tr key={r.id} className={styles.row} onClick={() => setSelectedId(r.id)}>
                <td onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleSelect(r.id)} />
                </td>
                <td>{fmtTime(r.startedAt)}</td>
                <td>
                  <span className={`${styles.badge} ${r.source === 'recon' ? styles.badgeRecon : r.source === 'operator' ? styles.badgeOperator : styles.badgeAgent}`}>
                    {r.source}
                  </span>
                </td>
                <td>{r.tool || '-'}</td>
                <td className={styles.mono}>{r.method}</td>
                <td>{r.host}</td>
                <td className={styles.pathCell} title={`${r.path}${r.query || ''}`}>
                  {r.path}{r.query || ''}
                </td>
                <td className={`${styles.mono} ${statusClassName(r.statusCode)}`}>{r.statusCode ?? (r.blocked ? 'BLK' : '-')}</td>
                <td>{fmtBytes(r.respBodySize)}</td>
                <td>{r.responseTimeMs ?? '-'}</td>
                <td>
                  <span className={styles.flags}>
                    {r.hasSetCookie && <span className={styles.flag}>cookie</span>}
                    {r.reflectedParams && <span className={`${styles.flag} ${styles.flagWarn}`}>reflect</span>}
                    {r.isReplay && <span className={styles.flag}>replay</span>}
                    {!r.inScope && <span className={`${styles.flag} ${styles.flagWarn}`}>oos</span>}
                    {r.iocIncidentId && (
                      // The strongest signal this table can carry: the target
                      // contacted a host named in a published supply-chain
                      // incident. Links out to the write-up when we have one.
                      // isHttpUrl, not truthiness: the URL comes from a public
                      // feed and React renders a `javascript:` href happily.
                      isHttpUrl(r.iocIncidentUrl) ? (
                        <a
                          href={r.iocIncidentUrl!}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={`${styles.flag} ${styles.flagWarn}`}
                          title={`Supply-chain incident ${r.iocIncidentId} (supplychainattack.org)`}
                          onClick={e => e.stopPropagation()}
                        >
                          ioc
                        </a>
                      ) : (
                        <span
                          className={`${styles.flag} ${styles.flagWarn}`}
                          title={`Supply-chain incident ${r.iocIncidentId}`}
                        >
                          ioc
                        </span>
                      )
                    )}
                  </span>
                </td>
                <td className={styles.detailCell}>
                  <button
                    type="button"
                    className={styles.detailBtn}
                    aria-label="Open request/response detail"
                    title="Open detail"
                    onClick={e => { e.stopPropagation(); setSelectedId(r.id) }}
                  >
                    <PanelRightOpen size={18} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {list.isLoading && <div className={styles.loading}>Loading…</div>}
        {!list.isLoading && rows.length === 0 && (
          <div className={styles.empty}>
            No captured traffic yet. Enable capture on the project and run a recon scan.
          </div>
        )}
      </div>

      {/* Pagination */}
      <div className={styles.pagination}>
        <button className={styles.pageBtn} disabled={filters.page <= 0}
          onClick={() => patch({ page: filters.page - 1 })}>Prev</button>
        <span className={styles.pageInfo}>Page {filters.page + 1} of {pageCount}</span>
        <button className={styles.pageBtn} disabled={filters.page + 1 >= pageCount}
          onClick={() => patch({ page: filters.page + 1 })}>Next</button>
        <select className={styles.select} value={filters.pageSize}
          onChange={e => patch({ pageSize: parseInt(e.target.value, 10) })}>
          {[25, 50, 100, 200].map(s => <option key={s} value={s}>{s} / page</option>)}
        </select>
      </div>

      {/* Detail drawer */}
      <Drawer
        isOpen={!!selectedId}
        onClose={() => setSelectedId(null)}
        position="right"
        mode="overlay"
        width="620px"
        resizable
        title="Transaction detail"
      >
        {detail.isLoading && <div className={styles.loading}>Loading…</div>}
        {detail.data && (
          <div className={styles.detail}>
            <div className={styles.detailSection}>
              <div className={styles.sectionHead}>
                <span className={styles.detailLabel}>Request</span>
                <button className={styles.copyBtn} onClick={() => copyText(toCurl(detail.data as TrafficDetail), 'curl command')}>
                  <Copy size={13} /> Copy as curl
                </button>
              </div>
              <dl className={styles.kv}>
                <dt>URL</dt>
                <dd className={styles.mono}>
                  <span className={styles.urlText}>{fullUrl(detail.data as TrafficDetail)}</span>
                  <button className={styles.iconCopy} title="Copy URL" aria-label="Copy URL"
                    onClick={() => copyText(fullUrl(detail.data as TrafficDetail), 'URL')}>
                    <Copy size={13} />
                  </button>
                </dd>
                <dt>Method</dt><dd className={styles.mono}>{detail.data.method}</dd>
                <dt>Source</dt><dd>{detail.data.source}{detail.data.tool ? ` · ${detail.data.tool}` : ''}</dd>
                {detail.data.runId && (<><dt>Run</dt><dd className={styles.mono}>{detail.data.runId}</dd></>)}
                {detail.data.sessionId && (<><dt>Session</dt><dd className={styles.mono}>{detail.data.sessionId}</dd></>)}
                {detail.data.targetIp && (<><dt>Target IP</dt><dd className={styles.mono}>{detail.data.targetIp}</dd></>)}
                {detail.data.tlsVersion && (<><dt>TLS</dt><dd>{detail.data.tlsVersion}</dd></>)}
              </dl>
            </div>

            {detail.data.reqHeaders && Object.keys(detail.data.reqHeaders).length > 0 && (
              <div className={styles.detailSection}>
                <div className={styles.sectionHead}>
                  <span className={styles.detailLabel}>Request headers</span>
                  <button className={styles.iconCopy} title="Copy request headers" aria-label="Copy request headers"
                    onClick={() => copyText(JSON.stringify(detail.data!.reqHeaders ?? {}, null, 2), 'request headers')}>
                    <Copy size={13} />
                  </button>
                </div>
                <pre className={styles.pre}>{JSON.stringify(detail.data.reqHeaders ?? {}, null, 2)}</pre>
              </div>
            )}

            {detail.data.reqBody && (
              <div className={styles.detailSection}>
                <div className={styles.sectionHead}>
                  <span className={styles.detailLabel}>Request body</span>
                  <button className={styles.iconCopy} title="Copy request body" aria-label="Copy request body"
                    onClick={() => copyText(detail.data!.reqBody ?? '', 'request body')}>
                    <Copy size={13} />
                  </button>
                </div>
                {/* Rendered as inert text - never HTML. Captured bodies are attacker-controlled (§15.6). */}
                <pre className={styles.pre}>{detail.data.reqBody}</pre>
              </div>
            )}

            <div className={styles.detailSection}>
              <div className={styles.detailLabel}>
                Response - {detail.data.statusCode ?? (detail.data.blocked ? 'blocked' : 'no status')}
                {' · '}{fmtBytes(detail.data.respBodySize)}
                {detail.data.respContentType ? ` · ${detail.data.respContentType}` : ''}
              </div>
              <div className={styles.sectionHead}>
                <span className={styles.detailLabel}>Response headers</span>
                <button className={styles.iconCopy} title="Copy response headers" aria-label="Copy response headers"
                  onClick={() => copyText(JSON.stringify(detail.data!.respHeaders ?? {}, null, 2), 'response headers')}>
                  <Copy size={13} />
                </button>
              </div>
              <pre className={styles.pre}>{JSON.stringify(detail.data.respHeaders ?? {}, null, 2)}</pre>
              <div className={styles.sectionHead}>
                <span className={styles.detailLabel}>
                  Response body{detail.data.respBodyRef ? ' (offloaded - Phase 1)' : ''}
                </span>
                <button className={styles.iconCopy} title="Copy response body" aria-label="Copy response body"
                  disabled={!detail.data.respBody}
                  onClick={() => copyText(detail.data!.respBody ?? '', 'response body')}>
                  <Copy size={13} />
                </button>
              </div>
              {/* Rendered as inert text - never HTML. Captured bodies are attacker-controlled (§15.6). */}
              <pre className={styles.pre}>{detail.data.respBody ?? (detail.data.respBodyRef ? '[body stored on disk]' : '[no body]')}</pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}
