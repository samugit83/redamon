'use client'

import { useEffect, useState } from 'react'
import { TrafficCaptureToggle } from './TrafficCaptureToggle'
import { fetchJson, errorMessage } from '@/lib/apiError'

type ProjectRow = { id: string; name: string; captureProxyEnabled: boolean; updatedAt: string | null }

/**
 * Per-project routing matrix shown in user settings under the (enabled) global
 * TrafficMind master switch. Lists every project the effective user owns with a
 * live capture toggle, so routing can be flipped for any project from one place.
 * Each toggle writes straight to that project (PUT /api/projects/[id]).
 */
export function TrafficMindProjectMatrix() {
  const [rows, setRows] = useState<ProjectRow[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchJson<Array<{ id: string; name: string; captureProxyEnabled?: boolean; updatedAt?: string }>>('/api/projects', undefined, 'Could not load projects')
      .then((list) => {
        if (cancelled) return
        setRows(list.map((p) => ({ id: p.id, name: p.name, captureProxyEnabled: !!p.captureProxyEnabled, updatedAt: p.updatedAt ?? null })))
      })
      .catch((err) => { if (!cancelled) setLoadError(errorMessage(err, 'Could not load projects')) })
    return () => { cancelled = true }
  }, [])

  return (
    <div style={{ marginTop: 18, borderTop: '1px solid var(--border-default)', paddingTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: 13, fontWeight: 600 }}>Per-project routing</span>
        <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
          Choose which projects route their traffic through the proxy. Applies immediately; takes effect next session.
        </span>
      </div>

      {loadError ? (
        <div style={{ color: 'var(--status-error, #e5484d)', fontSize: 13 }} role="alert">{loadError}</div>
      ) : rows === null ? (
        <div style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>Loading projects…</div>
      ) : rows.length === 0 ? (
        <div style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>No projects.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {rows.map((p) => (
            <div
              key={p.id}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
                padding: '8px 10px', borderRadius: 6, background: 'var(--bg-tertiary, transparent)',
              }}
            >
              <span style={{ color: 'var(--text-primary)', fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {p.name}
              </span>
              <TrafficCaptureToggle
                projectId={p.id}
                projectName={p.name}
                initialEnabled={p.captureProxyEnabled}
                initialVersion={p.updatedAt}
                showName={false}
                size="small"
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
