'use client'

import { useCallback, useEffect, useState } from 'react'
import { BookOpen, ChevronDown, ChevronRight, ExternalLink, List, Lock } from 'lucide-react'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import { IngestionReport } from '@/components/settings/tradecraft/IngestionReport'
import { MapView } from '@/components/settings/tradecraft/MapView'
import { ApiError, fetchJson, toApiError } from '@/lib/apiError'
import { relTime } from '@/lib/tradecraft/client'
import { canonicalJson } from '@/lib/tradecraft/effectiveSettings'
import { SETTINGS, settingDef } from '@/lib/tradecraft/settingsSpec'
import type { ProjectResourceRow, ProjectTradecraftView } from '@/lib/tradecraft/projectView'
import styles from '../ProjectForm.module.css'

export const GLOBAL_TRADECRAFT_HREF = '/settings?tab=tradecraft'
export const editInGlobalHref = (id: string) => `${GLOBAL_TRADECRAFT_HREF}&edit=${encodeURIComponent(id)}`
/** The tab and the drawer window are called this when the project owner has Tradecraft 2.0 on (§3.4). */
export const TAB_LABEL_V2 = 'Agent Skills & Tradecraft'

const TYPE_WORDS: Readonly<Record<string, string>> = {
  'mkdocs-wiki': 'mkdocs-wiki', 'sphinx-docs': 'docs', gitbook: 'gitbook', 'github-repo': 'github-repo',
  'cve-poc-db': 'cve archive', pdf: 'pdf', 'agentic-crawl': 'website',
}
const MAP_SOURCE: Readonly<Record<number, string>> = {
  1: 'the map made before 2.0, not ingested by 2.0 yet', 2: 'converted from the map made before 2.0', 3: 'ingested by 2.0',
}

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; view: ProjectTradecraftView }
  | { kind: 'error'; text: string }
  | { kind: 'denied'; text: string }

/** The project's tradecraft view (GET /api/projects/[id]/tradecraft), read once per project. */
export function useProjectTradecraft(projectId: string | null): { load: Load; reload: () => void } {
  const [load, setLoad] = useState<Load>({ kind: 'loading' })
  const [token, setToken] = useState(0)
  useEffect(() => {
    if (!projectId) return
    let live = true
    setLoad({ kind: 'loading' })
    fetchJson<ProjectTradecraftView>(`/api/projects/${encodeURIComponent(projectId)}/tradecraft`, undefined, "Couldn't load the project's tradecraft resources")
      .then(view => { if (live) setLoad({ kind: 'ready', view }) })
      .catch(e => {
        if (!live) return
        const err = toApiError(e, "Couldn't load the project's tradecraft resources")
        const denied = e instanceof ApiError && (e.status === 401 || e.status === 403 || e.status === 404)
        setLoad({ kind: denied ? 'denied' : 'error', text: err.message })
      })
    return () => { live = false }
  }, [projectId, token])
  return { load, reload: useCallback(() => setToken(t => t + 1), []) }
}

/** Whether the project's owner has 2.0 on: the tab and the drawer window take the new name. */
export function useTradecraftV2(projectId: string | null): boolean {
  const { load } = useProjectTradecraft(projectId)
  return load.kind === 'ready' && load.view.v2
}

export function isActiveHere(r: ProjectResourceRow, off: ReadonlySet<string>): boolean {
  return r.enabledGlobally && !r.ownerOnly && !off.has(r.id)
}

/**
 * The project's Tradecraft Resources (§3.4): the owner's resources, each with its switch for this
 * project, read-only details for the owner, locked rows for a resource disabled in Global Settings
 * and for an owner-only one. Nothing here changes a resource: the only control is the switch,
 * held in `offIds` and saved with the project (the form's Save, the drawer's autosave).
 */
export function TradecraftResourcesAccordion({ projectId, offIds, onChange, inDrawer = false, readOnly = false }: {
  projectId: string
  offIds: readonly string[]
  onChange: (offIds: string[]) => void
  inDrawer?: boolean
  readOnly?: boolean
}) {
  const { load, reload } = useProjectTradecraft(projectId)
  const [open, setOpen] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [pagesOf, setPagesOf] = useState<ProjectResourceRow | null>(null)
  const linkProps: Record<string, string> = inDrawer ? { target: '_blank', rel: 'noopener noreferrer' } : {}

  if (load.kind === 'ready' && !load.view.v2) return null
  const view = load.kind === 'ready' ? load.view : null
  const off = new Set(offIds)
  const resources = view?.resources ?? []
  const changeable = resources.filter(r => !r.locked)
  const active = resources.filter(r => isActiveHere(r, off)).length
  const setOff = (ids: Iterable<string>) => onChange([...new Set(ids)].sort())
  const toggle = (r: ProjectResourceRow, on: boolean) => setOff(on ? offIds.filter(id => id !== r.id) : [...offIds, r.id])
  const turnAll = (on: boolean) => {
    const ids = new Set(changeable.map(r => r.id))
    setOff(on ? offIds.filter(id => !ids.has(id)) : [...offIds, ...ids])
  }

  return (
    <div className={`${styles.section} ${styles.formSkin}`} data-testid="tradecraft-accordion">
      <div className={styles.sectionHeader} onClick={() => setOpen(o => !o)}>
        <h2 className={styles.sectionTitle}>
          <BookOpen size={16} />
          Tradecraft Resources
          {view && <span className={styles.badgeActive} data-testid="tradecraft-active-count">{active} of {resources.length} active in this project</span>}
        </h2>
        <ChevronDown size={16} className={`${styles.sectionIcon} ${open ? styles.sectionIconOpen : ''}`} />
      </div>
      {open && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Managed in{' '}
            <a href={GLOBAL_TRADECRAFT_HREF} {...linkProps}>Global Settings &gt; Tradecraft</a>
            . A resource is used in this project when it is enabled there and on here; a change applies from the next message.
          </p>
          {load.kind === 'loading' && <p className={styles.sectionDescription}>Loading the tradecraft resources…</p>}
          {load.kind === 'error' && (
            <p className={styles.sectionDescription} role="alert">
              {load.text}.{' '}<button type="button" className="textButton" onClick={reload}>Retry</button>
            </p>
          )}
          {load.kind === 'denied' && <p className={styles.sectionDescription} role="alert">You cannot see this project&apos;s tradecraft resources: {load.text}.</p>}
          {view && resources.length === 0 && (
            <p className={styles.sectionDescription}>No tradecraft resources yet: add them in Global Settings &gt; Tradecraft.</p>
          )}
          {view && resources.length > 0 && (
            <>
              {!readOnly && (
                <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                  <button type="button" className="secondaryButton" onClick={() => turnAll(true)} disabled={changeable.length === 0}>Turn all on</button>
                  <button type="button" className="secondaryButton" onClick={() => turnAll(false)} disabled={changeable.length === 0}>Turn all off</button>
                </div>
              )}
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {resources.map(r => (
                  <li key={r.id} data-resource={r.id}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                      <Toggle
                        checked={isActiveHere(r, off)} disabled={readOnly || r.locked} size="small"
                        aria-label={`${r.name} in this project`} onChange={on => toggle(r, on)}
                      />
                      <strong>{r.name}</strong>
                      {!r.enabledGlobally ? (
                        <span>
                          <Lock size={12} /> Disabled in{' '}
                          <a href={GLOBAL_TRADECRAFT_HREF} {...linkProps}>Global Settings</a>
                        </span>
                      ) : r.ownerOnly ? (
                        <span title="A resource with a login is used only in its owner's own chats"><Lock size={12} /> Owner only</span>
                      ) : null}
                      {r.type && <span>{TYPE_WORDS[r.type] ?? r.type}</span>}
                      {r.storageMode && <span>{r.storageMode === 'stored' ? 'Stored' : 'Live'}</span>}
                      {r.pages !== null && <span>{r.pages.toLocaleString('en-US')} pages</span>}
                      {r.details && <span>{relTime(r.lastRefreshedAt)}</span>}
                      {r.details && (
                        <button
                          type="button" className="iconButton" aria-expanded={expanded === r.id} aria-label={`Details of ${r.name}`}
                          onClick={() => setExpanded(e => (e === r.id ? null : r.id))}
                        >
                          <ChevronRight size={14} />
                        </button>
                      )}
                    </div>
                    {r.details && expanded === r.id && (
                      <Details row={r} linkProps={linkProps} onPages={view?.ownerId ? () => setPagesOf(r) : undefined} />
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      {pagesOf?.details && view?.ownerId && (
        <MapView
          userId={view.ownerId} readOnly onClose={() => setPagesOf(null)}
          resource={{ id: pagesOf.id, name: pagesOf.name, url: pagesOf.details.url, storageMode: pagesOf.storageMode ?? 'live' }}
        />
      )}
    </div>
  )
}

const SPEC_ORDER = new Map(SETTINGS.map((s, i) => [s.key, i]))

function settingText(key: string, value: unknown): string {
  if (typeof value === 'boolean') return value ? 'on' : 'off'
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'none'
  if (typeof value === 'number') {
    const unit = settingDef(key)?.unit
    return unit ? `${value.toLocaleString('en-US')} ${unit}` : value.toLocaleString('en-US')
  }
  if (typeof value === 'string') return value || 'none'
  return JSON.stringify(value)
}

/**
 * The snapshot's values in the spec's order, each by its label (several share one, so the key
 * follows it), marked when it is not the spec's default; a key this version no longer knows
 * comes last, by its name.
 */
export function ingestedWithRows(values: Record<string, unknown>): { key: string; text: string; changed: boolean }[] {
  return Object.keys(values)
    .sort((a, b) => (SPEC_ORDER.get(a) ?? Infinity) - (SPEC_ORDER.get(b) ?? Infinity) || a.localeCompare(b))
    .map(key => {
      const def = settingDef(key)
      const changed = !!def && canonicalJson(values[key]) !== canonicalJson(def.default)
      return { key, changed, text: `${def ? `${def.label} (${key})` : key}: ${settingText(key, values[key])}${changed ? ' (changed)' : ''}` }
    })
}

function Details({ row, linkProps, onPages }: { row: ProjectResourceRow; linkProps: Record<string, string>; onPages?: () => void }) {
  const d = row.details!
  const report = d.report
  const ingestedWith = ingestedWithRows(d.ingestedWith)
  const changedCount = ingestedWith.filter(s => s.changed).length
  return (
    <dl className={styles.sectionDescription} data-testid={`details-${row.id}`} style={{ margin: '6px 0 0 44px', display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '2px 12px' }}>
      <dt>URL</dt><dd>{d.url}</dd>
      <dt>Pages from</dt><dd>{MAP_SOURCE[d.mapVersion] ?? 'unknown'}</dd>
      {d.stale && <><dt>Stale</dt><dd>Ingested with older settings</dd></>}
      <dt>Focus</dt><dd>{Object.keys(d.focus).length ? 'Focused' : 'Everything'}</dd>
      <dt>Summary</dt>
      <dd>{d.summary === null ? 'Not shown while acting as the owner: it was built from pages behind a login' : (d.summary || 'none yet')}{d.summarySource === 'manual' ? ' (written by the owner)' : ''}</dd>
      {report && (
        <>
          <dt>Report</dt>
          <dd><IngestionReport report={report} /></dd>
        </>
      )}
      <dt>Ingested with</dt>
      <dd>
        {ingestedWith.length ? (
          <details>
            <summary>
              {ingestedWith.length} setting{ingestedWith.length === 1 ? '' : 's'}, {changedCount} changed from the defaults
            </summary>
            <ul data-testid={`ingested-with-${row.id}`} style={{ margin: '2px 0 0', paddingLeft: 16 }}>
              {ingestedWith.map(s => <li key={s.key}>{s.text}</li>)}
            </ul>
          </details>
        ) : 'not ingested by 2.0 yet'}
      </dd>
      <dt>Login</dt><dd>{d.hasLogin ? 'Has a login' : 'No login'}</dd>
      {d.lastError && <><dt>Last error</dt><dd>{d.lastError}</dd></>}
      <dt />
      <dd style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        {/* The Map view, read-only (§3.4): its routes answer the account's own content only. */}
        {onPages && <button type="button" className="secondaryButton" onClick={onPages}><List size={12} /> Pages</button>}
        <a href={editInGlobalHref(row.id)} {...linkProps}><ExternalLink size={12} /> Edit in Global Settings</a>
      </dd>
    </dl>
  )
}
