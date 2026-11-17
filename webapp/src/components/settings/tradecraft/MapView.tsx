'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ExternalLink, Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ApiError, toApiError } from '@/lib/apiError'
import {
  tradecraftClient, type CurateOp, type MapEntryView, type MapStatus, type PageTextView, type ReadNowResult,
} from '@/lib/tradecraft/client'
import { failureText } from '@/components/settings/failureText'
import css from './mapView.module.css'
import tc from './tradecraft.module.css'

export interface MapViewResource {
  id: string
  name: string
  url: string
  storageMode: string
}

const LOAD_FAILED = "Couldn't read the map"
export const READ_ONLY_NOTE = 'Read-only: pins, blocks, renames and restores are made in Global Settings > Tradecraft.'
export const BLOCK_NOTE = 'Their stored text is deleted now, and a refresh never adds them back.'
export const READ_NOW_NOTE = 'Downloaded now the way the agent reads it; nothing is kept.'

type Load =
  | { kind: 'loading' }
  | { kind: 'ready' }
  | { kind: 'error'; text: string }
  | { kind: 'denied'; text: string }
  | { kind: 'off' }

type Viewing = {
  entry: MapEntryView
  page?: PageTextView
  read?: ReadNowResult
  busy: boolean
  error: string
}

type Confirming =
  | { kind: 'selected'; urls: string[] }
  | { kind: 'matching'; count: number; changed?: string }

const TABS: ReadonlyArray<[MapStatus, string]> = [['kept', 'In the map'], ['dropped', 'Dropped'], ['blocked', 'Blocked']]

/** Only a web address becomes a link: a map entry is page data, and a `javascript:` one must never run. */
function isWebUrl(url: string): boolean {
  return /^https?:\/\//i.test(url)
}

function fetchedText(iso: string | null): string {
  if (!iso) return 'date unknown'
  const d = new Date(iso)
  return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'date unknown'
}

/**
 * The Map view of a resource (§6.10): its map searched by title or URL, the count, each entry's
 * source, tags and one-line description; View shows the page's text exactly as the agent reads it,
 * always as plain text in a `<pre>` (nothing in it runs); Open on the site opens a new tab; Read
 * now downloads it once and keeps nothing. Curation: Pin a URL, Block one, the ticked ones or all
 * matching the search (the confirmation shows the count, and a changed count is refused and shown
 * again), the Blocked filter with Unblock, Rename, the Dropped filter with Restore. `readOnly` (a
 * project's Pages, §3.4) keeps search, tags, descriptions, View, Open and Read now only.
 */
export function MapView({ userId, resource, readOnly = false, onClose }: {
  userId: string
  resource: MapViewResource
  readOnly?: boolean
  onClose: () => void
}) {
  const [status, setStatus] = useState<MapStatus>('kept')
  const [queryDraft, setQueryDraft] = useState('')
  const [query, setQuery] = useState('')
  const [tag, setTag] = useState('')
  const [entries, setEntries] = useState<MapEntryView[]>([])
  const [total, setTotal] = useState(0)
  const [cursor, setCursor] = useState<string | null>(null)
  const [load, setLoad] = useState<Load>({ kind: 'loading' })
  const [moreBusy, setMoreBusy] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [viewing, setViewing] = useState<Viewing | null>(null)
  const [renaming, setRenaming] = useState<{ url: string; title: string } | null>(null)
  const [pinDraft, setPinDraft] = useState('')
  const [confirming, setConfirming] = useState<Confirming | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [actionError, setActionError] = useState('')
  const [reloadToken, setReloadToken] = useState(0)

  const read = useCallback(async (after: string | null) => {
    return tradecraftClient.map(userId, resource.id, { query: query || undefined, status, tag: tag || undefined, cursor: after })
  }, [userId, resource.id, query, status, tag])

  useEffect(() => {
    let live = true
    setLoad({ kind: 'loading' })
    setSelected(new Set())
    read(null)
      .then(page => {
        if (!live) return
        setEntries(page.entries)
        setTotal(page.total)
        setCursor(page.nextCursor)
        setLoad({ kind: 'ready' })
      })
      .catch(e => {
        if (!live) return
        if (e instanceof ApiError && e.code === 'tradecraft_v2_off') return setLoad({ kind: 'off' })
        const denied = e instanceof ApiError && (e.status === 401 || e.status === 403)
        setLoad({ kind: denied ? 'denied' : 'error', text: failureText(LOAD_FAILED, e) })
      })
    return () => { live = false }
  }, [read, reloadToken])

  const reload = () => setReloadToken(t => t + 1)

  const more = async () => {
    if (!cursor) return
    setMoreBusy(true)
    try {
      const page = await read(cursor)
      setEntries(prev => [...prev, ...page.entries])
      setTotal(page.total)
      setCursor(page.nextCursor)
    } catch (e) {
      setActionError(toApiError(e, LOAD_FAILED).message)
    } finally {
      setMoreBusy(false)
    }
  }

  const switchTab = (next: MapStatus) => {
    setStatus(next)
    setViewing(null)
    setConfirming(null)
    setNotice('')
    setActionError('')
  }

  const search = (e: FormEvent) => {
    e.preventDefault()
    setQuery(queryDraft.trim())
    setConfirming(null)
  }

  /** Runs one operation; a refusal is shown in its own words, a success re-reads the list. */
  const run = async (op: CurateOp, done: (count: number) => string): Promise<boolean> => {
    setBusy(true)
    setActionError('')
    setNotice('')
    try {
      const { count } = await tradecraftClient.curate(userId, resource.id, op)
      setNotice(done(count))
      setConfirming(null)
      setRenaming(null)
      setViewing(null)
      reload()
      return true
    } catch (e) {
      const err = toApiError(e, "Couldn't change the map")
      if (op.op === 'block' && 'matching' in op && err.code === 'count_changed' && typeof err.body?.count === 'number') {
        // A refresh changed what the search matches: the person confirms the new count.
        setConfirming({ kind: 'matching', count: err.body.count, changed: err.reason })
        reload()
      } else {
        setActionError(err.message)
      }
      return false
    } finally {
      setBusy(false)
    }
  }

  const pages = (count: number) => `${count.toLocaleString('en-US')} ${count === 1 ? 'page' : 'pages'}`

  const blockOne = (e: MapEntryView) => run({ op: 'block', urls: [e.url] }, () => `Blocked: ${e.title || e.url}`)
  const unblock = (urls: string[]) => run({ op: 'unblock', urls }, c => `Unblocked ${pages(c)}: back in the map at the next refresh`)
  const restore = (e: MapEntryView) => run({ op: 'restore', url: e.url }, () => `Restored and pinned: ${e.title || e.url}`)
  const confirmBlock = () => {
    if (!confirming) return
    if (confirming.kind === 'selected') {
      void run({ op: 'block', urls: confirming.urls }, c => `Blocked ${pages(c)}`)
    } else {
      void run({
        op: 'block',
        matching: { ...(query ? { query } : {}), status: status === 'dropped' ? 'dropped' : 'kept', ...(tag ? { tag } : {}) },
        expectedCount: confirming.count,
      }, c => `Blocked ${pages(c)}`)
    }
  }
  const pin = async (e: FormEvent) => {
    e.preventDefault()
    const url = pinDraft.trim()
    if (!url) return
    if (await run({ op: 'pin', url }, () => 'Pinned: the page joins the map at the next refresh')) setPinDraft('')
  }
  const saveRename = () => {
    if (!renaming) return
    void run({ op: 'rename', url: renaming.url, title: renaming.title.trim() }, () => (renaming.title.trim() ? 'Renamed' : 'The page keeps its own title'))
  }

  const view = async (entry: MapEntryView) => {
    setViewing({ entry, busy: true, error: '' })
    try {
      const page = await tradecraftClient.page(userId, resource.id, entry.pageId)
      setViewing({ entry, page, busy: false, error: '' })
    } catch (e) {
      setViewing({ entry, busy: false, error: toApiError(e, "Couldn't read the page").message })
    }
  }

  const readNow = async (entry: MapEntryView) => {
    setViewing(prev => ({ ...(prev?.entry.url === entry.url ? prev : {}), entry, read: undefined, busy: true, error: '' }))
    try {
      const { result } = await tradecraftClient.readNow(userId, resource.id, entry.pageId)
      setViewing(prev => ({ ...(prev?.entry.url === entry.url ? prev : {}), entry, read: result, busy: false, error: '' }))
    } catch (e) {
      setViewing(prev => ({ ...(prev?.entry.url === entry.url ? prev : {}), entry, busy: false, error: toApiError(e, 'Read now failed').message }))
    }
  }

  const toggle = (url: string, on: boolean) => setSelected(prev => {
    const next = new Set(prev)
    if (on) next.add(url)
    else next.delete(url)
    return next
  })

  const sources = [...new Set(entries.map(e => e.source).filter(Boolean))]
  const curating = !readOnly
  const tabs = readOnly ? TABS.slice(0, 1) : TABS

  return (
    <Modal isOpen onClose={onClose} title={`Map of ${resource.name}`} size="large">
      <div data-testid="tc-map-view">
        {readOnly && <p className={css.hint}>{READ_ONLY_NOTE}</p>}
        <div className={css.toolbar}>
          {tabs.length > 1 && (
            <div className={css.tabs} role="group" aria-label="Which pages">
              {tabs.map(([id, label]) => (
                <button key={id} type="button" className={css.tab} aria-pressed={status === id} onClick={() => switchTab(id)}>{label}</button>
              ))}
            </div>
          )}
          <form className={css.grow} onSubmit={search} role="search" style={{ display: 'flex', gap: 6 }}>
            <input
              className="textInput" aria-label="Search the map" placeholder="Search titles and URLs, e.g. /tag/"
              value={queryDraft} onChange={e => setQueryDraft(e.target.value)} maxLength={200}
            />
            <button type="submit" className="secondaryButton">Search</button>
          </form>
          {tag && (
            <button type="button" className={css.chip} onClick={() => setTag('')} aria-label={`Clear the tag ${tag}`}>tag: {tag} ×</button>
          )}
        </div>

        {curating && status === 'kept' && (
          <form className={css.toolbar} onSubmit={pin}>
            <input
              className={`textInput ${css.grow}`} aria-label="Pin a URL" placeholder="Pin a page by its URL: it stays in the map"
              value={pinDraft} onChange={e => setPinDraft(e.target.value)} maxLength={2048}
            />
            <button type="submit" className="secondaryButton" disabled={busy || !pinDraft.trim()}>Pin</button>
          </form>
        )}

        {load.kind === 'ready' && (
          <div className={css.toolbar}>
            <span className={css.count} data-testid="tc-map-count">
              {pages(total)}{query || tag ? ' match' : ''}{sources.length > 0 ? ` · from ${sources.join(', ')}` : ''}
            </span>
            {curating && status !== 'blocked' && (
              <>
                <button
                  type="button" className="secondaryButton" disabled={busy || selected.size === 0}
                  onClick={() => setConfirming({ kind: 'selected', urls: [...selected] })}
                >
                  Block selected ({selected.size})
                </button>
                {(query || tag) && (
                  <button
                    type="button" className="secondaryButton" disabled={busy || total === 0}
                    onClick={() => setConfirming({ kind: 'matching', count: total })}
                  >
                    Block all matching the search
                  </button>
                )}
              </>
            )}
            {curating && status === 'blocked' && (
              <button type="button" className="secondaryButton" disabled={busy || selected.size === 0} onClick={() => void unblock([...selected])}>
                Unblock selected ({selected.size})
              </button>
            )}
          </div>
        )}

        {confirming && (
          <div className={css.confirm} role="alertdialog" aria-label="Confirm the block">
            {confirming.kind === 'matching' && confirming.changed && <span className={css.error}>{confirming.changed}.</span>}
            <span>
              Block {pages(confirming.kind === 'selected' ? confirming.urls.length : confirming.count)}
              {confirming.kind === 'matching' ? ` matching "${[query, tag && `tag ${tag}`].filter(Boolean).join(', ')}"` : ''}? {BLOCK_NOTE}
            </span>
            <button type="button" className="secondaryButton" onClick={() => setConfirming(null)} disabled={busy}>Cancel</button>
            <button type="button" className="primaryButton" onClick={confirmBlock} disabled={busy}>
              {busy && <Loader2 size={12} className={tc.spin} />} Block
            </button>
          </div>
        )}
        {notice && <div className={css.notice} role="status">{notice}</div>}
        {actionError && <div className={css.error} role="alert">{actionError}</div>}

        {load.kind === 'loading' && <div className={tc.state}>Loading the map…</div>}
        {load.kind === 'off' && <div className={tc.state} role="alert">Tradecraft 2.0 is off for this account: the Map view needs it.</div>}
        {load.kind === 'denied' && <div className={tc.state} role="alert">You cannot see this map: {load.text}.</div>}
        {load.kind === 'error' && (
          <div className={tc.state} role="alert">
            {load.text}.{' '}<button type="button" className="textButton" onClick={reload}>Retry</button>
          </div>
        )}
        {load.kind === 'ready' && entries.length === 0 && (
          <div className={tc.state}>
            {query || tag ? 'No page matches the search.'
              : status === 'blocked' ? 'No page is blocked.'
                : status === 'dropped' ? 'The focus dropped no page.'
                  : 'No pages in the map yet: refresh the resource to build it.'}
          </div>
        )}
        {load.kind === 'ready' && entries.length > 0 && (
          <ul className={css.entries}>
            {entries.map(e => (
              <li key={e.url} className={css.entry} data-entry={e.url}>
                {curating && (
                  <input
                    type="checkbox" aria-label={`Select ${e.title || e.url}`} checked={selected.has(e.url)}
                    onChange={ev => toggle(e.url, ev.target.checked)}
                  />
                )}
                <div className={css.entryBody}>
                  {renaming?.url === e.url ? (
                    <div style={{ display: 'flex', gap: 6 }}>
                      <input
                        className="textInput" aria-label="New title" value={renaming.title} maxLength={300}
                        onChange={ev => setRenaming({ url: e.url, title: ev.target.value })}
                      />
                      <button type="button" className="primaryButton" onClick={saveRename} disabled={busy}>Save title</button>
                      <button type="button" className="secondaryButton" onClick={() => setRenaming(null)} disabled={busy}>Cancel</button>
                    </div>
                  ) : (
                    <span className={css.entryTitle}>{e.title || '(no title)'}{e.renamed && <span className={css.hint}> (renamed)</span>}</span>
                  )}
                  <span className={css.entryUrl}>{e.url}</span>
                  <div className={css.entryMeta}>
                    {e.pageId && <span>{e.pageId}</span>}
                    {e.source && <span>source: {e.source}</span>}
                    {e.pinned && <span className={tc.badge}>pinned</span>}
                    {e.stored && <span className={tc.badge}>stored</span>}
                    {[...e.topics, ...e.kinds, ...e.technologies].map(t => (
                      <button key={t} type="button" className={css.chip} onClick={() => setTag(t)} aria-label={`Filter by the tag ${t}`}>{t}</button>
                    ))}
                  </div>
                  {e.description && <span className={css.count}>{e.description}</span>}
                  {e.status === 'dropped' && <span className={css.hint}>dropped{e.reason ? `: ${e.reason}` : ''}</span>}
                  <div className={css.actions}>
                    {e.pageId && <button type="button" className="secondaryButton" onClick={() => void view(e)}>View</button>}
                    {isWebUrl(e.url) && (
                      <a className="secondaryButton" href={e.url} target="_blank" rel="noopener noreferrer">
                        <ExternalLink size={12} /> Open on the site
                      </a>
                    )}
                    {e.pageId && status !== 'blocked' && (
                      <button type="button" className="secondaryButton" onClick={() => void readNow(e)}>Read now</button>
                    )}
                    {curating && status === 'kept' && (
                      <button type="button" className="secondaryButton" onClick={() => setRenaming({ url: e.url, title: e.renamed ? e.title : '' })} disabled={busy}>
                        Rename
                      </button>
                    )}
                    {curating && status !== 'blocked' && (
                      <button type="button" className="secondaryButton" onClick={() => void blockOne(e)} disabled={busy}>Block</button>
                    )}
                    {curating && status === 'dropped' && (
                      <button type="button" className="secondaryButton" onClick={() => void restore(e)} disabled={busy}>Restore</button>
                    )}
                    {curating && status === 'blocked' && (
                      <button type="button" className="secondaryButton" onClick={() => void unblock([e.url])} disabled={busy}>Unblock</button>
                    )}
                  </div>
                  {viewing?.entry.url === e.url && <PagePanel viewing={viewing} storageMode={resource.storageMode} onReadNow={() => void readNow(e)} />}
                </div>
              </li>
            ))}
          </ul>
        )}
        {load.kind === 'ready' && cursor && (
          <div style={{ marginTop: 8 }}>
            <button type="button" className="secondaryButton" onClick={() => void more()} disabled={moreBusy}>
              {moreBusy && <Loader2 size={12} className={tc.spin} />} Load more
            </button>
          </div>
        )}
      </div>
    </Modal>
  )
}

/** What View and Read now answered: always plain text, never rendered as a page. */
function PagePanel({ viewing, storageMode, onReadNow }: { viewing: Viewing; storageMode: string; onReadNow: () => void }) {
  const { page, read, busy, error } = viewing
  return (
    <div data-testid="tc-page-panel">
      {busy && <span className={css.hint}><Loader2 size={12} className={tc.spin} /> Reading…</span>}
      {error && <div className={css.error} role="alert">{error}</div>}
      {page && page.blocked && <span className={css.hint}>Blocked: unblock it to read it.</span>}
      {page && !page.blocked && page.stored && (
        <>
          <span className={css.hint}>Stored text, downloaded {fetchedText(page.fetchedAt)}. Nothing was fetched.</span>
          <pre className={css.pageText} data-testid="tc-page-text">{page.text}</pre>
        </>
      )}
      {page && !page.blocked && !page.stored && !read && (
        <span className={css.hint}>
          {storageMode === 'stored' ? 'Not stored (beyond the storage limits): ' : 'A Live resource keeps no text: '}
          Open it on the site, or{' '}
          <button type="button" className={tc.linkButton} onClick={onReadNow} disabled={busy}>Read now</button>.
        </span>
      )}
      {read && (
        <>
          <span className={css.hint}>
            {READ_NOW_NOTE}{read.truncated ? ' The text was cut at the read limit.' : ''}
            {read.error_code ? ` The read failed: ${read.error_code}.` : ''}
          </span>
          {!read.error_code && <pre className={css.pageText} data-testid="tc-read-now-text">{read.text}</pre>}
        </>
      )}
    </div>
  )
}
