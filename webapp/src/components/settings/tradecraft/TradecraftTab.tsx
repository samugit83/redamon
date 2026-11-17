'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { Plus, Search, SlidersHorizontal } from 'lucide-react'
import { TradecraftResourceForm } from '@/components/settings/TradecraftResourceForm'
import type { TradecraftResource } from '@/components/settings/TradecraftResourceForm'
import { TradecraftResourceList } from '@/components/settings/TradecraftResourceList'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import styles from '@/components/settings/Settings.module.css'
import { actionFailedText, failureText } from '@/components/settings/failureText'
import { readApiError } from '@/lib/apiError'
import { tradecraftClient } from '@/lib/tradecraft/client'
import { V2Switch } from './V2Switch'
import { ResourceListV2 } from './ResourceListV2'
import { ConfigureIngestionDialog } from './ConfigureIngestionDialog'
import { ConfigureSearchDialog } from './ConfigureSearchDialog'
import { LibrarianModelLine, NoLibrarianBanner, useLibrarianModel } from './LibrarianModel'

const TRADECRAFT_LOAD_FAILED = "Couldn't load your tradecraft resources"

type TcResource = TradecraftResource & {
  crawlStoppedBecause?: string
  crawlStats?: { pages_fetched?: number; llm_calls?: number; elapsed_sec?: number }
  sitemap?: { nav?: unknown[]; tree?: unknown[]; pages?: unknown[]; links?: unknown[] }
}

export interface TradecraftTabProps {
  userId: string
  /** The resource form's unsaved edits, for the page's leave-the-tab guard. */
  onDirtyChange: (dirty: boolean) => void
}

/**
 * Global Settings → Tradecraft. Mounted only while its tab is open. The account's Tradecraft 2.0
 * (preview) switch sits on top; with it off the tab is exactly the 1.x component. A switch that
 * cannot be read shows the 1.x tab without it: the routes decide by the switch themselves.
 */
export function TradecraftTab({ userId, onDirtyChange }: TradecraftTabProps) {
  const [v2, setV2] = useState<boolean | null>(null)
  const [switchKnown, setSwitchKnown] = useState(false)

  useEffect(() => {
    if (!userId) return
    let live = true
    tradecraftClient.getSwitch(userId)
      .then(s => { if (live) { setV2(s?.v2Enabled === true); setSwitchKnown(true) } })
      .catch(() => { if (live) { setV2(false); setSwitchKnown(false) } })
    return () => { live = false }
  }, [userId])

  if (!userId || v2 === null) {
    return <div className={styles.section}><div className={styles.emptyState}>Loading…</div></div>
  }
  return (
    <>
      {switchKnown && <V2Switch userId={userId} enabled={v2} onChange={setV2} />}
      {v2 ? <TradecraftV2Section userId={userId} onDirtyChange={onDirtyChange} /> : <LegacyTradecraftTab userId={userId} onDirtyChange={onDirtyChange} />}
    </>
  )
}

function TradecraftV2Section({ userId, onDirtyChange }: TradecraftTabProps) {
  const toast = useToast()
  // A project's "Edit in Global Settings" link (§3.4) names the resource to open.
  const editId = useSearchParams()?.get('edit') ?? null
  const [configuring, setConfiguring] = useState(false)
  const [configuringSearch, setConfiguringSearch] = useState(false)
  // A save changes which cards read as stale: the list is read again by mounting it anew.
  const [listKey, setListKey] = useState(0)
  const [resourceCount, setResourceCount] = useState<number | null>(null)
  // Librarian use (Q11): with "Search only" no librarian model is needed, so none is missing.
  const [librarianUse, setLibrarianUse] = useState<string | null>(null)
  const [searchKey, setSearchKey] = useState(0)
  const librarian = useLibrarianModel(userId)
  useEffect(() => {
    let live = true
    tradecraftClient.getSettings(userId)
      .then(s => { if (live) setLibrarianUse(typeof s.search?.values['librarian.use'] === 'string' ? s.search.values['librarian.use'] as string : null) })
      .catch(() => { if (live) setLibrarianUse(null) })
    return () => { live = false }
  }, [userId, searchKey])
  const noLibrarian = librarianUse === 'agent' && (resourceCount ?? 0) > 0 && librarian.state.kind === 'ready' && !librarian.state.model
  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}>
          Tradecraft Resources
          <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Tradecraft-Lookup" title="Open Tradecraft Lookup wiki page" />
        </h2>
      </div>
      <p className={styles.sectionHint}>
        Curated knowledge sites the agent consults during exploitation. Each resource is ingested in the
        background: its card shows the stage, and Refresh becomes Cancel while it runs. Live resources are
        read from their site at every read; Stored ones keep a copy in your database.
      </p>
      {noLibrarian && <NoLibrarianBanner onChoose={librarian.choose} />}
      <LibrarianModelLine state={librarian.state} onChoose={librarian.choose} />
      <ResourceListV2
        key={listKey}
        userId={userId}
        onDirtyChange={onDirtyChange}
        initialEditId={editId}
        onLoaded={list => setResourceCount(list.length)}
        headerActions={
          <>
            <button type="button" className="secondaryButton" onClick={() => setConfiguringSearch(true)}>
              <Search size={14} /> Configure search
            </button>
            <button type="button" className="secondaryButton" onClick={() => setConfiguring(true)}>
              <SlidersHorizontal size={14} /> Configure ingestion
            </button>
          </>
        }
      />
      {configuringSearch && (
        <ConfigureSearchDialog
          userId={userId}
          onDirtyChange={onDirtyChange}
          onClose={() => setConfiguringSearch(false)}
          onSaved={() => {
            setConfiguringSearch(false)
            toast.success('Saved: the agent uses the new search settings from the next message')
            setSearchKey(k => k + 1)
            setListKey(k => k + 1)
          }}
        />
      )}
      {configuring && (
        <ConfigureIngestionDialog
          userId={userId}
          onDirtyChange={onDirtyChange}
          onClose={() => setConfiguring(false)}
          onSaved={() => {
            setConfiguring(false)
            toast.success('Saved: each resource uses the new settings the next time it is added or refreshed')
            setListKey(k => k + 1)
          }}
        />
      )}
    </div>
  )
}

/** The 1.x tab, unchanged. */
function LegacyTradecraftTab({ userId, onDirtyChange }: TradecraftTabProps) {
  const { confirm: showConfirm } = useAlertModal()
  const toast = useToast()
  const [tcResources, setTcResources] = useState<TcResource[]>([])
  const [tcLoading, setTcLoading] = useState(false)
  const [tcShowForm, setTcShowForm] = useState(false)
  const [tcEditing, setTcEditing] = useState<TcResource | null>(null)
  const [tcRefreshingId, setTcRefreshingId] = useState<string | null>(null)
  const [tcError, setTcError] = useState<string | null>(null)
  const tcPollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchTcResources = useCallback(async () => {
    if (!userId) return
    setTcLoading(true)
    try {
      const r = await fetch(`/api/users/${userId}/tradecraft-resources`)
      if (r.ok) {
        setTcResources(await r.json())
        setTcError(null)
      } else {
        setTcError(failureText(TRADECRAFT_LOAD_FAILED, await readApiError(r, TRADECRAFT_LOAD_FAILED)))
      }
    } catch (e) {
      console.error('fetchTcResources', e)
      setTcError(failureText(TRADECRAFT_LOAD_FAILED, e))
    }
    finally { setTcLoading(false) }
  }, [userId])

  useEffect(() => {
    if (userId) {
      fetchTcResources()
    }
  }, [userId, fetchTcResources])

  // Light polling while a resource has not yet been verified (lastVerifiedAt null)
  useEffect(() => {
    if (!userId) {
      if (tcPollingRef.current) { clearInterval(tcPollingRef.current); tcPollingRef.current = null }
      return
    }
    const anyPending = tcResources.some(r => !r.lastVerifiedAt)
    if (anyPending && !tcPollingRef.current) {
      tcPollingRef.current = setInterval(fetchTcResources, 5000)
    } else if (!anyPending && tcPollingRef.current) {
      clearInterval(tcPollingRef.current); tcPollingRef.current = null
    }
    return () => {
      if (tcPollingRef.current) { clearInterval(tcPollingRef.current); tcPollingRef.current = null }
    }
  }, [userId, tcResources, fetchTcResources])

  const tcHandleSave = useCallback(() => {
    setTcShowForm(false); setTcEditing(null); fetchTcResources(); toast.success('Saved')
  }, [fetchTcResources, toast])

  const tcHandleCancel = useCallback(() => { setTcShowForm(false); setTcEditing(null) }, [])

  const tcHandleDelete = useCallback(async (r: TcResource) => {
    if (!userId || !r.id) return
    const ok = await showConfirm(
      `Delete "${r.name}"? This removes the catalog entry and disk cache.`,
      'Delete tradecraft resource',
    )
    if (!ok) return
    try {
      const resp = await fetch(`/api/users/${userId}/tradecraft-resources/${r.id}`, { method: 'DELETE' })
      if (!resp.ok) throw await readApiError(resp, 'the server gave no reason')
      toast.success('Deleted')
      fetchTcResources()
    } catch (e) { toast.error(actionFailedText('Delete', e)) }
  }, [userId, showConfirm, toast, fetchTcResources])

  const tcHandleRefresh = useCallback(async (r: TcResource) => {
    if (!userId || !r.id) return
    setTcRefreshingId(r.id)
    try {
      const resp = await fetch(`/api/users/${userId}/tradecraft-resources/${r.id}/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
      })
      if (!resp.ok) throw await readApiError(resp, 'the server gave no reason')
      toast.success('Refreshed')
      fetchTcResources()
    } catch (e) {
      toast.error(actionFailedText('Refresh', e))
      // A failed refresh records its cause on the row (lastError).
      fetchTcResources()
    }
    finally { setTcRefreshingId(null) }
  }, [userId, toast, fetchTcResources])

  const tcHandleToggleEnabled = useCallback(async (r: TcResource, next: boolean) => {
    if (!userId || !r.id) return
    // Optimistic update
    setTcResources(prev => prev.map(x => x.id === r.id ? { ...x, enabled: next } : x))
    try {
      const resp = await fetch(`/api/users/${userId}/tradecraft-resources/${r.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: next }),
      })
      if (!resp.ok) throw await readApiError(resp, 'the server gave no reason')
    } catch (e) {
      toast.error(actionFailedText('Toggle', e))
      fetchTcResources()
    }
  }, [userId, toast, fetchTcResources])

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}>
          Tradecraft Resources
          <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Tradecraft-Lookup" title="Open Tradecraft Lookup wiki page" />
        </h2>
        {!tcShowForm && !tcEditing && (
          <button className="primaryButton" onClick={() => setTcShowForm(true)}>
            <Plus size={14} /> Add Resource
          </button>
        )}
      </div>
      <p className={styles.sectionHint}>
        Curated knowledge sites the agent consults during exploitation
        (HackTricks, PayloadsAllTheThings, CVE PoC repos, ...). On add, the
        agent fetches the homepage, builds a sitemap, and writes a short
        summary that becomes the tool&apos;s catalog entry. The agent only sees
        enabled resources.
      </p>
      {(tcShowForm || tcEditing) && (
        <TradecraftResourceForm
          userId={userId}
          resource={tcEditing}
          onDirtyChange={onDirtyChange}
          onSave={tcHandleSave}
          onCancel={tcHandleCancel}
        />
      )}
      {tcError && (
        <div className={styles.emptyState} role="alert">
          {tcError}.{' '}
          <button type="button" className="textButton" onClick={fetchTcResources}>Retry</button>
        </div>
      )}
      <TradecraftResourceList
        resources={tcResources}
        loading={tcLoading}
        refreshingId={tcRefreshingId}
        onEdit={(r) => setTcEditing(r)}
        onDelete={tcHandleDelete}
        onRefresh={tcHandleRefresh}
        onToggleEnabled={tcHandleToggleEnabled}
      />
    </div>
  )
}
