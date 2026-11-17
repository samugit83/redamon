'use client'

import { useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { Search, SlidersHorizontal } from 'lucide-react'
import { useToast, WikiInfoButton } from '@/components/ui'
import styles from '@/components/settings/Settings.module.css'
import { actionFailedText } from '@/components/settings/failureText'
import { refreshAllText, tradecraftClient } from '@/lib/tradecraft/client'
import { ResourceListV2 } from './ResourceListV2'
import { ConfigureIngestionDialog } from './ConfigureIngestionDialog'
import { ConfigureSearchDialog } from './ConfigureSearchDialog'
import { RefreshAllConfirm } from './dialog/RefreshAllConfirm'
import tc from './tradecraft.module.css'
import { LibrarianModelLine, NoLibrarianBanner, librarianMissing, useLibrarianModel } from './LibrarianModel'

export const BULK_REFRESH_OFFER_TEXT = 'Your resources were converted to Tradecraft 2.0 from their saved maps, without '
  + 'reading their pages. Refresh them for headings, descriptions and search inside pages.'

export interface TradecraftTabProps {
  userId: string
  /** The resource form's unsaved edits, for the page's leave-the-tab guard. */
  onDirtyChange: (dirty: boolean) => void
}

/**
 * Global Settings → Tradecraft. Mounted only while its tab is open. Since the cut-over (T9.3) it
 * is the 2.0 library for every account: the preview switch and the 1.x form and list are gone.
 */
export function TradecraftTab({ userId, onDirtyChange }: TradecraftTabProps) {
  if (!userId) {
    return <div className={styles.section}><div className={styles.emptyState}>Loading…</div></div>
  }
  return <TradecraftV2Section userId={userId} onDirtyChange={onDirtyChange} />
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
  // Save & refresh all, offered once after the conversion of 1.x resources (§7.2, T9.1).
  const [offer, setOffer] = useState(false)
  const [offerError, setOfferError] = useState('')
  const [confirming, setConfirming] = useState<{ id: string; name: string }[] | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshError, setRefreshError] = useState('')
  const librarian = useLibrarianModel(userId, { checkUsable: librarianUse === 'agent' && (resourceCount ?? 0) > 0 })
  useEffect(() => {
    let live = true
    tradecraftClient.getSettings(userId)
      .then(s => {
        if (!live) return
        setLibrarianUse(typeof s.search?.values['librarian.use'] === 'string' ? s.search.values['librarian.use'] as string : null)
        setOffer(s.offerBulkRefresh === true)
      })
      .catch(() => { if (live) setLibrarianUse(null) })
    return () => { live = false }
  }, [userId, searchKey])

  /** Either answer is recorded, so the offer is never shown again; accepting opens the confirmation. */
  const answerOffer = async (accept: boolean) => {
    setOfferError('')
    try {
      await tradecraftClient.answerBulkRefreshOffer(userId)
      setOffer(false)
      if (accept) {
        const list = await tradecraftClient.list(userId)
        setRefreshError('')
        setConfirming(list.filter(r => r.enabled).map(r => ({ id: r.id, name: r.name })))
      }
    } catch (e) {
      setOfferError(actionFailedText(accept ? 'Save & refresh all' : 'Not now', e))
    }
  }

  const refreshAll = async (ids: string[]) => {
    setRefreshing(true)
    setRefreshError('')
    try {
      const started = await tradecraftClient.refreshAll(userId, ids)
      setConfirming(null)
      toast.success(refreshAllText(started))
      setListKey(k => k + 1)
    } catch (e) {
      setRefreshError(actionFailedText('Save & refresh all', e))
    } finally {
      setRefreshing(false)
    }
  }
  const noLibrarian = librarianUse === 'agent' && (resourceCount ?? 0) > 0 && librarianMissing(librarian.state)
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
      {offer && (
        <div className={`${tc.banner} ${tc.bannerInfo}`} role="status" data-testid="bulk-refresh-offer">
          <span className={tc.bannerText}>{BULK_REFRESH_OFFER_TEXT}</span>
          <button type="button" className="primaryButton" onClick={() => void answerOffer(true)}>Save &amp; refresh all</button>
          <button type="button" className="secondaryButton" onClick={() => void answerOffer(false)}>Not now</button>
          {offerError && <span className={tc.failure} role="alert">{offerError}</span>}
        </div>
      )}
      {confirming && (
        <RefreshAllConfirm
          resources={confirming} busy={refreshing} error={refreshError}
          onConfirm={ids => void refreshAll(ids)} onCancel={() => setConfirming(null)}
        />
      )}
      {noLibrarian && <NoLibrarianBanner onChoose={librarian.choose} />}
      <ResourceListV2
        key={listKey}
        userId={userId}
        onDirtyChange={onDirtyChange}
        initialEditId={editId}
        onLoaded={list => setResourceCount(list.length)}
        toolbarStart={<LibrarianModelLine state={librarian.state} onChoose={librarian.choose} />}
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
          onSaved={(_view, refresh) => {
            setConfiguring(false)
            toast.success(refresh
              ? `Saved. ${refreshAllText(refresh)}`
              : 'Saved: each resource uses the new settings the next time it is added or refreshed')
            setListKey(k => k + 1)
          }}
        />
      )}
    </div>
  )
}
