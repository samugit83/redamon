'use client'

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Plus } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import { actionFailedText, failureText } from '@/components/settings/failureText'
import { ApiError } from '@/lib/apiError'
import { JOB_POLL_MS, isRunning, tradecraftClient, type IngestionSettingsView, type JobView, type ResourceView } from '@/lib/tradecraft/client'
import { ResourceCard } from './ResourceCard'
import { DeleteConfirm } from './DeleteConfirm'
import { ResourceFormV2 } from './form/ResourceFormV2'
import css from './tradecraft.module.css'

const LOAD_FAILED = "Couldn't load your tradecraft resources"

type Status = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; text: string } | { kind: 'denied'; text: string }

/**
 * The 2.0 resources of the account: cards, the basic form, and the job views read every 3 s while a job runs.
 * `headerActions` sit left of Add Resource and show exactly when it does (§3.1).
 */
export function ResourceListV2({ userId, onDirtyChange, headerActions, initialEditId = null, onLoaded }: {
  userId: string
  onDirtyChange: (dirty: boolean) => void
  headerActions?: ReactNode
  /** A resource to open in its Edit form once the list is read (a project's "Edit in Global Settings"). */
  initialEditId?: string | null
  /** Each list read: the tab's librarian banner needs to know whether there are resources (Q10). */
  onLoaded?: (resources: ResourceView[]) => void
}) {
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()
  const [resources, setResources] = useState<ResourceView[]>([])
  const [status, setStatus] = useState<Status>({ kind: 'loading' })
  const [busy, setBusy] = useState<Set<string>>(new Set())
  const [form, setForm] = useState<null | 'new' | ResourceView>(null)
  // The account's ingestion settings: the form shows them as the inherited values and takes the
  // default model and storage from them. Unreadable, the form shows the spec's defaults.
  const [settings, setSettings] = useState<IngestionSettingsView | null>(null)
  const resourcesRef = useRef(resources)
  resourcesRef.current = resources
  const onLoadedRef = useRef(onLoaded)
  onLoadedRef.current = onLoaded

  const load = useCallback(async () => {
    try {
      const list = await tradecraftClient.list(userId)
      setResources(list)
      setStatus({ kind: 'ready' })
      onLoadedRef.current?.(list)
    } catch (e) {
      const denied = e instanceof ApiError && (e.status === 401 || e.status === 403)
      setStatus({ kind: denied ? 'denied' : 'error', text: failureText(LOAD_FAILED, e) })
    }
  }, [userId])

  useEffect(() => { load() }, [load])
  const editOpened = useRef(false)
  useEffect(() => {
    if (!initialEditId || editOpened.current || status.kind !== 'ready') return
    editOpened.current = true
    const target = resources.find(r => r.id === initialEditId)
    if (target) setForm(target)
  }, [initialEditId, status.kind, resources])
  useEffect(() => {
    let live = true
    tradecraftClient.getSettings(userId)
      .then(s => { if (live) setSettings(s.ingestion ?? null) })
      .catch(() => { if (live) setSettings(null) })
    return () => { live = false }
  }, [userId])

  const setJob = useCallback((id: string, job: JobView | null) => {
    setResources(prev => prev.map(r => (r.id === id ? { ...r, job } : r)))
  }, [])

  const anyRunning = resources.some(r => isRunning(r.job))
  useEffect(() => {
    if (!anyRunning) return
    const timer = setInterval(async () => {
      const running = resourcesRef.current.filter(r => isRunning(r.job))
      let ended = false
      for (const r of running) {
        try {
          const { job } = await tradecraftClient.job(userId, r.id)
          setJob(r.id, job)
          if (!isRunning(job)) ended = true
        } catch {
          // The next tick reads it again; the card keeps its last view meanwhile.
        }
      }
      // A finished job changed the map, the report and the dates: read the resources again.
      if (ended) load()
    }, JOB_POLL_MS)
    return () => clearInterval(timer)
  }, [anyRunning, userId, setJob, load])

  const withBusy = async (id: string, work: () => Promise<void>) => {
    setBusy(prev => new Set(prev).add(id))
    try { await work() } finally {
      setBusy(prev => { const next = new Set(prev); next.delete(id); return next })
    }
  }

  const refresh = (r: ResourceView) => withBusy(r.id, async () => {
    try {
      setJob(r.id, (await tradecraftClient.refresh(userId, r.id)).job)
    } catch (e) {
      const job = e instanceof ApiError ? (e.body?.job as JobView | undefined) : undefined
      if (job) setJob(r.id, job)
      toast.error(actionFailedText('Refresh', e))
    }
  })

  const cancel = (r: ResourceView) => withBusy(r.id, async () => {
    try {
      setJob(r.id, (await tradecraftClient.cancel(userId, r.id)).job)
    } catch (e) {
      toast.error(actionFailedText('Cancel', e))
    }
  })

  const remove = async (r: ResourceView) => {
    const ok = await dangerConfirm(<DeleteConfirm resource={r} />, 'Delete tradecraft resource')
    if (!ok) return
    await withBusy(r.id, async () => {
      try {
        await tradecraftClient.remove(userId, r.id)
        toast.success('Deleted')
      } catch (e) {
        toast.error(actionFailedText('Delete', e))
      }
      await load()
    })
  }

  const toggleEnabled = async (r: ResourceView, next: boolean) => {
    setResources(prev => prev.map(x => (x.id === r.id ? { ...x, enabled: next } : x)))
    try {
      await tradecraftClient.update(userId, r.id, { enabled: next })
    } catch (e) {
      toast.error(actionFailedText('Toggle', e))
      load()
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginBottom: '12px' }}>
        {status.kind === 'ready' && !form && (
          <>
            {headerActions}
            <button type="button" className="primaryButton" onClick={() => setForm('new')}><Plus size={14} /> Add Resource</button>
          </>
        )}
      </div>
      {form && (
        <ResourceFormV2
          userId={userId}
          resource={form === 'new' ? null : form}
          settings={settings}
          onDirtyChange={onDirtyChange}
          onCancel={() => setForm(null)}
          onSaved={saved => {
            setForm(null)
            if (saved.jobError) toast.error(`Saved, but the ingestion did not start (${saved.jobError})`)
            else toast.success(saved.job ? 'Saved: ingestion started' : 'Saved')
            load()
          }}
        />
      )}
      {status.kind === 'loading' && <div className={css.state}>Loading…</div>}
      {status.kind === 'denied' && <div className={css.state} role="alert">You cannot use these resources: {status.text}.</div>}
      {status.kind === 'error' && (
        <div className={css.state} role="alert">
          {status.text}.{' '}<button type="button" className="textButton" onClick={load}>Retry</button>
        </div>
      )}
      {status.kind === 'ready' && resources.length === 0 && (
        <div className={css.state}>No resources yet. Add a site the agent can read during an engagement.</div>
      )}
      {status.kind === 'ready' && resources.length > 0 && (
        <div className={css.list}>
          {resources.map(r => (
            <ResourceCard
              key={r.id}
              userId={userId}
              resource={r}
              busy={busy.has(r.id)}
              onRefresh={refresh}
              onCancel={cancel}
              onEdit={x => setForm(x)}
              onDelete={remove}
              onToggleEnabled={toggleEnabled}
            />
          ))}
        </div>
      )}
    </div>
  )
}
