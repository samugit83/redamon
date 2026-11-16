'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toApiError } from '@/lib/apiError'
import { tradecraftClient, type ResourceView } from '@/lib/tradecraft/client'
import { FormSection } from './FormSection'
import { OverrideList, type FormContext } from './OverrideList'
import { SECTION_KEYS, defsOf, overrideStatus } from './sections'
import css from './form.module.css'
import tc from '../tradecraft.module.css'

const SUMMARY_MAX = 6000

export function summaryStatus(resource: Pick<ResourceView, 'summarySource' | 'summaryLocked'> | null, overrideLine: string): string {
  const source = resource?.summarySource === 'manual' ? 'Written by me' : 'Generated'
  const parts = [source, ...(resource?.summaryLocked ? ['locked'] : []), ...(overrideLine === 'Inherit' ? [] : [overrideLine])]
  return parts.join(' · ')
}

/**
 * Summary (§6.9): the settings the summary is written with, and on a saved resource the editor:
 * the text the agent reads, Generated or Written by me, the lock, and Regenerate. The editor saves
 * at once, apart from the form's Save, and starts no ingestion.
 */
export function SummarySection({ ctx, resource, onResource, onJob }: {
  ctx: FormContext
  resource: ResourceView | null
  onResource: (r: ResourceView) => void
  onJob: () => void
}) {
  const [text, setText] = useState(resource?.summary ?? '')
  const [locked, setLocked] = useState(resource?.summaryLocked ?? false)
  const [busy, setBusy] = useState<null | 'save' | 'regenerate'>(null)
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  useEffect(() => {
    setText(resource?.summary ?? '')
    setLocked(resource?.summaryLocked ?? false)
  }, [resource?.summary, resource?.summaryLocked])

  const manual = resource?.summarySource === 'manual'
  const changed = !!resource && (text !== resource.summary || locked !== resource.summaryLocked)
  const act = async (kind: 'save' | 'regenerate', work: () => Promise<void>) => {
    setBusy(kind)
    setMessage(null)
    try { await work() } catch (e) {
      setMessage({ ok: false, text: toApiError(e, kind === 'save' ? "Couldn't save the summary" : "Couldn't start the summary job").message })
    } finally { setBusy(null) }
  }
  const save = () => act('save', async () => {
    const body = text !== resource!.summary ? { text, locked } : { locked }
    const { resource: saved } = await tradecraftClient.saveSummary(ctx.userId, resource!.id, body)
    if (saved) onResource(saved)
    setMessage({ ok: true, text: 'Summary saved' })
  })
  const backToGenerated = () => act('save', async () => {
    const { resource: saved } = await tradecraftClient.saveSummary(ctx.userId, resource!.id, { source: 'generated' })
    if (saved) onResource(saved)
  })
  const regenerate = () => act('regenerate', async () => {
    await tradecraftClient.regenerateSummary(ctx.userId, resource!.id)
    setMessage({ ok: true, text: 'Regenerating the summary in the background' })
    onJob()
  })

  return (
    <FormSection title="Summary" status={summaryStatus(resource, overrideStatus(SECTION_KEYS.summary, ctx.overrides))}>
      {resource && (
        <div className={css.override} aria-label="Summary editor" role="group">
          <label className="formLabel" htmlFor="tc-summary-text">
            The summary the agent reads {manual ? '(written by me)' : '(generated)'}
          </label>
          <textarea
            id="tc-summary-text" className="textarea" rows={6} maxLength={SUMMARY_MAX} value={text}
            onChange={e => setText(e.target.value)}
          />
          <span className={css.inherited}>{text.length.toLocaleString('en-US')} / {SUMMARY_MAX.toLocaleString('en-US')} characters. Saving your own text makes it "Written by me".</span>
          <label className={css.overrideHead}>
            <input type="checkbox" checked={locked} onChange={e => setLocked(e.target.checked)} />
            <span>Lock summary: a refresh rebuilds the map and keeps this summary</span>
          </label>
          <div className={css.row}>
            <button type="button" className="secondaryButton" onClick={save} disabled={!changed || !!busy || !text.trim()}>
              {busy === 'save' && <Loader2 size={14} className={tc.spin} />} Save summary
            </button>
            {manual && <button type="button" className="textButton" onClick={backToGenerated} disabled={!!busy}>Back to Generated</button>}
            <button
              type="button" className="secondaryButton" onClick={regenerate} disabled={!!busy || manual || resource.summaryLocked}
              title={resource.summaryLocked ? 'Unlock the summary to regenerate it' : manual ? 'Switch back to Generated to regenerate it' : undefined}
            >
              {busy === 'regenerate' && <Loader2 size={14} className={tc.spin} />} Regenerate
            </button>
          </div>
          {message && <span className={message.ok ? css.checkResult : css.checkFailed} role={message.ok ? 'status' : 'alert'}>{message.text}</span>}
        </div>
      )}
      <OverrideList ctx={ctx} defs={defsOf('summary')} />
    </FormSection>
  )
}
