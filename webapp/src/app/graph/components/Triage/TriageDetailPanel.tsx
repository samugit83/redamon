'use client'

/**
 * Why a finding sits where it does on the Priority Board: the result, the
 * rules that scored it, the review that corrected it, the decision that
 * overrides both, the evidence a reviewer read, and the findings it shares a
 * fix with.
 *
 * It is a side panel over the board rather than a page, so the board stays
 * usable behind it: an agent error here is an inline Retry, not a broken tab.
 * The evidence loads on its own spinner because it is the one slow, large
 * read, and the rest of the panel is useful without it.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { AlertTriangle, Check, Loader2, RotateCcw, X } from 'lucide-react'
import {
  FACTOR_KEYS, FACTOR_NAMES, NOT_REVIEWABLE_TEXT, TIER_LABELS, asTier, baseLine,
  changedFactors, decisionChip, fmtWhen, formatFactor, parseFactors, parseJson,
  personDecided, reviewChip, tierForScore, tierOf,
  type TriageFinding, type VerdictResult, type VerdictStatus,
} from './triageLayers'
import { DispositionLine } from './DispositionChip'
import { readDisposition } from '@/lib/triage/disposition'
import { triageBodyErrorText } from '@/lib/triage/errorText'
import { toApiError } from '@/lib/apiError'
import { useRefusal } from '@/hooks/useRefusal'
import styles from './TriageDetailPanel.module.css'

interface GroupMember {
  id: string
  label: string
  name: string
  state: string
  score: number | null
  tier: string
  host: string
}

interface FindingDetail {
  row: TriageFinding & { proven_now?: boolean; proof_types?: string[] }
  group: GroupMember[]
  detector: { key: string; real: number; fp: number }
  review_survives_rescan?: boolean
}

interface EvidenceAnswer {
  evidence: string
  matches_last_run: boolean
  reviewable: boolean
  not_reviewable_because: string | null
  review_survives_rescan: boolean
}

type Load<T> =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'gone' }
  | { kind: 'ready'; data: T }

export interface DetailTarget {
  id: string
  label: string
  name: string
}

interface TriageDetailPanelProps {
  projectId: string
  target: DetailTarget
  /** The board's current row, null once it has been dropped. A verdict made
   *  from the panel or the row replaces it, and the panel follows. */
  row: TriageFinding | null
  onClose: () => void
  onVerdict: (status: VerdictStatus, reason: string) => Promise<VerdictResult>
  /** The finding no longer exists: drop it from the board. */
  onGone: () => void
  onReload: () => void
}

interface Corrections {
  verdict?: string
  impact_multiplier?: number
  impact_quote?: string
  disputed_facts?: Array<{ fact?: string; quote?: string }>
}

async function readJson(res: Response): Promise<Record<string, unknown>> {
  return (await res.json().catch(() => ({}))) as Record<string, unknown>
}

function failureText(body: Record<string, unknown>, what: string, status: number): string {
  return triageBodyErrorText(body, status, `The ${what} could not be loaded.`)
}

const NO_ANSWER = 'The findings service did not answer.'

export function TriageDetailPanel({
  projectId, target, row, onClose, onVerdict, onGone, onReload,
}: TriageDetailPanelProps) {
  const [detail, setDetail] = useState<Load<FindingDetail>>({ kind: 'loading' })
  const [evidence, setEvidence] = useState<Load<EvidenceAnswer>>({ kind: 'loading' })
  // A person's decision is triage:verdict's; a read share reads the decision and makes none (4.11).
  const verdictRefusal = useRefusal('triage:verdict', projectId)?.text ?? null
  const [detailTry, setDetailTry] = useState(0)
  const [evidenceTry, setEvidenceTry] = useState(0)
  /** The board row as it was when the detail loaded. A different object later
   *  means a verdict replaced it, so its newer values win over the detail's. */
  const [rowAtLoad, setRowAtLoad] = useState<TriageFinding | null>(row)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState<VerdictStatus | null>(null)
  const [decisionError, setDecisionError] = useState<string | null>(null)

  const query = `projectId=${encodeURIComponent(projectId)}` +
    `&findingId=${encodeURIComponent(target.id)}&label=${encodeURIComponent(target.label)}`

  useEffect(() => {
    let live = true
    setDetail({ kind: 'loading' })
    ;(async () => {
      try {
        const res = await fetch(`/api/triage/finding?${query}`)
        const body = await readJson(res)
        if (!live) return
        if (res.status === 404) {
          setDetail({ kind: 'gone' })
          onGone()
          return
        }
        if (!res.ok) {
          setDetail({ kind: 'error', message: failureText(body, 'finding', res.status) })
          return
        }
        setRowAtLoad(row)
        setDetail({ kind: 'ready', data: body as unknown as FindingDetail })
      } catch (e) {
        if (live) setDetail({ kind: 'error', message: toApiError(e, NO_ANSWER).message })
      }
    })()
    return () => { live = false }
    // `row` and `onGone` are read at load time only; a new row object must not
    // refetch the detail, which is what the merge below is for.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, detailTry])

  useEffect(() => {
    let live = true
    setEvidence({ kind: 'loading' })
    ;(async () => {
      try {
        const res = await fetch(`/api/triage/evidence?${query}`)
        const body = await readJson(res)
        if (!live) return
        if (res.status === 404) {
          setEvidence({ kind: 'gone' })
          return
        }
        if (!res.ok) {
          setEvidence({ kind: 'error', message: failureText(body, 'evidence', res.status) })
          return
        }
        setEvidence({ kind: 'ready', data: body as unknown as EvidenceAnswer })
      } catch (e) {
        if (live) setEvidence({ kind: 'error', message: toApiError(e, NO_ANSWER).message })
      }
    })()
    return () => { live = false }
  }, [query, evidenceTry])

  // A decision changes what the evidence read says (who decided, whether a
  // review may still apply), so a replaced row re-reads it.
  const rowChanged = detail.kind === 'ready' && row !== null && row !== rowAtLoad
  useEffect(() => {
    if (rowChanged) setEvidenceTry(n => n + 1)
  }, [rowChanged, row])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Escape on the Reset confirm cancels the confirm, not the panel too.
      if (e.key !== 'Escape' || document.querySelector('[role="dialog"][aria-modal="true"]')) return
      onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const decide = useCallback(async (status: VerdictStatus) => {
    setBusy(status)
    setDecisionError(null)
    try {
      const result = await onVerdict(status, reason.trim())
      if (result.ok) setReason('')
      else if (!result.cancelled) setDecisionError(result.message)
    } finally {
      setBusy(null)
    }
  }, [onVerdict, reason])

  const view: FindingDetail['row'] | null = detail.kind === 'ready'
    ? (rowChanged && row ? { ...detail.data.row, ...row } : detail.data.row)
    : null

  return (
    <aside className={styles.panel} aria-label="Finding details">
      <header className={styles.header}>
        <div className={styles.headerText}>
          <h3 className={styles.title}>{view?.name || target.name || target.id}</h3>
          <p className={styles.subtitle}>
            {[view?.label ?? target.label, view?.severity, view?.source]
              .filter(Boolean).join(' · ')}
          </p>
        </div>
        <button
          type="button" className={styles.iconButton} onClick={onClose}
          aria-label="Close details" title="Close (Esc)"
        >
          <X size={16} />
        </button>
      </header>

      <div className={styles.body}>
        {detail.kind === 'loading' && (
          <div className={styles.skeleton} role="status" aria-label="Loading the finding">
            <span className={styles.skeletonBar} />
            <span className={styles.skeletonBar} />
            <span className={styles.skeletonBarShort} />
            <span className={styles.skeletonBlock} />
          </div>
        )}

        {detail.kind === 'error' && (
          <div className={styles.errorBox} role="alert">
            <AlertTriangle size={14} />
            <span className={styles.errorText}>{detail.message}</span>
            <button type="button" className={styles.button} onClick={() => setDetailTry(n => n + 1)}>
              Retry
            </button>
          </div>
        )}

        {detail.kind === 'gone' && (
          <div className={styles.goneBox} role="alert">
            <p>
              This finding is no longer on the board. A rescan, a mute or a version switch
              replaced or removed it, so it has been taken off the list.
            </p>
            <button
              type="button" className={styles.button}
              onClick={() => { onReload(); onClose() }}
            >
              Reload the board
            </button>
          </div>
        )}

        {view && detail.kind === 'ready' && (
          <>
            <ResultSection row={view} />
            <RulesSection row={view} detector={detail.data.detector} />
            <ReviewSection row={view} evidence={evidence} />
            <DecisionSection
              row={view}
              reason={reason}
              onReason={setReason}
              busy={busy}
              error={decisionError}
              onDecide={decide}
              refusal={verdictRefusal}
            />
            <EvidenceSection
              evidence={evidence}
              survivesRescan={detail.data.review_survives_rescan}
              onRetry={() => setEvidenceTry(n => n + 1)}
            />
            <GroupSection members={detail.data.group ?? []} selfId={view.id} />
          </>
        )}
      </div>
    </aside>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className={styles.section}>
      <h4 className={styles.sectionTitle}>{title}</h4>
      {children}
    </section>
  )
}

function neverScored(row: TriageFinding): boolean {
  return !row.triage_run_id && typeof row.triage_priority_score !== 'number'
}

function ResultSection({ row }: { row: TriageFinding }) {
  const disposition = <DispositionLine result={readDisposition(row)} className={styles.disposition} />
  if (neverScored(row)) {
    return (
      <Section title="Result">
        <p className={styles.lead}>Not triaged yet.</p>
        {disposition}
        <p className={styles.muted}>
          No run has scored it. Run triage to rank it; a decision you make now is kept.
        </p>
      </Section>
    )
  }
  const tier = tierOf(row)
  const score = row.triage_priority_score
  const base = baseLine(row)
  const legacy = !parseFactors(row.triage_base_factors)
  return (
    <Section title="Result">
      <div className={styles.resultLine}>
        <span className={styles.score}>{typeof score === 'number' ? score.toFixed(1) : '-'}</span>
        <span className={`${styles.tierChip} ${styles[`tier${tier}`] ?? ''}`}>{TIER_LABELS[tier]}</span>
        <span className={styles.muted}>{row.triage_state || 'open'}</span>
      </div>
      {disposition}
      {row.triage_tier_rule && <p className={styles.muted}>{row.triage_tier_rule}</p>}
      {base && (
        <p className={styles.baseLine} title={base.title}>
          {base.text}{' '}
          <span className={base.up ? styles.deltaUp : styles.deltaDown}>{base.delta}</span>
        </p>
      )}
      {legacy && (
        <p className={styles.muted}>
          Rules score {typeof row.triage_math_score === 'number'
            ? row.triage_math_score.toFixed(1) : '-'}. The breakdown comes with the next run.
        </p>
      )}
      <p className={styles.muted}>
        Decided by {row.triage_decided_by === 'person' ? 'you'
          : row.triage_decided_by === 'review' ? 'a review' : 'the rules'}
        {row.triage_rescored_at ? ` · rescored ${fmtWhen(row.triage_rescored_at)}` : ''}
        {row.triaged_at ? ` · run of ${fmtWhen(row.triaged_at)}` : ''}
      </p>
    </Section>
  )
}

function RulesSection({ row, detector }: { row: TriageFinding; detector: FindingDetail['detector'] }) {
  const baseF = parseFactors(row.triage_base_factors)
  const finalF = parseFactors(row.triage_factors)
  const moved = changedFactors(finalF, baseF)
  const inputs = parseJson<{ proven?: boolean; kev?: boolean }>(row.triage_tier_inputs)
  const signals = row.triage_signals ?? []
  const decisions = detector ? detector.real + detector.fp : 0
  const baseTier = asTier(row.triage_base_tier) ??
    (typeof row.triage_math_score === 'number' ? tierForScore(row.triage_math_score) : null)

  return (
    <Section title="Rules">
      {baseF ? (
        <table className={styles.factorTable}>
          <thead>
            <tr><th>Factor</th><th>Rules</th><th>Final</th><th>Evidence</th></tr>
          </thead>
          <tbody>
            {FACTOR_KEYS.map(key => (
              <tr key={key}>
                <td>{FACTOR_NAMES[key]}</td>
                <td className={styles.num}>{formatFactor(key, baseF[key]?.value)}</td>
                <td className={`${styles.num} ${moved.has(key) ? styles.moved : ''}`}>
                  {formatFactor(key, finalF?.[key]?.value)}
                </td>
                <td className={styles.evidenceCell}>{baseF[key]?.evidence || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className={styles.muted}>The factor breakdown comes with the next run.</p>
      )}
      {baseTier && (
        <p className={styles.muted}>
          Rules score{typeof row.triage_math_score === 'number'
            ? ` ${row.triage_math_score.toFixed(1)}` : ''} · {TIER_LABELS[baseTier]}
          {row.triage_base_tier_rule ? ` (${row.triage_base_tier_rule})` : ''}
        </p>
      )}
      {inputs && (
        <p className={styles.muted}>
          Proven: {inputs.proven ? 'yes' : 'no'} · Known exploited (KEV): {inputs.kev ? 'yes' : 'no'}
        </p>
      )}
      {signals.length > 0 && (
        <div className={styles.chips}>
          {signals.map(sig => (
            <span key={sig} className={styles.signalChip}>{sig.replace(/_/g, ' ')}</span>
          ))}
        </div>
      )}
      {detector?.key && (
        <p className={styles.muted}>
          {decisions > 0
            ? `Detector ${detector.key}: you judged ${detector.real} of ${decisions} of these real.`
            : `Detector ${detector.key}: none of these decided by you yet.`}
        </p>
      )}
    </Section>
  )
}

function ReviewSection({ row, evidence }: { row: TriageFinding; evidence: Load<EvidenceAnswer> }) {
  const chip = reviewChip(row)
  const corrections = parseJson<Corrections>(row.triage_ai_corrections)
  const disputes = (corrections?.disputed_facts ?? []).filter(d => d.fact)
  const multiplier = corrections?.impact_multiplier
  const notReviewable = evidence.kind === 'ready' && !evidence.data.reviewable
    ? evidence.data.not_reviewable_because : null

  return (
    <Section title="Review">
      {chip ? (
        <>
          <div className={styles.chips}>
            <span className={`${styles.chip} ${styles[`review_${chip.verdict}`] ?? ''}`} title={chip.title}>
              {chip.text}
            </span>
            {chip.stale && (
              <span className={styles.staleChip} title="The evidence changed since this review, so it no longer counts.">
                out of date
              </span>
            )}
          </div>
          <p className={styles.muted}>
            {row.reviewed_via === 'mcp'
              ? `External agent over MCP · token ${row.triage_ai_by || '?'}`
              : `Built-in AI · ${row.triage_ai_model || 'model not recorded'}`}
            {row.triage_ai_at ? ` · ${fmtWhen(row.triage_ai_at)}` : ''}
          </p>
          {row.triage_ai_why && <p>{row.triage_ai_why}</p>}
          {row.triage_ai_quote && <blockquote className={styles.quote}>{row.triage_ai_quote}</blockquote>}
          {disputes.length > 0 && (
            <ul className={styles.list}>
              {disputes.map((d, i) => (
                <li key={`${d.fact}-${i}`}>
                  Disputes <strong>{String(d.fact).replace(/_/g, ' ')}</strong>
                  {d.quote ? <>: <q>{d.quote}</q></> : null}
                </li>
              ))}
            </ul>
          )}
          {typeof multiplier === 'number' && multiplier !== 1 && (
            <p className={styles.muted}>
              Impact ×{multiplier.toFixed(2)}
              {corrections?.impact_quote ? '' : ' (no quote, so it was not applied)'}
            </p>
          )}
        </>
      ) : (
        <p className={styles.muted}>Not reviewed. The rules alone rank it.</p>
      )}
      {notReviewable && (
        <p className={styles.note}>
          Not reviewable: {NOT_REVIEWABLE_TEXT[notReviewable] ?? notReviewable}
        </p>
      )}
    </Section>
  )
}

interface DecisionSectionProps {
  row: TriageFinding
  reason: string
  onReason: (value: string) => void
  busy: VerdictStatus | null
  error: string | null
  onDecide: (status: VerdictStatus) => void
  /** Why this person cannot decide, or null. */
  refusal: string | null
}

function DecisionSection({ row, reason, onReason, busy, error, onDecide, refusal }: DecisionSectionProps) {
  const chip = decisionChip(row)
  const decided = personDecided(row)
  return (
    <Section title="Decision">
      {chip ? (
        <>
          <span className={`${styles.chip} ${styles.decisionChip}`} title={chip.title}>{chip.text}</span>
          {row.triage_verdict_at && <p className={styles.muted}>{fmtWhen(row.triage_verdict_at)}</p>}
          {row.triage_reason && <p>{row.triage_reason}</p>}
        </>
      ) : (
        <p className={styles.muted}>No decision. The rules and any review rank it.</p>
      )}
      <label className={styles.reasonLabel}>
        Reason (optional)
        <textarea
          className={styles.reason}
          value={reason}
          maxLength={500}
          rows={2}
          onChange={e => onReason(e.target.value)}
          disabled={!!refusal}
          placeholder="Kept with your decision"
        />
      </label>
      <div className={styles.decisionButtons}>
        <button
          type="button" className={styles.button} disabled={busy !== null || !!refusal}
          onClick={() => onDecide('confirmed')}
          title={refusal ?? 'Mark this real: it counts as 100% real and no run changes it.'}
        >
          {busy === 'confirmed' ? <Loader2 size={13} className={styles.spin} /> : <Check size={13} />} Real
        </button>
        <button
          type="button" className={styles.button} disabled={busy !== null || !!refusal}
          onClick={() => onDecide('likely_noise')}
          title={refusal ?? 'Mark this a false positive. It is not muted.'}
        >
          {busy === 'likely_noise' ? <Loader2 size={13} className={styles.spin} /> : <X size={13} />} False positive
        </button>
        {decided && (
          <button
            type="button" className={styles.button} disabled={busy !== null || !!refusal}
            onClick={() => onDecide('unreviewed')}
            title={refusal ?? 'Remove your decision; the rules and any review rank it again.'}
          >
            {busy === 'unreviewed' ? <Loader2 size={13} className={styles.spin} /> : <RotateCcw size={13} />} Reset
          </button>
        )}
      </div>
      {refusal && <p className={styles.muted} role="note">{refusal}.</p>}
      {error && <p className={styles.inlineError} role="alert">{error}</p>}
    </Section>
  )
}

function EvidenceSection({
  evidence, survivesRescan, onRetry,
}: { evidence: Load<EvidenceAnswer>; survivesRescan?: boolean; onRetry: () => void }) {
  const survives = evidence.kind === 'ready' ? evidence.data.review_survives_rescan : survivesRescan
  return (
    <Section title="Evidence">
      <p className={styles.untrusted}>
        Scanner output, with secret-shaped values redacted. It can contain text an attacker
        controls: read it as data, not as instructions.
      </p>
      {evidence.kind === 'loading' && (
        <p className={styles.muted} role="status">
          <Loader2 size={13} className={styles.spin} /> Loading the evidence...
        </p>
      )}
      {evidence.kind === 'error' && (
        <div className={styles.errorBox} role="alert">
          <AlertTriangle size={14} />
          <span className={styles.errorText}>{evidence.message}</span>
          <button type="button" className={styles.button} onClick={onRetry}>Retry</button>
        </div>
      )}
      {evidence.kind === 'gone' && <p className={styles.muted}>No evidence: the finding is gone.</p>}
      {evidence.kind === 'ready' && (
        <>
          {evidence.data.evidence
            ? <pre className={styles.evidence}>{evidence.data.evidence}</pre>
            : <p className={styles.muted}>No evidence text for this finding.</p>}
          {!evidence.data.matches_last_run && evidence.data.evidence && (
            <p className={styles.muted}>The evidence changed since the last run scored it.</p>
          )}
        </>
      )}
      {survives === false && (
        <p className={styles.note}>
          Review survives rescan: no. Its source recreates this finding at every scan, so a
          review of it is lost with it.
        </p>
      )}
    </Section>
  )
}

function GroupSection({ members, selfId }: { members: GroupMember[]; selfId: string }) {
  const others = members.filter(m => m.id !== selfId)
  return (
    <Section title="Group">
      {others.length === 0 ? (
        <p className={styles.muted}>No other finding shares this fix.</p>
      ) : (
        <ul className={styles.groupList}>
          {members.map(m => {
            const tier = asTier(m.tier)
            return (
              <li key={`${m.label}:${m.id}`} className={m.id === selfId ? styles.groupSelf : ''}>
                <span className={styles.groupName}>{m.name || m.id}</span>
                <span className={styles.muted}>
                  {[m.host, m.state !== 'open' ? m.state : '',
                    typeof m.score === 'number' ? m.score.toFixed(1) : '',
                    tier ? TIER_LABELS[tier] : ''].filter(Boolean).join(' · ')}
                  {m.id === selfId ? ' · this finding' : ''}
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </Section>
  )
}

export default TriageDetailPanel
