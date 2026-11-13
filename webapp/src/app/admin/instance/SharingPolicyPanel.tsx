'use client'

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useToast } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import type { SharingPolicy } from '@/lib/authz/sharingPolicy'
import type { InstanceSettingsView } from './instanceView'
import { putInstanceSettings } from './instanceSettingsClient'
import { CheckField, FieldRow, Panel, RootOnlyNote } from './Panel'
import styles from './instance.module.css'

/**
 * Root's instance sharing policy (step 4.2, SH-21 UI). The instance settings carry it only to
 * administrators and only with RBAC_SHARING_ENABLED on, so with the switch off this panel is never
 * shown (the page asks `sharingPolicyOf` first). The confirmed Root changes it with its password;
 * the Save sends only the settings that changed, as `sharingPolicy: {...}`.
 *
 * The bound is lib/authz/sharingPolicy.ts DEFAULT_EXPIRY_DAYS_BOUNDS; that module reads the
 * database, so only its types come here (instanceView.test.ts pins the copy).
 */
export const EXPIRY_DAYS_BOUNDS = [1, 3650] as const

const BOOLEANS = ['enabled', 'membersMayGrantExploit', 'adminsSeeAllShares'] as const

/** The policy the settings carry, or null when they carry none (switch off, or not an administrator). */
export function sharingPolicyOf(settings: InstanceSettingsView | null): SharingPolicy | null {
  const raw = settings?.sharingPolicy
  if (!raw || typeof raw !== 'object') return null
  const p = raw as Partial<SharingPolicy>
  return {
    enabled: p.enabled === true,
    maxLevel: p.maxLevel === 'read' ? 'read' : 'write',
    membersMayGrantExploit: p.membersMayGrantExploit === true,
    defaultExpiryDays: typeof p.defaultExpiryDays === 'number' ? p.defaultExpiryDays : null,
    adminsSeeAllShares: p.adminsSeeAllShares === true,
  }
}

interface Draft {
  enabled: boolean
  maxLevel: 'read' | 'write'
  membersMayGrantExploit: boolean
  defaultExpiryDays: string
  adminsSeeAllShares: boolean
}

const draftOf = (p: SharingPolicy): Draft => ({ ...p, defaultExpiryDays: p.defaultExpiryDays === null ? '' : String(p.defaultExpiryDays) })

function expiryProblem(text: string): string | null {
  const v = text.trim()
  if (!v) return null
  const [min, max] = EXPIRY_DAYS_BOUNDS
  const n = Number(v)
  return /^\d+$/.test(v) && n >= min && n <= max ? null : `Empty, or a whole number of days from ${min} to ${max}.`
}

/** The settings that differ from the policy in force, typed as the route takes them. */
export function sharingPatch(current: SharingPolicy, draft: Draft): Partial<SharingPolicy> {
  const patch: Partial<SharingPolicy> = {}
  for (const k of BOOLEANS) if (draft[k] !== current[k]) patch[k] = draft[k]
  if (draft.maxLevel !== current.maxLevel) patch.maxLevel = draft.maxLevel
  const days = draft.defaultExpiryDays.trim() === '' ? null : Number(draft.defaultExpiryDays.trim())
  if (days !== current.defaultExpiryDays) patch.defaultExpiryDays = days
  return patch
}

const LABELS: Record<(typeof BOOLEANS)[number], { label: string; hint: string }> = {
  enabled: { label: 'Sharing is on', hint: 'Off: no project can be shared, and existing shares give no access until sharing is on again.' },
  membersMayGrantExploit: { label: 'Members may grant Exploitation & shells', hint: 'Off: only administrators grant it.' },
  adminsSeeAllShares: { label: 'Administrators see every share', hint: 'Lists every share in the console for administrators holding users:read.' },
}

const SAVE_FAILED = 'The sharing policy was not saved'

export function SharingPolicyPanel({ settings, unconfirmedRoot, onSaved }: {
  settings: InstanceSettingsView
  unconfirmedRoot: boolean
  onSaved: (settings: InstanceSettingsView) => void
}) {
  const toast = useToast()
  const policy = useMemo(() => sharingPolicyOf(settings), [settings])
  const canEdit = settings.canManageSharingPolicy === true
  const saved = useMemo(() => (policy ? draftOf(policy) : null), [policy])
  const [draft, setDraft] = useState<Draft | null>(saved)
  const [confirming, setConfirming] = useState(false)
  useEffect(() => setDraft(saved), [saved])
  if (!policy || !draft || !saved) return null

  const lead = 'Whether accounts share projects with each other, up to which level, and what administrators see.'
  if (!canEdit) {
    return (
      <Panel id="sharing" title="Sharing policy" lead={lead}>
        <dl className={styles.readList}>
          {BOOLEANS.map((k) => (
            <div key={k} style={{ display: 'contents' }}><dt>{LABELS[k].label}</dt><dd>{policy[k] ? 'Yes' : 'No'}</dd></div>
          ))}
          <dt>Highest level a share may have</dt><dd>{policy.maxLevel === 'read' ? 'Read' : 'Write'}</dd>
          <dt>Default share expiry</dt><dd>{policy.defaultExpiryDays === null ? 'None' : `${policy.defaultExpiryDays} days`}</dd>
        </dl>
        <RootOnlyNote unconfirmedRoot={unconfirmedRoot} />
      </Panel>
    )
  }

  const problem = expiryProblem(draft.defaultExpiryDays)
  const patch = sharingPatch(policy, draft)
  const dirty = Object.keys(patch).length > 0
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (dirty && !problem) setConfirming(true)
  }

  return (
    <Panel id="sharing" title="Sharing policy" lead={lead}>
      <form onSubmit={submit} noValidate className={styles.page} style={{ gap: 'var(--space-3)' }}>
        {BOOLEANS.map((k) => (
          <CheckField
            key={k}
            id={`sharing-${k}`}
            label={LABELS[k].label}
            hint={LABELS[k].hint}
            checked={draft[k]}
            onChange={(checked) => setDraft((d) => (d ? { ...d, [k]: checked } : d))}
          />
        ))}
        <div className={styles.fields}>
          <FieldRow id="sharing-maxLevel" label="Highest level a share may have" hint="The highest level a member may grant.">
            <select
              id="sharing-maxLevel"
              className="select"
              value={draft.maxLevel}
              aria-describedby="sharing-maxLevel-hint"
              onChange={(e) => setDraft((d) => (d ? { ...d, maxLevel: e.target.value === 'read' ? 'read' : 'write' } : d))}
            >
              <option value="read">Read</option>
              <option value="write">Write</option>
            </select>
          </FieldRow>
          <FieldRow
            id="sharing-defaultExpiryDays"
            label="Default share expiry (days)"
            hint="The expiry a new share gets when the person sharing sets none. Empty: none."
            error={problem}
          >
            <input
              id="sharing-defaultExpiryDays"
              className="textInput"
              inputMode="numeric"
              value={draft.defaultExpiryDays}
              placeholder="None"
              aria-invalid={problem ? true : undefined}
              aria-describedby="sharing-defaultExpiryDays-hint"
              onChange={(e) => setDraft((d) => (d ? { ...d, defaultExpiryDays: e.target.value } : d))}
            />
          </FieldRow>
        </div>
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={!dirty || !!problem}>Save the sharing policy</button>
          {dirty && <button type="button" className="secondaryButton" onClick={() => setDraft(saved)}>Revert</button>}
          <span className={styles.hint}>Saving asks for your password.</span>
        </div>
      </form>
      <StepUpModal
        isOpen={confirming}
        title="Change the sharing policy"
        message="This changes who may share projects on the whole instance. Enter your password to confirm."
        confirmLabel="Save the sharing policy"
        onConfirm={async (password) => {
          const answer = await putInstanceSettings({ sharingPolicy: patch, stepUpPassword: password }, SAVE_FAILED)
          onSaved(answer)
          toast.success('Sharing policy saved')
        }}
        onClose={() => setConfirming(false)}
      />
    </Panel>
  )
}
