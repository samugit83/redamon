'use client'

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useToast } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import {
  SECURITY_POLICY_GROUPS, baseUrlOf, policyDraftErrors, policyDraftOf, policyPatch,
  type InstanceSettingsView, type PolicyDraft,
} from './instanceView'
import { putInstanceSettings } from './instanceSettingsClient'
import { CheckField, FieldRow, Panel, RootOnlyNote } from './Panel'
import styles from './instance.module.css'

interface Props {
  settings: InstanceSettingsView
  unconfirmedRoot: boolean
  onSaved: (settings: InstanceSettingsView) => void
}

const SAVE_FAILED = 'The security policy was not saved'
const URL_SAVE_FAILED = 'The public address was not saved'

/**
 * The instance security policy (step 2.6's fields): every administrator reads it, the confirmed
 * Root changes it with its password. The Save sends only the fields that changed.
 */
export function SecurityPolicyPanel({ settings, unconfirmedRoot, onSaved }: Props) {
  const toast = useToast()
  const canEdit = settings.canManageSecurityPolicy === true
  const saved = useMemo(() => policyDraftOf(settings.securityPolicy), [settings.securityPolicy])
  const [draft, setDraft] = useState<PolicyDraft>(saved)
  const [confirming, setConfirming] = useState(false)
  useEffect(() => setDraft(saved), [saved])

  const errors = policyDraftErrors(draft)
  const patch = policyPatch(saved, draft)
  const dirty = Object.keys(patch).length > 0
  const invalid = Object.keys(errors).length > 0

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (dirty && !invalid) setConfirming(true)
  }

  const lead = 'Passwords, how long sessions and links last, and how administrators act as other accounts.'
  if (!canEdit) {
    return (
      <Panel id="security" title="Security policy" lead={lead}>
        {SECURITY_POLICY_GROUPS.map((g) => (
          <div key={g.title}>
            <h3 className={styles.groupTitle}>{g.title}</h3>
            <dl className={styles.readList}>
              {g.integers.map((f) => (
                <div key={f.field} style={{ display: 'contents' }}>
                  <dt>{f.label}</dt>
                  <dd>{saved[f.field] ? `${saved[f.field]} ${f.unit}` : 'Not set'}</dd>
                </div>
              ))}
              {g.booleans.map((f) => (
                <div key={f.field} style={{ display: 'contents' }}>
                  <dt>{f.label}</dt>
                  <dd>{saved[f.field] ? 'Yes' : 'No'}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}
        <RootOnlyNote unconfirmedRoot={unconfirmedRoot} />
      </Panel>
    )
  }

  return (
    <Panel id="security" title="Security policy" lead={lead}>
      <form onSubmit={submit} noValidate className={styles.page} style={{ gap: 'var(--space-3)' }}>
        {SECURITY_POLICY_GROUPS.map((g) => (
          <fieldset key={g.title} style={{ border: 'none', margin: 0, padding: 0 }}>
            <legend className={styles.groupTitle}>{g.title}</legend>
            <div className={styles.fields}>
              {g.integers.map((f) => {
                const id = `policy-${f.field}`
                return (
                  <FieldRow key={f.field} id={id} label={`${f.label} (${f.unit})`} hint={`${f.hint} ${f.min} to ${f.max}.`} error={errors[f.field]}>
                    <input
                      id={id}
                      className="textInput"
                      inputMode="numeric"
                      value={draft[f.field]}
                      aria-invalid={errors[f.field] ? true : undefined}
                      aria-describedby={`${id}-hint`}
                      onChange={(e) => setDraft((d) => ({ ...d, [f.field]: e.target.value }))}
                    />
                  </FieldRow>
                )
              })}
            </div>
            {g.booleans.map((f) => (
              <div key={f.field} style={{ marginTop: 'var(--space-2)' }}>
                <CheckField
                  id={`policy-${f.field}`}
                  label={f.label}
                  hint={f.hint}
                  checked={draft[f.field]}
                  onChange={(checked) => setDraft((d) => ({ ...d, [f.field]: checked }))}
                />
              </div>
            ))}
          </fieldset>
        ))}
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={!dirty || invalid}>Save the security policy</button>
          {dirty && <button type="button" className="secondaryButton" onClick={() => setDraft(saved)}>Revert</button>}
          <span className={styles.hint}>Saving asks for your password.</span>
        </div>
      </form>
      <StepUpModal
        isOpen={confirming}
        title="Change the security policy"
        message={`This changes ${Object.keys(patch).length} setting(s) for every account on the instance. Enter your password to confirm.`}
        confirmLabel="Save the security policy"
        onConfirm={async (password) => {
          const answer = await putInstanceSettings({ ...patch, stepUpPassword: password }, SAVE_FAILED)
          onSaved(answer)
          toast.success('Security policy saved')
        }}
        onClose={() => setConfirming(false)}
      />
    </Panel>
  )
}

/** A light check before the route's own (which also refuses credentials, a query or a fragment). */
function baseUrlProblem(text: string): string | null {
  const v = text.trim()
  if (!v) return null
  return /^https?:\/\/[^\s/]+/i.test(v) ? null : 'An http:// or https:// address, e.g. https://redamon.example.com'
}

/**
 * The public base URL invite and reset links are built on (step 2.9). Empty means the links use
 * the address the person's browser used. Root's, with its password.
 */
export function PublicUrlPanel({ settings, unconfirmedRoot, onSaved }: Props) {
  const toast = useToast()
  const canEdit = settings.canManageSecurityPolicy === true
  const saved = baseUrlOf(settings.securityPolicy)
  const [value, setValue] = useState(saved)
  const [confirming, setConfirming] = useState(false)
  useEffect(() => setValue(saved), [saved])

  const problem = baseUrlProblem(value)
  const dirty = value.trim() !== saved
  const lead = 'The address invite and reset links point to. Empty: the links use the address the browser used, which is wrong behind a proxy.'

  if (!canEdit) {
    return (
      <Panel id="public-url" title="Public address" lead={lead}>
        <dl className={styles.readList}>
          <dt>Public base URL</dt>
          <dd>{saved || 'Not set'}</dd>
        </dl>
        <RootOnlyNote unconfirmedRoot={unconfirmedRoot} />
      </Panel>
    )
  }

  return (
    <Panel id="public-url" title="Public address" lead={lead}>
      <form
        onSubmit={(e) => { e.preventDefault(); if (dirty && !problem) setConfirming(true) }}
        noValidate
        className={styles.page}
        style={{ gap: 'var(--space-2)' }}
      >
        <FieldRow id="policy-publicBaseUrl" label="Public base URL" hint="No query or fragment; leave it empty to clear it." error={problem}>
          <input
            id="policy-publicBaseUrl"
            className="textInput"
            type="url"
            value={value}
            placeholder="https://redamon.example.com"
            aria-invalid={problem ? true : undefined}
            aria-describedby="policy-publicBaseUrl-hint"
            onChange={(e) => setValue(e.target.value)}
          />
        </FieldRow>
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={!dirty || !!problem}>Save the public address</button>
          <span className={styles.hint}>Saving asks for your password.</span>
        </div>
      </form>
      <StepUpModal
        isOpen={confirming}
        title="Change the public address"
        message="New invite and reset links will point to this address. Enter your password to confirm."
        confirmLabel="Save the public address"
        onConfirm={async (password) => {
          const answer = await putInstanceSettings({ publicBaseUrl: value.trim() || null, stepUpPassword: password }, URL_SAVE_FAILED)
          onSaved(answer)
          toast.success('Public address saved')
        }}
        onClose={() => setConfirming(false)}
      />
    </Panel>
  )
}
