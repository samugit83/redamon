'use client'

import { useId, useState } from 'react'
import Link from 'next/link'
import { Eye, EyeOff, ExternalLink } from 'lucide-react'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { credentialField, isSecretField } from '@/lib/credentialFields'
import { useOptionalAlertModal } from '@/components/ui/AlertModal'
import { StepUpModal } from '@/components/auth/StepUpModal'
import type { CredentialKeysApi, SecretReentryPrompt } from '@/hooks/useCredentialKeys'
import styles from './CredentialShortcut.module.css'

/** The secrets a re-pointed endpoint needs again, typed in the confirm dialog. */
function ReentryFields({ prompt, onChange }: { prompt: SecretReentryPrompt; onChange: (field: string, value: string) => void }) {
  const baseId = useId()
  return (
    <div className={styles.reentry}>
      <p>{prompt.message}</p>
      {prompt.fields.map((f, i) => (
        <div key={f} className={styles.reentryField}>
          <label htmlFor={`${baseId}-${i}`}>{credentialField(f)?.label ?? f}</label>
          <input
            id={`${baseId}-${i}`}
            className="textInput"
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            onChange={e => onChange(f, e.target.value)}
          />
        </div>
      ))}
      <p className={styles.hint}>Leave it empty to clear the stored value: nothing stored is sent to the new address.</p>
    </div>
  )
}

interface CredentialShortcutProps {
  /** The UserSettings column, e.g. 'trufflehogGithubToken'. */
  settingsKey: string
  /** Shared reader/writer, so one page does not fetch settings once per field. */
  keys: CredentialKeysApi
  /** Mandatory keys block a scan; optional ones only widen its reach. */
  optional?: boolean
  /** Drops the hint text, for dense surfaces like the Other Scans rows. */
  compact?: boolean
}

/**
 * An inline editor for a single Global Settings credential.
 *
 * The scan sections used to link out to /settings, which meant leaving a
 * half-filled project form to go and set a token. This writes the same
 * user-level setting in place.
 *
 * It can say whether a key is set and never what it is: the API masks secrets on
 * read, so the box always starts empty and a save REPLACES rather than edits.
 * The reveal toggle therefore only shows what the user is currently typing,
 * which is what it is for - checking a pasted token.
 */
export function CredentialShortcut({
  settingsKey,
  keys,
  optional = false,
  compact = false,
}: CredentialShortcutProps) {
  const field = credentialField(settingsKey)
  const inputId = useId()
  const alerts = useOptionalAlertModal()
  const [draft, setDraft] = useState('')
  const [visible, setVisible] = useState(false)
  const [justSaved, setJustSaved] = useState(false)
  // Re-pointing a configured endpoint takes the password (ID-25): the dialog answers the save.
  const [stepUpAsk, setStepUpAsk] = useState<{ resolve: (password: string | null) => void } | null>(null)

  // An unknown key would render an unlabelled box telling the user to set
  // something it cannot name. credentialFields.test.ts makes this unreachable.
  if (!field) return null

  const secret = isSecretField(settingsKey)
  const isSet = keys.isSet(settingsKey)
  const busy = keys.saving === settingsKey
  const blocking = !isSet && !optional

  // A new endpoint (the GitHub Enterprise host) whose stored secret the server will not
  // carry over (HD-24): ask for it, or to clear it, so both go in the same save.
  const askForSecrets = async (prompt: SecretReentryPrompt): Promise<Record<string, string> | null> => {
    if (!alerts) return null
    const typed: Record<string, string> = Object.fromEntries(prompt.fields.map(f => [f, '']))
    const confirmed = await alerts.confirm(
      <ReentryFields prompt={prompt} onChange={(f, v) => { typed[f] = v }} />,
      `Save the new ${field.label}`,
      { confirmLabel: 'Save' },
    )
    return confirmed ? Object.fromEntries(Object.entries(typed).map(([k, v]) => [k, v.trim()])) : null
  }

  const askForPassword = () => new Promise<string | null>(resolve => setStepUpAsk({ resolve }))

  const commit = async () => {
    const value = draft.trim()
    if (!value || busy) return
    const ok = await keys.save(settingsKey, value, { onSecretReentry: askForSecrets, onStepUp: askForPassword })
    if (ok) {
      setDraft('')
      setVisible(false)
      setJustSaved(true)
    }
  }

  return (
    <div className={`${styles.wrap} ${blocking ? styles.missing : ''}`}>
      <div className={styles.head}>
        <label htmlFor={inputId}>{field.label}</label>
        <span className={`${styles.badge} ${styles.badgeGlobal}`}>Global setting</span>
        {isSet ? (
          <span className={`${styles.badge} ${styles.badgeSet}`}>Set</span>
        ) : optional ? (
          <span className={`${styles.badge} ${styles.badgeOptional}`}>Optional</span>
        ) : (
          <span className={`${styles.badge} ${styles.badgeMissing}`}>Required</span>
        )}
      </div>

      <div className={styles.row}>
        <input
          id={inputId}
          className="textInput"
          type={secret && !visible ? 'password' : 'text'}
          value={draft}
          // The stored secret never reaches the browser, so the masked value can
          // only be shown as a placeholder - it is not editable text.
          placeholder={isSet ? keys.masked(settingsKey) || 'Stored' : `Paste your ${field.label}`}
          autoComplete={secret ? 'new-password' : 'off'}
          spellCheck={false}
          disabled={busy}
          onChange={e => { setDraft(e.target.value); setJustSaved(false) }}
          onKeyDown={e => {
            if (e.key === 'Enter') { e.preventDefault(); void commit() }
          }}
        />
        {secret && (
          <button
            type="button"
            className={styles.iconButton}
            onClick={() => setVisible(v => !v)}
            aria-label={visible ? 'Hide the value' : 'Show the value'}
          >
            {visible ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        )}
        <button
          type="button"
          className={styles.saveButton}
          disabled={!draft.trim() || busy}
          onClick={() => void commit()}
        >
          {busy ? 'Saving…' : isSet ? 'Replace' : 'Save'}
        </button>
      </div>

      {justSaved && <p className={styles.saved}>Saved to Global Settings.</p>}
      {keys.loadError && !isSet && (
        <p className={styles.error} role="alert">{keys.loadError}, so this key may already be set.</p>
      )}
      {keys.error && keys.saving === null && draft && (
        <p className={styles.error}>{keys.error}</p>
      )}

      {!compact && <p className={styles.hint}>{field.hint}</p>}

      {stepUpAsk && (
        <StepUpModal
          isOpen
          title={`Save the new ${field.label}`}
          message="What is stored for it, and the requests that use it, will go to a new address. Enter your password to save the change."
          confirmLabel="Save"
          onConfirm={async password => { stepUpAsk.resolve(password) }}
          onClose={() => { stepUpAsk.resolve(null); setStepUpAsk(null) }}
        />
      )}

      <div className={styles.links}>
        <Link href={SETTINGS_KEYS_HREF}>All keys in Global Settings</Link>
        {field.signupUrl && (
          <a href={field.signupUrl} target="_blank" rel="noopener noreferrer">
            Get a token <ExternalLink size={10} />
          </a>
        )}
      </div>
    </div>
  )
}
