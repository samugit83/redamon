'use client'

import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, KeyRound, Play, Save } from 'lucide-react'
import { useAlertModal, WikiInfoButton, Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { AUTH_TYPES, type AuthProfileMetadata } from '@/lib/authProfile'
import { RecordingModal } from '@/components/traffic/RecordingModal'
import { readApiError, toApiError } from '@/lib/apiError'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AuthenticationSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode?: 'create' | 'edit'
}

const NEEDS_NAME = new Set(['header', 'apikey'])

export function AuthenticationSection({ projectId, mode }: AuthenticationSectionProps) {
  const { alertError, alert } = useAlertModal()
  const [isOpen, setIsOpen] = useState(false)
  const [meta, setMeta] = useState<AuthProfileMetadata | null>(null)
  // Starts true so the switches are never clickable before the first load answers:
  // a gate flipped meanwhile was saved, then overwritten on screen by the load's
  // older value, so the switch showed the opposite of what the server holds.
  const [loading, setLoading] = useState(Boolean(projectId))
  const [saving, setSaving] = useState(false)
  const [recordingOpen, setRecordingOpen] = useState(false)

  // Local edit state. authValue is write-only: it starts empty (we never receive
  // the stored bytes) and is only sent when the operator types a new value.
  const [authType, setAuthType] = useState('none')
  const [authHeaderName, setAuthHeaderName] = useState('')
  const [authValue, setAuthValue] = useState('')
  const [scopeHosts, setScopeHosts] = useState('')
  const [reconEnabled, setReconEnabled] = useState(true)
  const [agentEnabled, setAgentEnabled] = useState(true)
  const [dirty, setDirty] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setLoadError(null)
    try {
      const res = await fetch(`/api/projects/${projectId}/auth-profile`)
      if (!res.ok) throw await readApiError(res, 'Could not load the auth profile')
      const { authProfile } = await res.json()
      setMeta(authProfile)
      setAuthType(authProfile?.authType ?? 'none')
      setAuthHeaderName(authProfile?.authHeaderName ?? '')
      setScopeHosts((authProfile?.scopeHosts ?? []).join(', '))
      setReconEnabled(authProfile?.reconEnabled !== false)
      setAgentEnabled(authProfile?.agentEnabled !== false)
      setAuthValue('')
      setDirty(false)
    } catch (err) {
      // The empty state below would otherwise read as "no profile set".
      setLoadError(toApiError(err, 'Could not load the auth profile').message)
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => { void load() }, [load])

  const markDirty = () => setDirty(true)

  const save = async () => {
    if (!projectId) return
    setSaving(true)
    try {
      const body: Record<string, unknown> = {
        authType,
        authHeaderName: NEEDS_NAME.has(authType) ? authHeaderName : '',
        scopeHosts,
      }
      // Only send the value when the operator actually typed one (write-only).
      if (authValue) body.authValue = authValue
      const res = await fetch(`/api/projects/${projectId}/auth-profile`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      if (!res.ok) { alertError((await readApiError(res, 'Failed to save the auth profile')).message); return }
      const json = await res.json()
      setMeta(json.authProfile)
      setAuthValue('')
      setDirty(false)
    } catch (err) {
      alertError(toApiError(err, 'Failed to save the auth profile').message)
    } finally {
      setSaving(false)
    }
  }

  const clearValue = async () => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}/auth-profile`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clearValue: true, authType: 'none' }),
      })
      if (!res.ok) { alertError((await readApiError(res, 'Failed to clear the stored value')).message); return }
      setMeta((await res.json()).authProfile); setAuthType('none'); setAuthValue(''); setDirty(false)
    } catch (err) {
      alertError(toApiError(err, 'Failed to clear the stored value').message)
    }
  }

  // The consumer gates apply immediately (they are not secret and not part of the
  // write-only value flow), with optimistic UI + rollback on failure.
  const setGate = async (which: 'reconEnabled' | 'agentEnabled', v: boolean) => {
    if (!projectId) return
    const setter = which === 'reconEnabled' ? setReconEnabled : setAgentEnabled
    setter(v)
    try {
      const res = await fetch(`/api/projects/${projectId}/auth-profile`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [which]: v }),
      })
      if (!res.ok) { setter(!v); alertError((await readApiError(res, 'Failed to update the toggle')).message); return }
      setMeta((await res.json()).authProfile)
    } catch (err) {
      setter(!v)
      alertError(toApiError(err, 'Failed to update the toggle').message)
    }
  }

  const valuePlaceholder = meta?.hasValue
    ? '•••••••••• (a value is set — type to replace it)'
    : authType === 'basic' ? 'username:password'
    : authType === 'cookie' ? 'session=…; other=…'
    : 'the token / header value'

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <KeyRound size={16} />
          Authenticated Session
          <WikiInfoButton target="Authenticated-Session-Recording" />
          {meta?.hasValue && <span className={styles.badgeActive}>{meta.source === 'recorded' ? 'Recorded' : 'Set'}</span>}
        </h2>
        <div className={styles.sectionHeaderRight}>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            One login identity every recon tool and the agent attach to in-scope
            requests, so the post-login surface is crawled and tested. The value is
            <strong> write-only</strong>: it is stored for scanners and the agent but
            never shown back here. Record it automatically by driving your own browser
            through the capture proxy, or enter it by hand.
          </p>

          {mode === 'create' || !projectId ? (
            <p className={styles.fieldHint}>Save the project first, then configure its authenticated session.</p>
          ) : (
            <>
              {loadError && <p className={styles.inlineError} role="alert">{loadError}</p>}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Apply this identity to</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Recon pipeline</div>
                    <div className={styles.toggleDescription}>
                      Crawlers, fuzzers and probes attach the session to in-scope hosts.
                    </div>
                  </div>
                  <Toggle checked={reconEnabled} onChange={(v) => setGate('reconEnabled', v)} disabled={loading} aria-label="Apply to recon" />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>AI agent</div>
                    <div className={styles.toggleDescription}>
                      Replay, browser and curl send logged-in for in-scope hosts. Turn off to
                      keep agent probing anonymous (e.g. for access-control testing).
                    </div>
                  </div>
                  <Toggle checked={agentEnabled} onChange={(v) => setGate('agentEnabled', v)} disabled={loading} aria-label="Apply to agent" />
                </div>
              </div>

              <div className={styles.subSection}>
                <button
                  type="button"
                  onClick={() => setRecordingOpen(true)}
                  className={`${styles.actionButton} ${styles.actionButtonWarning}`}
                >
                  <Play size={12} /> Record login through the proxy
                </button>
                {meta && (
                  <p className={styles.fieldHint}>
                    Current: <strong>{meta.hasValue ? meta.authType : 'none'}</strong>
                    {meta.hasValue && ` · source ${meta.source} · status ${meta.status}`}
                    {meta.extraHeaderNames.length > 0 && ` · extra: ${meta.extraHeaderNames.join(', ')}`}
                  </p>
                )}
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Manual entry</h3>

                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Type</label>
                  <select className="textInput" value={authType} disabled={loading}
                    onChange={(e) => { setAuthType(e.target.value); markDirty() }}>
                    {AUTH_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>

                {authType !== 'none' && (
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Value</label>
                    <input type="password" className="textInput" autoComplete="off"
                      value={authValue} placeholder={valuePlaceholder}
                      onChange={(e) => { setAuthValue(e.target.value); markDirty() }} />
                    {meta?.hasValue && (
                      <button type="button" onClick={clearValue}
                        className={`${styles.textButton} ${styles.textButtonDanger}`} style={{ marginTop: 6 }}>
                        Clear the stored value
                      </button>
                    )}
                  </div>
                )}

                {NEEDS_NAME.has(authType) && (
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Header name</label>
                    <input type="text" className="textInput" value={authHeaderName}
                      placeholder={authType === 'apikey' ? 'X-API-Key' : 'X-Auth-Token'}
                      onChange={(e) => { setAuthHeaderName(e.target.value); markDirty() }} />
                  </div>
                )}

                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Scope hosts</label>
                  <input type="text" className="textInput" value={scopeHosts}
                    placeholder="blank = the project's target hosts"
                    onChange={(e) => { setScopeHosts(e.target.value); markDirty() }} />
                  <p className={styles.fieldHint}>
                    {/* Plain text, not <code>: global.css pins code to --text-sm,
                        which is larger than the hint and made "*.suffix" tower
                        over the sentence around it. */}
                    Comma-separated. Auth is attached ONLY to these hosts (exact, *.suffix or CIDR),
                    never cross-origin. Leave blank to default to the project&apos;s own target hosts.
                  </p>
                </div>

                <button type="button" onClick={save} disabled={!dirty || saving}
                  className={styles.actionButton}>
                  <Save size={12} /> {saving ? 'Saving…' : 'Save'}
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* Recording happens in place: on save, reload so the recorded profile
          shows here immediately (no page refresh). Same modal as /traffic. */}
      {projectId && (
        <RecordingModal
          isOpen={recordingOpen}
          onClose={() => setRecordingOpen(false)}
          projectId={projectId}
          onSaved={() => { void load() }}
        />
      )}
    </div>
  )
}
