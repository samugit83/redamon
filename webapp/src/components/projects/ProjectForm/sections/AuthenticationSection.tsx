'use client'

import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, KeyRound, Play, Save } from 'lucide-react'
import { useAlertModal, WikiInfoButton, Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { AUTH_TYPES, type AuthProfileMetadata } from '@/lib/authProfile'
import { RecordingModal } from '@/components/traffic/RecordingModal'

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
  const [loading, setLoading] = useState(false)
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

  const load = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    try {
      const res = await fetch(`/api/projects/${projectId}/auth-profile`)
      if (!res.ok) return
      const { authProfile } = await res.json()
      setMeta(authProfile)
      setAuthType(authProfile?.authType ?? 'none')
      setAuthHeaderName(authProfile?.authHeaderName ?? '')
      setScopeHosts((authProfile?.scopeHosts ?? []).join(', '))
      setReconEnabled(authProfile?.reconEnabled !== false)
      setAgentEnabled(authProfile?.agentEnabled !== false)
      setAuthValue('')
      setDirty(false)
    } catch {
      /* leave the section in its empty state */
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
      const json = await res.json()
      if (!res.ok) { alertError(json.error || 'Failed to save the auth profile'); return }
      setMeta(json.authProfile)
      setAuthValue('')
      setDirty(false)
    } catch {
      alertError('Failed to save the auth profile')
    } finally {
      setSaving(false)
    }
  }

  const clearValue = async () => {
    if (!projectId) return
    const res = await fetch(`/api/projects/${projectId}/auth-profile`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clearValue: true, authType: 'none' }),
    })
    if (res.ok) { setMeta((await res.json()).authProfile); setAuthType('none'); setAuthValue(''); setDirty(false) }
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
      if (!res.ok) { setter(!v); alertError('Failed to update the toggle'); return }
      setMeta((await res.json()).authProfile)
    } catch {
      setter(!v)
      alertError('Failed to update the toggle')
    }
  }

  const valuePlaceholder = meta?.hasValue
    ? '•••••••••• (a value is set — type to replace it)'
    : authType === 'basic' ? 'username:password'
    : authType === 'cookie' ? 'session=…; other=…'
    : 'the token / header value'

  return (
    <div className={styles.section}>
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
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Apply this identity to</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Recon pipeline</div>
                    <div className={styles.toggleDescription}>
                      Crawlers, fuzzers and probes attach the session to in-scope hosts.
                    </div>
                  </div>
                  <Toggle checked={reconEnabled} onChange={(v) => setGate('reconEnabled', v)} aria-label="Apply to recon" />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>AI agent</div>
                    <div className={styles.toggleDescription}>
                      Replay, browser and curl send logged-in for in-scope hosts. Turn off to
                      keep agent probing anonymous (e.g. for access-control testing).
                    </div>
                  </div>
                  <Toggle checked={agentEnabled} onChange={(v) => setGate('agentEnabled', v)} aria-label="Apply to agent" />
                </div>
              </div>

              <div className={styles.subSection}>
                <button
                  type="button"
                  onClick={() => setRecordingOpen(true)}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 12px',
                    borderRadius: 6, border: '1px solid rgba(224,175,104,0.4)',
                    background: 'rgba(224,175,104,0.12)', color: '#e0af68', cursor: 'pointer',
                    fontSize: 12, fontWeight: 500,
                  }}
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
                        style={{ marginTop: 6, fontSize: 11, color: '#f7768e', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
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
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 6,
                    border: '1px solid rgba(122,162,247,0.4)', background: dirty ? 'rgba(122,162,247,0.15)' : 'transparent',
                    color: '#7aa2f7', cursor: dirty && !saving ? 'pointer' : 'not-allowed', fontSize: 12, fontWeight: 500,
                    opacity: dirty ? 1 : 0.5,
                  }}>
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
