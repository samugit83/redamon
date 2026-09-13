'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Modal, useAlertModal } from '@/components/ui'

interface RecordingSummary {
  hasCookie: boolean
  hasBearer: boolean
  authType?: string
  extraHeaderNames: string[]
  hosts: string[]
}
interface RecordingSessionView {
  id: string
  state: string
  scopeHosts: string[]
  expiresAt: string
  observedCount: number
  lastError: string | null
}

const PROXY_ADDR = '127.0.0.1:8888'

export function RecordingModal({ isOpen, onClose, projectId, onSaved }: {
  isOpen: boolean
  onClose: () => void
  projectId: string
  onSaved?: () => void
}) {
  const { alertError } = useAlertModal()
  const [phase, setPhase] = useState<'idle' | 'starting' | 'recording' | 'stopped' | 'saving'>('idle')
  const [session, setSession] = useState<RecordingSessionView | null>(null)
  const [summary, setSummary] = useState<RecordingSummary | null>(null)
  const [blocked, setBlocked] = useState<string | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopPolling = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null } }

  const start = useCallback(async () => {
    setPhase('starting'); setBlocked(null); setSummary(null)
    try {
      const res = await fetch(`/api/projects/${projectId}/recording/start`, { method: 'POST' })
      const json = await res.json()
      if (!res.ok) { setBlocked(json.error || 'Could not start recording'); setPhase('idle'); return }
      setSession(json.session)
      setPhase('recording')
    } catch { setBlocked('Could not reach the server'); setPhase('idle') }
  }, [projectId])

  const stop = useCallback(async () => {
    stopPolling()
    try {
      const res = await fetch(`/api/projects/${projectId}/recording/stop`, { method: 'POST' })
      const json = await res.json()
      setSession(json.session)
      setSummary(json.summary)
      setPhase('stopped')
    } catch { alertError('Could not stop the recording') }
  }, [projectId, alertError])

  const commit = useCallback(async (save: boolean) => {
    setPhase('saving')
    try {
      const res = await fetch(`/api/projects/${projectId}/recording/commit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ save }),
      })
      const json = await res.json()
      if (!res.ok) { alertError(json.error || 'Could not save the recorded session'); setPhase('stopped'); return }
      onSaved?.()
      onClose()
    } catch { alertError('Could not save the recorded session'); setPhase('stopped') }
  }, [projectId, onClose, onSaved, alertError])

  // Poll the live counter while recording so "nothing captured yet" is visible (G4).
  useEffect(() => {
    if (phase !== 'recording') return
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/projects/${projectId}/recording/status`)
        if (!res.ok) return
        const json = await res.json()
        if (json.session) { setSession(json.session); setSummary(json.summary) }
      } catch { /* transient */ }
    }, 3000)
    return stopPolling
  }, [phase, projectId])

  useEffect(() => { if (!isOpen) { stopPolling(); setPhase('idle'); setSession(null); setSummary(null); setBlocked(null) } }, [isOpen])

  // Closing the modal must end the recording. Without this the session stays
  // active server-side until its 30-minute TTL: the proxy keeps tagging the
  // operator's browsing and every other project is refused the single global
  // recording slot, while the UI shows nothing at all.
  const handleClose = useCallback(() => {
    if (phase === 'recording' || phase === 'starting') {
      stopPolling()
      void fetch(`/api/projects/${projectId}/recording/stop`, { method: 'POST' }).catch(() => {})
    }
    onClose()
  }, [phase, projectId, onClose])

  const captured = summary && (summary.hasCookie || summary.hasBearer || summary.extraHeaderNames.length > 0)

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="large" title="Record a login">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxHeight: '75vh', overflowY: 'auto', paddingRight: 6 }}>
        <p style={{ margin: 0, color: 'var(--text-tertiary)', fontSize: 13 }}>
          Point your browser at the capture proxy and log in to the target once. RedAmon
          extracts the session and offers to save it as this project&apos;s authenticated
          identity. The raw value is never shown back to you.
        </p>

        {/* The proxy gate is the usual reason a recording captures nothing: the
            modal happily starts, the operator logs in, and no request is ever
            tagged. State the prerequisite before the steps, not after. */}
        <p style={{
          margin: 0, fontSize: 12, color: 'var(--text-secondary)',
          borderLeft: '3px solid #7aa2f7', paddingLeft: 10,
        }}>
          <strong>Before you start:</strong> HTTP capture must be on, or nothing is
          recorded. Enable the capture proxy in <strong>Settings → TrafficMind</strong>
          {' '}(admin), and turn on <strong>HTTP capture</strong> for this project.
        </p>

        <div style={{ background: 'var(--bg-secondary, rgba(255,255,255,0.03))', borderRadius: 8, padding: 12, fontSize: 13 }}>
          <div>1. Set your browser&apos;s HTTP(S) proxy to <strong>{PROXY_ADDR}</strong></div>
          <div>
            2. Open <a href="http://mitm.it" target="_blank" rel="noreferrer">http://mitm.it</a> and install the CA
          </div>
          <div>3. Browse the target and log in.</div>
          <div>4. Come back and press <strong>Stop</strong>.</div>
          <p style={{ marginTop: 8, color: '#e0af68', fontSize: 12 }}>
            ⚠ Use a clean/dedicated browser profile, browse only the target, and remove the CA when finished. While
            recording, all of that browser&apos;s traffic is decrypted by the proxy.
          </p>
        </div>

        {blocked && <p style={{ color: '#f7768e', fontSize: 13, margin: 0 }}>{blocked}</p>}

        {phase === 'recording' && session && (
          <div style={{ fontSize: 13 }}>
            <span style={{ color: '#e0af68' }}>● Recording…</span>{' '}
            captured {session.observedCount} request(s){session.observedCount === 0 ? ', waiting for login traffic' : ''}.
            {session.lastError && <div style={{ color: '#f7768e' }}>{session.lastError}</div>}
          </div>
        )}

        {phase === 'stopped' && (
          <div style={{ fontSize: 13 }}>
            {captured ? (
              <>
                <div style={{ color: '#9ece6a' }}>Captured a session:</div>
                <ul style={{ margin: '6px 0' }}>
                  {summary!.hasCookie && <li>Cookie set</li>}
                  {summary!.hasBearer && <li>Bearer token set</li>}
                  {summary!.extraHeaderNames.map(n => <li key={n}>{n} set</li>)}
                  {summary!.hosts.length > 0 && <li>hosts: {summary!.hosts.join(', ')}</li>}
                </ul>
              </>
            ) : (
              <div style={{ color: '#f7768e' }}>No login detected. Nothing was captured, so the existing profile is unchanged.</div>
            )}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          {phase === 'idle' && <button className="primaryButton" type="button" onClick={start}>Start recording</button>}
          {phase === 'starting' && <button className="primaryButton" type="button" disabled>Starting…</button>}
          {phase === 'recording' && <button className="primaryButton" type="button" onClick={stop}>Stop</button>}
          {phase === 'stopped' && (
            <>
              <button className="secondaryButton" type="button" onClick={() => commit(false)}>Discard</button>
              {captured && <button className="primaryButton" type="button" onClick={() => commit(true)}>Save session</button>}
            </>
          )}
          {phase === 'saving' && <button className="primaryButton" type="button" disabled>Saving…</button>}
        </div>
      </div>
    </Modal>
  )
}
