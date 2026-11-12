'use client'

/**
 * Global Settings → Tunneling with the identity switch on (step 2.4): the tunnel is an
 * instance setting, read and saved through /api/admin/instance-settings as the signed-in
 * person, never the account an admin acts as. Whoever may change it (an admin, the member
 * holding the `tunnels` legacy grant, a pre-upgrade account under the escape hatch) gets
 * the controls and a Save of their own, apart from the page's keys; anyone else sees the
 * tunnel's status. A new chisel URL asks for its auth again and for the password, as the
 * route requires.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { Eye, EyeOff, Loader2 } from 'lucide-react'
import { useToast } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { readApiError } from '@/lib/apiError'
import { failureText, saveWarningLines } from '@/components/settings/failureText'
import styles from '@/components/settings/Settings.module.css'
import { TunnelStatusReadOnly } from './TunnelStatusReadOnly'

const INSTANCE_SETTINGS_URL = '/api/admin/instance-settings'
const LOAD_FAILED = "Couldn't load the tunnel settings"
const SAVE_FAILED = 'The tunnel settings were not saved'

interface Tunnel {
  tunnelsEnabled: boolean
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
}

type View = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'readonly' } | { kind: 'edit' }

const pickTunnel = (body: Record<string, unknown>): Tunnel => ({
  tunnelsEnabled: body.tunnelsEnabled === true,
  ngrokAuthtoken: typeof body.ngrokAuthtoken === 'string' ? body.ngrokAuthtoken : '',
  chiselServerUrl: typeof body.chiselServerUrl === 'string' ? body.chiselServerUrl : '',
  chiselAuth: typeof body.chiselAuth === 'string' ? body.chiselAuth : '',
})

const fieldId = (name: string) => `instance-tunnel-${name}`

export function InstanceTunnelSection() {
  const toast = useToast()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [tunnel, setTunnel] = useState<Tunnel>({ tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  const saved = useRef<Tunnel | null>(null)
  const [saving, setSaving] = useState(false)
  const [visible, setVisible] = useState<Record<string, boolean>>({})
  const [stepUp, setStepUp] = useState<{ retry: (password: string) => Promise<void> } | null>(null)

  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const resp = await fetch(INSTANCE_SETTINGS_URL, { cache: 'no-store' })
      if (resp.status === 403 || resp.status === 404) {
        setView({ kind: 'readonly' })
        return
      }
      if (!resp.ok) throw await readApiError(resp, LOAD_FAILED)
      const body = await resp.json() as Record<string, unknown>
      if (body.canManageTunnels !== true) {
        setView({ kind: 'readonly' })
        return
      }
      const t = pickTunnel(body)
      saved.current = t
      setTunnel(t)
      setView({ kind: 'edit' })
    } catch (err) {
      setView({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [])

  useEffect(() => { load() }, [load])

  const dirty = !!saved.current && (Object.keys(tunnel) as (keyof Tunnel)[]).some(k => tunnel[k] !== saved.current![k])

  const send = useCallback((stepUpPassword?: string) => fetch(INSTANCE_SETTINGS_URL, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...tunnel, ...(stepUpPassword ? { stepUpPassword } : {}) }),
  }), [tunnel])

  const applySaved = useCallback((body: Record<string, unknown>) => {
    const t = pickTunnel(body)
    saved.current = t
    setTunnel(t)
    toast.success('Tunnel settings saved')
    const warnings = saveWarningLines(body)
    if (warnings.length) toast.warning(warnings.join('\n'), 'Saved, but not applied')
  }, [toast])

  const save = useCallback(async () => {
    setSaving(true)
    try {
      const resp = await send()
      if (resp.ok) {
        applySaved(await resp.json())
        return
      }
      const err = await readApiError(resp, SAVE_FAILED)
      if (err.code === 'step_up_required') {
        setStepUp({
          retry: async (password) => {
            const again = await send(password)
            // Thrown, the dialog stays open and shows why (a wrong password, a lockout).
            if (!again.ok) throw await readApiError(again, SAVE_FAILED)
            applySaved(await again.json())
            setStepUp(null)
          },
        })
        return
      }
      toast.error(err.message)
      // A new chisel URL needs its auth typed again (HD-24): go to that field.
      if (err.code === 'secret_reentry_required' && typeof err.body?.field === 'string') {
        document.getElementById(fieldId(err.body.field))?.focus()
      }
    } catch (err) {
      toast.error(failureText(SAVE_FAILED, err))
    } finally {
      setSaving(false)
    }
  }, [send, applySaved, toast])

  if (view.kind === 'loading') {
    return <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
  }
  if (view.kind === 'error') {
    return (
      <div className={styles.emptyState} role="alert">
        {view.message}.{' '}
        <button type="button" className="textButton" onClick={load}>Retry</button>
      </div>
    )
  }
  if (view.kind === 'readonly') return <TunnelStatusReadOnly />

  const secret = (name: 'ngrokAuthtoken' | 'chiselAuth', label: string, hint: string) => (
    <div className="formGroup">
      <label className="formLabel" htmlFor={fieldId(name)}>{label}</label>
      <div className={styles.secretInputWrapper}>
        <input
          id={fieldId(name)}
          className="textInput"
          type={visible[name] ? 'text' : 'password'}
          value={tunnel[name]}
          onChange={e => setTunnel(prev => ({ ...prev, [name]: e.target.value }))}
          placeholder={`Enter ${label.toLowerCase()}`}
          autoComplete="off"
        />
        <button
          className={styles.secretToggle}
          type="button"
          aria-label={visible[name] ? `Hide ${label}` : `Show ${label}`}
          onClick={() => setVisible(prev => ({ ...prev, [name]: !prev[name] }))}
        >
          {visible[name] ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
      <span className="formHint">{hint}</span>
    </div>
  )

  return (
    <>
      <div className={styles.settingsGrid}>
        <div className="formGroup">
          <label className="formLabel" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <input
              type="checkbox"
              checked={tunnel.tunnelsEnabled}
              onChange={e => setTunnel(prev => ({ ...prev, tunnelsEnabled: e.target.checked }))}
            />
            <span>Enable tunnels</span>
          </label>
          <span className="formHint">
            When off, saved credentials are stored but no tunnel is started. Enabling exposes port 4444 to the internet via ngrok/chisel.
          </span>
        </div>
        {secret('ngrokAuthtoken', 'ngrok Auth Token', 'Enables ngrok TCP tunnel for reverse shells on port 4444. Stageless payloads only.')}
        <div className="formGroup">
          <label className="formLabel" htmlFor={fieldId('chiselServerUrl')}>Chisel Server URL</label>
          <input
            id={fieldId('chiselServerUrl')}
            className="textInput"
            type="text"
            value={tunnel.chiselServerUrl}
            onChange={e => setTunnel(prev => ({ ...prev, chiselServerUrl: e.target.value }))}
            placeholder="e.g. http://your-vps.com:9090"
          />
          <span className="formHint">
            Your VPS chisel server URL. Run on VPS: <code>chisel server -p 9090 --reverse</code>. Tunnels port 4444 (reverse-shell handler).
          </span>
        </div>
        {secret('chiselAuth', 'Chisel Auth', 'user:pass for chisel server authentication (optional - only if your chisel server requires auth)')}
      </div>
      <div>
        <button type="button" className="primaryButton" onClick={save} disabled={!dirty || saving}>
          {saving ? <><Loader2 size={14} className={styles.spin} /> Saving...</> : 'Save tunnel settings'}
        </button>
        <span className="formHint" style={{ marginLeft: 8 }}>
          The tunnel is shared by the whole instance; it is saved on its own, apart from your keys.
        </span>
      </div>
      {stepUp && (
        <StepUpModal
          isOpen
          title="Confirm the new tunnel server"
          message="Moving the tunnel to another server sends the reverse-shell traffic there. Enter your password to confirm."
          confirmLabel="Save tunnel settings"
          onConfirm={stepUp.retry}
          onClose={() => setStepUp(null)}
        />
      )}
    </>
  )
}
