'use client'

import { useCallback, useEffect, useState } from 'react'
import { useOptionalProject } from '@/providers/ProjectProvider'
import { readApiError, type ApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'

/**
 * Read/write access to the Global Settings credentials from wherever a scan is
 * configured or started, so a missing key can be fixed in place instead of
 * navigating away from a half-filled form.
 *
 * These are USER-level settings, not project ones. A shortcut that writes them
 * from inside a project form is editing a value shared by every project, which
 * is why the UI built on this hook has to say so.
 *
 * GET returns secrets masked ('••••••••abcd'), never the real value, so this
 * hook can report whether a key is SET but can never show what it is. PUT
 * accepts a partial body and treats a '••••' prefix as "keep what you have", so
 * writing one key here cannot clobber the other twenty-one.
 */

/** The prefix the API masks secrets with. Writing it back is a no-op server-side. */
export const MASK_PREFIX = '••••'

/** A save refused because it re-points a stored secret (400 secret_reentry_required, HD-24). */
export interface SecretReentryPrompt {
  /** The first secret to type again. */
  field: string
  /** Every stored secret the new endpoint would have received. */
  fields: string[]
  /** The setting whose change asks for them, e.g. githubEnterpriseHost. */
  endpoint: string
  /** The server's sentence. */
  message: string
}

export interface SaveOptions {
  /**
   * Asked when the save re-points a stored secret: resolves the secrets to send with the
   * same save (a typed value, or '' to clear it), or null to give up.
   */
  onSecretReentry?: (r: SecretReentryPrompt) => Promise<Record<string, string> | null>
  /**
   * Asked when the save re-points a configured endpoint (403 step_up_required, ID-25):
   * resolves the signed-in person's password, sent with the same save, or null to give up.
   */
  onStepUp?: () => Promise<string | null>
}

export interface CredentialKeysApi {
  loading: boolean
  /** True once the key has a stored value. Never reveals what it is. */
  isSet: (name: string) => boolean
  /** The masked value for display, or '' when unset. */
  masked: (name: string) => string
  /** Persists one key. Resolves true on success. */
  save: (name: string, value: string, options?: SaveOptions) => Promise<boolean>
  /** The key currently being written, or null. */
  saving: string | null
  error: string
  /** Why the saved keys could not be read, with its status; a key then only LOOKS unset. */
  loadError?: string
  refresh: () => Promise<void>
}

const LOAD_FAILED = "Couldn't read your saved keys"
const SAVE_FAILED = 'Could not save the key'

function reentryOf(err: ApiError): SecretReentryPrompt | null {
  const b = err.body
  if (err.code !== 'secret_reentry_required' || typeof b?.field !== 'string') return null
  const fields = Array.isArray(b.fields) ? b.fields.filter((f): f is string => typeof f === 'string') : [b.field]
  return { field: b.field, fields, endpoint: typeof b.endpoint === 'string' ? b.endpoint : '', message: err.reason }
}


export function useCredentialKeys(): CredentialKeysApi {
  // Optional on purpose: this hook is embedded in scan cards that also render
  // outside a ProjectProvider, and a throw here would blank the whole surface
  // rather than degrade one input.
  const userId = useOptionalProject()?.userId ?? null
  const [values, setValues] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [loadError, setLoadError] = useState('')

  const refresh = useCallback(async () => {
    if (!userId) { setLoading(false); return }
    try {
      const res = await fetch(`/api/users/${userId}/settings`)
      if (!res.ok) {
        setLoadError(failureText(LOAD_FAILED, await readApiError(res, LOAD_FAILED)))
        return
      }
      setValues(await res.json())
      setLoadError('')
    } catch (err) {
      // A failed read must not break the form this is embedded in; the shortcut
      // shows the key as unset, says why, and the user can still type into it.
      setLoadError(failureText(LOAD_FAILED, err))
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { void refresh() }, [refresh])

  const isSet = useCallback(
    (name: string) => Boolean((values[name] ?? '').trim()),
    [values],
  )

  const masked = useCallback((name: string) => values[name] ?? '', [values])

  const save = useCallback(async (name: string, value: string, options: SaveOptions = {}) => {
    if (!userId) { setError('No user in session'); return false }
    setSaving(name)
    setError('')
    const put = (body: Record<string, string>) => fetch(`/api/users/${userId}/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    try {
      // A new endpoint (the GitHub Enterprise host) cannot keep its stored secret, and
      // re-pointing a configured one takes the password: each is asked once, and what the
      // caller answers rides with the same key in ONE save, never the host alone.
      let body: Record<string, string> = { [name]: value }
      let askedSecrets = false
      let askedPassword = false
      for (;;) {
        const res = await put(body)
        if (res.ok) break
        const err = await readApiError(res, SAVE_FAILED)
        const reentry = askedSecrets ? null : reentryOf(err)
        if (reentry && options.onSecretReentry) {
          askedSecrets = true
          const secrets = await options.onSecretReentry(reentry)
          if (secrets) { body = { ...body, ...secrets }; continue }
        } else if (err.code === 'step_up_required' && !askedPassword && options.onStepUp) {
          askedPassword = true
          const password = await options.onStepUp()
          if (password) { body = { ...body, stepUpPassword: password }; continue }
        }
        setError(err.message)
        return false
      }
      // Re-read rather than storing what was typed: the value we hold must be
      // the masked one, so a later save of a DIFFERENT key cannot send this
      // plaintext secret back to the server.
      await refresh()
      return true
    } catch (err) {
      setError(failureText(SAVE_FAILED, err))
      return false
    } finally {
      setSaving(null)
    }
  }, [userId, refresh])

  return { loading, isSet, masked, save, saving, error, loadError: loadError || undefined, refresh }
}
