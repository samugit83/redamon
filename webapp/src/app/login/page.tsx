'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'
import { useVersionCheck } from '@/hooks/useVersionCheck'
import { readApiError, toApiError } from '@/lib/apiError'
import { usePendingNotices } from '@/components/auth/PendingNotices'
import styles from './page.module.css'

export default function LoginPage() {
  const router = useRouter()
  const { currentVersion } = useVersionCheck()
  const showNotices = usePendingNotices()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })

      if (!res.ok) {
        // nginx answers a sign-in burst (429) and a restarting webapp (502) with
        // an HTML page, so the status and Retry-After are all there is to show.
        const err = await readApiError(res, 'Login failed')
        const retryAfter = Number(res.headers?.get('Retry-After'))
        setError(retryAfter > 0 ? `${err.message}. Retry in ${retryAfter} s.` : err.message)
        setLoading(false)
        return
      }

      // A credentials reset is shown to the person once, here, before the app opens (step 2.10).
      const body = await res.json().catch(() => null)
      await showNotices(body?.notices)

      // Force full page reload to pick up the new cookie in middleware
      window.location.href = '/graph'
    } catch (err) {
      setError(toApiError(err, 'Unable to connect to the server').message)
      setLoading(false)
    }
  }

  return (
    <div className={styles.page}>
      <Image
        src="/logo.png"
        alt=""
        width={520}
        height={520}
        className={styles.watermark}
        priority
      />

      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.logoRow}>
            <Image src="/logo.png" alt="RedAmon" width={63} height={40} priority />
            <span className={styles.logoText}>
              <span className={styles.logoAccent}>Red</span>Amon
            </span>
          </div>
          <p className={styles.subtitle}>Sign in to your account</p>
        </div>

        <div className={styles.body}>
          <form className={styles.form} onSubmit={handleSubmit}>
            {error && <div className={styles.error}>{error}</div>}

            <div className={styles.field}>
              <label htmlFor="email" className={styles.label}>Email</label>
              <input
                id="email"
                type="email"
                className={styles.input}
                placeholder="admin@redamon.local"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
                autoComplete="email"
              />
            </div>

            <div className={styles.field}>
              <label htmlFor="password" className={styles.label}>Password</label>
              <input
                id="password"
                type="password"
                className={styles.input}
                placeholder="Enter your password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
            </div>

            <button
              type="submit"
              className={styles.submitButton}
              disabled={loading || !email || !password}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        </div>

        <div className={styles.footer}>
          <span className={styles.version}>v{currentVersion}</span>
        </div>
      </div>
    </div>
  )
}
