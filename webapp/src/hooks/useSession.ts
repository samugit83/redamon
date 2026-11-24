'use client'

import { useState, useEffect, useCallback } from 'react'

const SESSION_STORAGE_KEY = 'redamon-session-id'

// STRIDE S7: use a CSPRNG, not Math.random(), and widen the id to 128 bits so a
// session id cannot be guessed/predicted (which, combined with S6, would allow
// session-collision hijack). getRandomValues works in non-secure contexts
// (plain http on the LAN), unlike crypto.randomUUID()/crypto.subtle.
function generateSessionId(): string {
  const bytes = new Uint8Array(16) // 128 bits
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    // SSR / very old runtime fallback: still avoid a predictable stream.
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256)
  }
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return `session_${hex}`
}

export function useSession() {
  const [sessionId, setSessionId] = useState<string>('')
  const [mounted, setMounted] = useState(false)

  // Initialize session on mount
  useEffect(() => {
    // Use environment variable if available, otherwise generate new session ID
    const envSessionId = process.env.NEXT_PUBLIC_SESSION_ID
    const newSessionId = envSessionId || generateSessionId()
    // eslint-disable-next-line react-hooks/set-state-in-effect -- the id is made on the client after hydration, so the server render and the first client render agree
    setSessionId(newSessionId)
    sessionStorage.setItem(SESSION_STORAGE_KEY, newSessionId)
    setMounted(true)
  }, [])

  const resetSession = useCallback(() => {
    const newSessionId = generateSessionId()
    setSessionId(newSessionId)
    sessionStorage.setItem(SESSION_STORAGE_KEY, newSessionId)
    return newSessionId
  }, [])

  const switchSession = useCallback((existingSessionId: string) => {
    setSessionId(existingSessionId)
    sessionStorage.setItem(SESSION_STORAGE_KEY, existingSessionId)
  }, [])

  return {
    sessionId,
    resetSession,
    switchSession,
    mounted,
  }
}
