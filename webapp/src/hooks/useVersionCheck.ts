'use client'

import { useState, useEffect, useCallback } from 'react'
import { isNewerVersion } from '@/lib/semver'
import type { ChangelogEntry } from '@/lib/parseChangelog'

const DISMISSED_KEY = 'redamon-dismissed-version'

interface VersionCheckResult {
  current_version: string
  latest_version: string | null
  changelog: ChangelogEntry[]
}

interface VersionCheckState {
  currentVersion: string
  latestVersion: string | null
  changelog: ChangelogEntry[]
  updateAvailable: boolean
  isDismissed: boolean
  loading: boolean
  dismissUpdate: () => void
}

export function useVersionCheck(): VersionCheckState {
  const [currentVersion, setCurrentVersion] = useState('0.0.0')
  const [latestVersion, setLatestVersion] = useState<string | null>(null)
  const [changelog, setChangelog] = useState<ChangelogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [dismissedVersion, setDismissedVersion] = useState<string | null>(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem(DISMISSED_KEY)
    }
    return null
  })

  const updateAvailable = latestVersion !== null && isNewerVersion(currentVersion, latestVersion)
  const isDismissed = latestVersion !== null && dismissedVersion === latestVersion

  const fetchVersion = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/version/check')
      if (!res.ok) return

      const data: VersionCheckResult = await res.json()
      if (data.current_version) {
        setCurrentVersion(data.current_version)
        setLatestVersion(data.latest_version)
        setChangelog(data.changelog || [])
      }
    } catch {
      // Silent failure -- no error UI if GitHub is unreachable
    } finally {
      setLoading(false)
    }
  }, [])

  const dismissUpdate = useCallback(() => {
    if (latestVersion && typeof window !== 'undefined') {
      localStorage.setItem(DISMISSED_KEY, latestVersion)
      setDismissedVersion(latestVersion)
    }
  }, [latestVersion])

  // Fetch fresh on every mount (page load)
  useEffect(() => {
    fetchVersion()
  }, [fetchVersion])

  return {
    currentVersion,
    latestVersion,
    changelog,
    updateAvailable,
    isDismissed,
    loading,
    dismissUpdate,
  }
}
