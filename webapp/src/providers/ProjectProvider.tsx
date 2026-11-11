'use client'

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { useSearchParams, useRouter, usePathname } from 'next/navigation'
import { useAuth } from './AuthProvider'
import { type ProjectSummary, toProjectSummary } from '@/lib/projectSummary'
import { type ApiError, readApiError, toApiError } from '@/lib/apiError'

export type { ProjectSummary } from '@/lib/projectSummary'

interface ProjectContextValue {
  currentProject: ProjectSummary | null
  setCurrentProject: (project: ProjectSummary | null) => void
  projectId: string | null
  userId: string | null
  /**
   * Switch the effective user. Acting as another admin needs `stepUpPassword` (the
   * signed-in admin's own); a refused one resolves the error and changes nothing, so
   * the dialog that asked can ask again. Resolves null on success.
   */
  setUserId: (id: string | null, opts?: { stepUpPassword?: string }) => Promise<ApiError | null>
  isLoading: boolean
  /**
   * Why the last user switch was refused (the effective user stayed the admin's
   * own). This provider sits above the toast layer, so a component under it
   * shows the message.
   */
  userSwitchError: ApiError | null
}

const ProjectContext = createContext<ProjectContextValue | null>(null)

const STORAGE_KEY_PROJECT = 'redamon-current-project'
const STORAGE_KEY_USER = 'redamon-current-user'

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [currentProject, setCurrentProjectState] = useState<ProjectSummary | null>(null)
  const [userId, setUserIdState] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [userSwitchError, setUserSwitchError] = useState<ApiError | null>(null)
  // Gates data loads until the server-side act-as cookie has been reconciled with
  // the restored (localStorage) impersonation selection, so an admin's first load
  // after a refresh never fetches with a stale/absent cookie (which would 404
  // under enforcement). Standard users are ready immediately.
  const [impersonationSynced, setImpersonationSynced] = useState(false)
  const searchParams = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  const { user: authUser, isLoading: authLoading, isAdmin } = useAuth()

  // Sync userId with auth state + reconcile the server act-as cookie.
  useEffect(() => {
    if (authLoading) return
    if (!authUser) return
    let cancelled = false

    if (isAdmin) {
      // Admin: restore the saved impersonation target (or own id).
      const savedUserId = localStorage.getItem(STORAGE_KEY_USER)
      const target = savedUserId && savedUserId !== authUser.id ? savedUserId : null
      setUserIdState(target || authUser.id)
      // Make the server-side impersonation match, THEN allow loads.
      ;(async () => {
        try {
          if (target) {
            const resp = await fetch('/api/auth/act-as', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ targetUserId: target }),
            })
            // The server refuses to impersonate a user that no longer exists
            // (404 after a DB reset or a deleted account). Keeping the target
            // anyway left every user-scoped call pointed at a ghost id: reads
            // returned an innocuous empty list while the first write died on
            // the user_id foreign key as an opaque 500. Fall back to the
            // admin's own id and forget the stale selection.
            if (!resp.ok) {
              localStorage.removeItem(STORAGE_KEY_USER)
              if (!cancelled) setUserIdState(authUser.id)
              await fetch('/api/auth/act-as', { method: 'DELETE' }).catch(() => {})
            }
          } else {
            await fetch('/api/auth/act-as', { method: 'DELETE' })
          }
        } catch (e) {
          console.error('act-as reconcile failed', e)
        }
        if (!cancelled) setImpersonationSynced(true)
      })()
    } else {
      // Standard user: always locked to own id; no impersonation cookie.
      setUserIdState(authUser.id)
      localStorage.setItem(STORAGE_KEY_USER, authUser.id)
      setImpersonationSynced(true)
    }
    return () => { cancelled = true }
  }, [authUser, authLoading, isAdmin])

  // Initialize from URL or localStorage (after impersonation is reconciled)
  useEffect(() => {
    if (authLoading) return
    if (!impersonationSynced) return
    const urlProjectId = searchParams.get('project')
    const savedProjectId = localStorage.getItem(STORAGE_KEY_PROJECT)
    const projectIdToLoad = urlProjectId || savedProjectId

    // Load project
    if (projectIdToLoad) {
      fetch(`/api/projects/${projectIdToLoad}`)
        .then(async res => {
          if (res.ok) return res.json()
          // Only a 404 says the project is gone. An outage (500, 503) must not
          // wipe the saved selection, or every restart forgets the project.
          if (res.status === 404) localStorage.removeItem(STORAGE_KEY_PROJECT)
          else console.error((await readApiError(res, 'Could not load the saved project')).message)
          return null
        })
        .then(project => {
          if (project) {
            setCurrentProjectState(toProjectSummary(project))
            localStorage.setItem(STORAGE_KEY_PROJECT, project.id)
          }
        })
        .catch(console.error)
        .finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, [searchParams, authLoading, impersonationSynced])

  const setCurrentProject = useCallback((project: ProjectSummary | null) => {
    setCurrentProjectState(project)
    if (project) {
      localStorage.setItem(STORAGE_KEY_PROJECT, project.id)
      // Update URL without navigation if we're on a page that uses project context
      if (pathname.startsWith('/graph') || pathname.startsWith('/projects') || pathname.startsWith('/insights') || pathname.startsWith('/js-recon') || pathname.startsWith('/traffic')) {
        const params = new URLSearchParams(searchParams.toString())
        params.set('project', project.id)
        router.replace(`${pathname}?${params.toString()}`, { scroll: false })
      }
    } else {
      localStorage.removeItem(STORAGE_KEY_PROJECT)
      // Remove project from URL
      const params = new URLSearchParams(searchParams.toString())
      params.delete('project')
      const newUrl = params.toString() ? `${pathname}?${params.toString()}` : pathname
      router.replace(newUrl, { scroll: false })
    }
  }, [searchParams, router, pathname])

  const setUserId = useCallback(async (id: string | null, opts?: { stepUpPassword?: string }): Promise<ApiError | null> => {
    // Standard users cannot switch users
    if (!isAdmin && authUser) {
      setUserIdState(authUser.id)
      return null
    }
    if (opts?.stepUpPassword !== undefined && id && id !== authUser?.id) {
      try {
        const resp = await fetch('/api/auth/act-as', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetUserId: id, stepUpPassword: opts.stepUpPassword }),
        })
        if (!resp.ok) return await readApiError(resp, 'Could not switch user')
      } catch (e) {
        return toApiError(e, 'Could not switch user')
      }
      localStorage.setItem(STORAGE_KEY_USER, id)
      setUserSwitchError(null)
      setUserIdState(id)
      return null
    }
    // Persist the UI hint immediately; the localStorage value is NOT trusted for
    // authorization - the server derives the effective user from the signed
    // `redamon-act-as` cookie set below (admin-only, verified server-side).
    if (id && id !== authUser?.id) {
      localStorage.setItem(STORAGE_KEY_USER, id)
    } else {
      localStorage.removeItem(STORAGE_KEY_USER)
    }
    // Set the server cookie FIRST, then flip the effective userId so that the data
    // fetches it triggers already carry the correct impersonation (no race / no
    // transient 404 under enforcement).
    let refusal: ApiError | null = null
    {
      let impersonated = Boolean(id && id !== authUser?.id)
      try {
        if (impersonated) {
          const resp = await fetch('/api/auth/act-as', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetUserId: id }),
          })
          // Same ghost-user guard as the mount-time reconcile: a rejected
          // target must never become the effective id.
          if (!resp.ok) {
            impersonated = false
            refusal = await readApiError(resp, 'Could not switch user')
            setUserSwitchError(refusal)
            localStorage.removeItem(STORAGE_KEY_USER)
            await fetch('/api/auth/act-as', { method: 'DELETE' }).catch(() => {})
          } else {
            setUserSwitchError(null)
          }
        } else {
          await fetch('/api/auth/act-as', { method: 'DELETE' })
          setUserSwitchError(null)
        }
      } catch (e) {
        console.error('act-as sync failed', e)
        // No answer means no act-as cookie either: stay on the admin's own id,
        // as for a refused target, instead of a half-switched session.
        if (impersonated) {
          impersonated = false
          localStorage.removeItem(STORAGE_KEY_USER)
          refusal = toApiError(e, 'Could not switch user')
          setUserSwitchError(refusal)
        }
      }
      setUserIdState(impersonated ? id : (authUser?.id ?? null))
    }
    return refusal
  }, [isAdmin, authUser])

  return (
    <ProjectContext.Provider value={{
      currentProject,
      setCurrentProject,
      projectId: currentProject?.id || null,
      userId,
      setUserId,
      isLoading,
      userSwitchError,
    }}>
      {children}
    </ProjectContext.Provider>
  )
}

export function useProject() {
  const context = useContext(ProjectContext)
  if (!context) {
    throw new Error('useProject must be used within ProjectProvider')
  }
  return context
}

/**
 * The context if there is one, null otherwise.
 *
 * For widgets that are merely NICER with a user in scope and must not take the
 * tree down without one - an inline credential shortcut degrades to a disabled
 * box, where `useProject()` would throw and blank the whole page it sits in.
 */
export function useOptionalProject() {
  return useContext(ProjectContext)
}
