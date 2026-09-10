'use client'

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { useSearchParams, useRouter, usePathname } from 'next/navigation'
import { useAuth } from './AuthProvider'

export interface ProjectSummary {
  id: string
  name: string
  targetDomain: string
  ipMode?: boolean
  targetIps?: string[]
  /** Domain batch: true, plus the derived group roots in run order. A batch
   *  project has an EMPTY targetDomain, so anything rendering a target must
   *  fall back to these. */
  domainBatchMode?: boolean
  domainBatchDomains?: string[]
  subdomainList?: string[]
  description?: string
  agentOpenaiModel?: string
  agentToolPhaseMap?: Record<string, string[]>
  stealthMode?: boolean
  agentRequireToolConfirmation?: boolean
  roeEnabled?: boolean
  createdAt: string
  updatedAt: string
}

interface ProjectContextValue {
  currentProject: ProjectSummary | null
  setCurrentProject: (project: ProjectSummary | null) => void
  projectId: string | null
  userId: string | null
  setUserId: (id: string | null) => void
  isLoading: boolean
}

const ProjectContext = createContext<ProjectContextValue | null>(null)

const STORAGE_KEY_PROJECT = 'redamon-current-project'
const STORAGE_KEY_USER = 'redamon-current-user'

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [currentProject, setCurrentProjectState] = useState<ProjectSummary | null>(null)
  const [userId, setUserIdState] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
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
        .then(res => res.ok ? res.json() : null)
        .then(project => {
          if (project) {
            setCurrentProjectState({
              id: project.id,
              name: project.name,
              targetDomain: project.targetDomain,
              ipMode: project.ipMode,
              targetIps: project.targetIps,
              domainBatchMode: project.domainBatchMode,
              domainBatchDomains: Array.isArray(project.domainBatchGroups)
                ? (project.domainBatchGroups as Array<{ rootDomain?: string }>)
                    .map(g => String(g?.rootDomain || '')).filter(Boolean)
                : [],
              subdomainList: project.subdomainList,
              description: project.description,
              agentOpenaiModel: project.agentOpenaiModel,
              agentToolPhaseMap: typeof project.agentToolPhaseMap === 'string'
                ? JSON.parse(project.agentToolPhaseMap)
                : project.agentToolPhaseMap,
              stealthMode: project.stealthMode,
              agentRequireToolConfirmation: project.agentRequireToolConfirmation,
              roeEnabled: project.roeEnabled,
              createdAt: project.createdAt,
              updatedAt: project.updatedAt
            })
            localStorage.setItem(STORAGE_KEY_PROJECT, project.id)
          } else {
            // Remove stale project ID from localStorage if project no longer exists
            localStorage.removeItem(STORAGE_KEY_PROJECT)
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

  const setUserId = useCallback((id: string | null) => {
    // Standard users cannot switch users
    if (!isAdmin && authUser) {
      setUserIdState(authUser.id)
      return
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
    void (async () => {
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
            localStorage.removeItem(STORAGE_KEY_USER)
            await fetch('/api/auth/act-as', { method: 'DELETE' }).catch(() => {})
          }
        } else {
          await fetch('/api/auth/act-as', { method: 'DELETE' })
        }
      } catch (e) {
        console.error('act-as sync failed', e)
      }
      setUserIdState(impersonated ? id : (authUser?.id ?? null))
    })()
  }, [isAdmin, authUser])

  return (
    <ProjectContext.Provider value={{
      currentProject,
      setCurrentProject,
      projectId: currentProject?.id || null,
      userId,
      setUserId,
      isLoading,
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
