'use client'

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { useSearchParams, useRouter, usePathname } from 'next/navigation'
import { useAuth } from './AuthProvider'
import { useCan, useRbacFlags } from '@/hooks/useCan'
import { type ProjectSummary, toProjectSummary } from '@/lib/projectSummary'
import { type ApiError, readApiError, toApiError } from '@/lib/apiError'
import { ActAsDialog, type ActAsDialogTarget } from '@/components/auth/ActAsDialog'
import { ACT_AS_PICK_KEY, forgetActAsPick, recallActAsPick, rememberActAsPick } from '@/lib/actAsPick'

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
   *
   * With RBAC_PERMISSIONS_ENABLED on (step 3.14) every impersonation takes a reason, a duration
   * and the admin's password: without `stepUpPassword` this opens the act-as dialog (named by
   * `target` when the caller knows the account) and resolves when it closes, null when cancelled.
   */
  setUserId: (id: string | null, opts?: SetUserIdOptions) => Promise<ApiError | null>
  isLoading: boolean
  /**
   * Why the last user switch was refused (the effective user stayed the admin's
   * own). This provider sits above the toast layer, so a component under it
   * shows the message.
   */
  userSwitchError: ApiError | null
}

export interface SetUserIdOptions {
  stepUpPassword?: string
  /** Permissions switch on: why and for how long (the act-as dialog sends them). */
  reason?: string
  durationMinutes?: number
  /** Permissions switch on: how the dialog names the account, when the caller knows it. */
  target?: ActAsDialogTarget
}

const ProjectContext = createContext<ProjectContextValue | null>(null)

const STORAGE_KEY_PROJECT = 'redamon-current-project'

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
  const { user: authUser, isLoading: authLoading, refresh: refreshSession } = useAuth()
  // Acting as another account is `users:impersonate`'s (the act-as route asks it).
  const canSwitchUser = useCan('users:impersonate')
  // Permissions switch on (step 3.14): the server says whom the admin acts as (/api/auth/me
  // `actingAs`), with a time limit the browser must not outlive, so nothing is restored here.
  const rbacFlags = useRbacFlags()
  const serverOwned = rbacFlags?.permissions === true
  // Identity switch on: only a pick the signed-in admin made is remembered and restored (lib/actAsPick).
  // Then only a person's pick asks for another account here: the projects page chooses nobody (3.16c).
  const identityOn = rbacFlags?.identity === true || serverOwned
  const actingAsId = authUser?.actingAs?.id ?? null
  // The act-as dialog waiting for an answer, and who is waiting for its outcome.
  const [actAsRequest, setActAsRequest] = useState<{ target: ActAsDialogTarget; settle: (r: ApiError | null) => void } | null>(null)
  // The id, not the object: reading the session again (after a switch) must not reconcile again.
  const authUserId = authUser?.id ?? null

  // Sync userId with auth state + reconcile the server act-as cookie.
  useEffect(() => {
    if (authLoading) return
    if (!authUserId) return
    let cancelled = false

    if (serverOwned) {
      // No silent restore (IM-02): a selection a previous version remembered is dropped.
      forgetActAsPick()
      setUserIdState(actingAsId ?? authUserId)
      setImpersonationSynced(true)
    } else if (canSwitchUser) {
      // Restore the saved impersonation target (or own id).
      const target = recallActAsPick(authUserId, identityOn)
      setUserIdState(target || authUserId)
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
              forgetActAsPick()
              if (!cancelled) setUserIdState(authUserId)
              await fetch('/api/auth/act-as', { method: 'DELETE' }).catch(() => {})
            } else {
              // The session read at load may predate the cookie: what may be used while acting differs.
              await refreshSession?.()
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
      // Anyone who may not act as others: always locked to own id; no impersonation cookie.
      setUserIdState(authUserId)
      // Switches off the own id is saved, as before (DV-30); with identity on a pick is an admin's.
      if (identityOn) forgetActAsPick()
      else localStorage.setItem(ACT_AS_PICK_KEY, authUserId)
      setImpersonationSynced(true)
    }
    return () => { cancelled = true }
  }, [authUserId, authLoading, canSwitchUser, refreshSession, serverOwned, identityOn, actingAsId])

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

  /** Permissions switch on: start (from the dialog) or stop an impersonation; the server holds it. */
  const switchOnServer = useCallback(async (id: string | null, opts?: SetUserIdOptions): Promise<ApiError | null> => {
    if (!authUser) return null
    const other = id && id !== authUser.id ? id : null
    if (other && opts?.stepUpPassword === undefined) {
      return new Promise<ApiError | null>((settle) => {
        // A caller that does not name the account gets "this account", never its raw id.
        setActAsRequest({ target: opts?.target ?? { id: other, name: '', email: '' }, settle })
      })
    }
    try {
      const resp = other
        ? await fetch('/api/auth/act-as', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            targetUserId: other, stepUpPassword: opts?.stepUpPassword, reason: opts?.reason, durationMinutes: opts?.durationMinutes,
          }),
        })
        : await fetch('/api/auth/act-as', { method: 'DELETE' })
      if (!resp.ok) return await readApiError(resp, other ? 'Could not switch user' : 'Could not stop acting as this user')
    } catch (e) {
      return toApiError(e, other ? 'Could not switch user' : 'Could not stop acting as this user')
    }
    setUserSwitchError(null)
    setUserIdState(other ?? authUser.id)
    // The previous account's project is not the new one's.
    setCurrentProjectState(null)
    localStorage.removeItem(STORAGE_KEY_PROJECT)
    // The banner, the switcher and what may be used follow the cookie (/api/auth/me answers it).
    await refreshSession?.()
    return null
  }, [authUser, refreshSession])

  const setUserId = useCallback(async (id: string | null, opts?: SetUserIdOptions): Promise<ApiError | null> => {
    // Only an account that may act as others switches users.
    if (!canSwitchUser && authUser) {
      setUserIdState(authUser.id)
      return null
    }
    if (serverOwned) return switchOnServer(id, opts)
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
      rememberActAsPick(id, authUser?.id, identityOn)
      setUserSwitchError(null)
      setUserIdState(id)
      // What may be used follows the act-as cookie (/api/auth/me answers it).
      void refreshSession?.()
      return null
    }
    // Persist the UI hint immediately; the localStorage value is NOT trusted for
    // authorization - the server derives the effective user from the signed
    // `redamon-act-as` cookie set below (admin-only, verified server-side).
    if (id && id !== authUser?.id) {
      rememberActAsPick(id, authUser?.id, identityOn)
    } else {
      forgetActAsPick()
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
            forgetActAsPick()
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
          forgetActAsPick()
          refusal = toApiError(e, 'Could not switch user')
          setUserSwitchError(refusal)
        }
      }
      setUserIdState(impersonated ? id : (authUser?.id ?? null))
      // What may be used follows the act-as cookie just set or cleared (/api/auth/me answers it).
      void refreshSession?.()
    }
    return refusal
  }, [canSwitchUser, authUser, refreshSession, serverOwned, identityOn, switchOnServer])

  const closeActAs = useCallback(() => {
    actAsRequest?.settle(null)
    setActAsRequest(null)
  }, [actAsRequest])

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
      {serverOwned && (
        <ActAsDialog
          isOpen={actAsRequest !== null}
          target={actAsRequest?.target ?? null}
          maxMinutes={authUser?.impersonation?.maxMinutes ?? 720}
          reasonRequired={authUser?.impersonation?.reasonRequired ?? false}
          onConfirm={async ({ reason, durationMinutes, password }) => {
            if (!actAsRequest) return
            const refusal = await switchOnServer(actAsRequest.target.id, { stepUpPassword: password, reason, durationMinutes })
            if (refusal) throw refusal
          }}
          onClose={closeActAs}
        />
      )}
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
