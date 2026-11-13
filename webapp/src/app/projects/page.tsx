'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, FolderOpen, Users, RefreshCw, Trash2, Upload, AlertTriangle, ShieldAlert, ShieldOff, Share2 } from 'lucide-react'
import Link from 'next/link'
import { useProjects, useDeleteProject, type ProjectListItem } from '@/hooks/useProjects'
import { useUsers, useCreateUser, useDeleteUser } from '@/hooks/useUsers'
import { useProject } from '@/providers/ProjectProvider'
import { useOptionalAuth } from '@/providers/AuthProvider'
import { useCan, useRbacFlags } from '@/hooks/useCan'
import { useRefusalCheck } from '@/hooks/useRefusal'
import { accountTypeFor } from '@/components/auth/IdentityLabel'
import type { ActAsDialogTarget } from '@/components/auth/ActAsDialog'
import { BreakGlassDialog, type BreakGlassInput, type BreakGlassTarget } from '@/components/auth/BreakGlassDialog'
import { useOversightProjects } from '@/hooks/useOversightProjects'
import { ShareDialog, type ShareDialogProject } from '@/components/sharing/ShareDialog'
import { LeaveShareButton } from '@/components/sharing/LeaveShareButton'
import { shareActions } from '@/components/sharing/sharePresets'
import { ProjectCard } from '@/components/projects/ProjectCard'
import { InitialSetPicker, NO_INITIAL_SET, initialSetFields, type InitialSetChoice } from '@/components/admin/InitialSetPicker'
import { projectTargetLabel, toProjectSummary } from '@/lib/projectSummary'
import { accessBadge, isSharedWithMe, sharedByLabel, splitProjectList } from '@/lib/sharedProjects'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { errorMessage, fetchJson, fetchOk } from '@/lib/apiError'
import { ImportModal } from './ImportModal'
import styles from './page.module.css'

type ListFilter = 'all' | 'owned' | 'shared' | 'oversight'

const LIST_FILTERS: ReadonlyArray<{ value: ListFilter; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'owned', label: 'My projects' },
  { value: 'shared', label: 'Shared with me' },
]
const OVERSIGHT_FILTER: { value: ListFilter; label: string } = { value: 'oversight', label: 'All projects (oversight)' }

export default function ProjectsPage() {
  const router = useRouter()
  const { userId, setUserId, setCurrentProject, currentProject, checkAccessNow } = useProject()
  const { alertError, dangerConfirm, confirm } = useAlertModal()
  const toast = useToast()
  // The user bar is the directory's (UI-03): members never see it.
  const canReadUsers = useCan('users:read')
  const canSwitchUser = useCan('users:impersonate')
  const canCreateUsers = useCan('users:create')
  const canDeleteUsers = useCan('users:delete')
  const canOversee = useCan('projects:oversee')
  const canBreakGlass = useCan('projects:administer')
  const [showUserModal, setShowUserModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [newUserName, setNewUserName] = useState('')
  const [newUserEmail, setNewUserEmail] = useState('')
  // Permissions switch on: the set the new member starts with (step 3.13, ID-28).
  const [newUserSet, setNewUserSet] = useState<InitialSetChoice>(NO_INITIAL_SET)

  const { data: users, isLoading: usersLoading } = useUsers()
  const { data: projects, isLoading: projectsLoading, error: projectsError, refetch } = useProjects(userId || undefined)
  const deleteProjectMutation = useDeleteProject()
  const createUserMutation = useCreateUser()
  const deleteUserMutation = useDeleteUser()
  const hasAutoSelected = useRef(false)
  const auth = useOptionalAuth()
  const ownId = auth?.user?.id ?? null
  // With RBAC on, choosing another account here starts acting as it (ProjectProvider), so only the
  // admin's own pick in the select may choose one (step 3.16c). Null until /api/auth/me answered:
  // nothing is chosen before the page knows which rule applies.
  const flags = useRbacFlags()
  const rbacOn = flags ? flags.identity || flags.permissions : null
  // The list holds the projects shared with the effective user too (under act-as, the target's, at
  // read: D-22). Their own section and the filter show only while sharing is in force (the switch
  // and Root's policy, as /api/auth/me reports it) and something is shared (step 4.5).
  const [listFilter, setListFilter] = useState<ListFilter>('all')
  const sharingInForce = auth?.user?.sharing?.enabled === true
  const { owned, shared } = splitProjectList(projects ?? [])
  const showShared = sharingInForce && shared.length > 0
  // Step 4.14: a holder of projects:oversee (never while acting as someone: auth/me's set is then what
  // both may use, which leaves the admin's own powers out) lists every project, read only, from the
  // same filter; opening one is the audited read. Root may open break-glass on a card.
  const showOversight = sharingInForce && canOversee && !auth?.user?.actingAs
  const showFilter = showShared || showOversight
  const filters = [
    ...LIST_FILTERS.filter(f => f.value !== 'shared' || showShared),
    ...(showOversight ? [OVERSIGHT_FILTER] : []),
  ]
  const oversight = useOversightProjects(showOversight && listFilter === 'oversight')
  const [glassTarget, setGlassTarget] = useState<BreakGlassTarget | null>(null)
  // Step 4.12: the share dialog of one of the person's own projects, and the refusal of a Share button
  // up front (an owner whose set lacks project:share).
  const [shareTarget, setShareTarget] = useState<ShareDialogProject | null>(null)
  const refusalOf = useRefusalCheck()

  const actAsTarget = (id: string): ActAsDialogTarget | undefined => {
    const picked = users?.find(u => u.id === id)
    if (!picked || picked.id === ownId) return undefined
    return { id: picked.id, name: picked.name, email: picked.email, accountType: accountTypeFor(picked, auth?.user?.rbac?.root) }
  }

  useEffect(() => {
    if (!users || rbacOn === null) return
    if (rbacOn) {
      // The provider already holds the admin's own account or the one they chose to act as.
      if (userId && userId !== ownId && !users.some(u => u.id === userId)) {
        void setUserId(null)
        setCurrentProject(null)
      }
      return
    }
    // Switches off: clear a stale userId if deleted, or auto-select the first user on initial load.
    if (userId && !users.find(u => u.id === userId)) {
      setUserId(users.length > 0 ? users[0].id : null)
      setCurrentProject(null)
    } else if (!hasAutoSelected.current && !userId && users.length > 0) {
      setUserId(users[0].id)
      hasAutoSelected.current = true
    }
  }, [userId, users, setUserId, setCurrentProject, rbacOn, ownId])

  const handleSelectProject = (project: ProjectListItem) => {
    setCurrentProject(toProjectSummary(project))
    router.push(`/graph?project=${project.id}`)
  }

  const handleDeleteProject = async (projectId: string) => {
    if (await dangerConfirm('Delete this project? Its graph, scan results and agent workspace files are deleted. This action cannot be undone.')) {
      try {
        await deleteProjectMutation.mutateAsync(projectId)
        toast.success('Project deleted')
      } catch (error) {
        alertError(errorMessage(error, 'Failed to delete project'))
        // A proxy timeout can answer after the row is already gone.
        void refetch()
      }
    }
  }

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()
    const setFields = initialSetFields(newUserSet)
    if ('error' in setFields) {
      alertError(setFields.error)
      return
    }
    try {
      const user = await createUserMutation.mutateAsync({
        name: newUserName,
        email: newUserEmail,
        ...setFields,
      })
      // With RBAC on that would start acting as the new account: creating one is not asking to.
      if (rbacOn === false) setUserId(user.id)
      setShowUserModal(false)
      setNewUserName('')
      setNewUserEmail('')
      setNewUserSet(NO_INITIAL_SET)
      toast.success('User created')
    } catch (error) {
      alertError(error instanceof Error ? error.message : 'Failed to create user')
    }
  }

  const handleDeleteUser = async () => {
    if (!userId) return
    const selectedUser = users?.find(u => u.id === userId)
    const projectCount = selectedUser?._count?.projects ?? 0
    const warning = projectCount > 0
      ? `This will permanently delete user "${selectedUser?.name}" and their ${projectCount} project(s). This action cannot be undone.`
      : `Are you sure you want to delete user "${selectedUser?.name}"? This action cannot be undone.`
    if (await dangerConfirm(warning)) {
      try {
        await deleteUserMutation.mutateAsync(userId)
        setUserId(null)
        setCurrentProject(null)
        toast.success('User deleted')
      } catch (error) {
        alertError(error instanceof Error ? error.message : 'Failed to delete user')
      }
    }
  }

  const isLoading = usersLoading || projectsLoading

  const openBreakGlass = async (input: BreakGlassInput) => {
    if (!glassTarget) return
    const { breakGlass } = await fetchJson<Record<'breakGlass', { expiresAt: string }>>(`/api/projects/${glassTarget.id}/breakglass`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: input.reason, durationMinutes: input.durationMinutes, stepUpPassword: input.password }),
    }, 'Break-glass was refused')
    toast.success(`Break-glass open until ${new Date(breakGlass.expiresAt).toLocaleTimeString()}`)
    oversight.refetch()
  }

  const closeBreakGlass = async (project: ProjectListItem) => {
    if (!(await confirm(`Close your break-glass access to "${project.name}" now? You keep reading it by oversight.`, 'Close break-glass', { confirmLabel: 'Close it' }))) return
    try {
      await fetchOk(`/api/projects/${project.id}/breakglass`, { method: 'DELETE' }, 'Could not close break-glass')
      toast.success('Break-glass closed')
    } catch (error) {
      alertError(errorMessage(error, 'Could not close break-glass'))
    }
    oversight.refetch()
  }

  // A card of the oversight list: its owner and how the admin reaches it, opened read only; Root's
  // break-glass controls on someone else's project.
  const renderOversightCard = (project: ProjectListItem) => {
    const access = project.myAccess
    if (!access || access.level === 'owner') return renderCard(project)
    const owner = sharedByLabel(project)
    const glassOpen = access.via === 'break_glass'
    const action = canBreakGlass ? (
      <button
        type="button"
        className="iconButton"
        title={glassOpen ? 'Close break-glass' : 'Break-glass: read everything, raw data included'}
        aria-label={glassOpen ? `Close break-glass on ${project.name}` : `Open break-glass on ${project.name}`}
        onClick={(e) => {
          e.stopPropagation()
          if (glassOpen) void closeBreakGlass(project)
          else setGlassTarget({ id: project.id, name: project.name, owner })
        }}
      >
        {glassOpen ? <ShieldOff size={14} /> : <ShieldAlert size={14} />}
      </button>
    ) : undefined
    return (
      <ProjectCard
        key={project.id}
        id={project.id}
        name={project.name}
        target={projectTargetLabel(project)}
        description={project.description}
        createdAt={project.createdAt}
        ownedBy={owner}
        accessLabel={accessBadge(access)}
        extraActions={action}
        onSelect={() => handleSelectProject(project)}
      />
    )
  }

  // Leaving the open project asks its access at once: the provider then leads out and says the
  // access ended, so no toast of our own.
  const handleLeft = (project: ProjectListItem) => {
    if (currentProject?.id === project.id) void checkAccessNow?.()
    void refetch()
  }

  // Step 4.12: Share on the person's own card, Leave on a card shared with them, only while sharing
  // is in force (shareActions); each stops its click before the card opens the project.
  const shareControl = (project: ProjectListItem) => {
    const actions = shareActions(project, sharingInForce)
    if (actions.leave) {
      return (
        <LeaveShareButton
          project={{ id: project.id, name: project.name }}
          announce={currentProject?.id !== project.id}
          onLeft={() => handleLeft(project)}
        />
      )
    }
    if (!actions.share) return undefined
    const refusal = refusalOf('project:share', project.myAccess)
    return (
      <button
        type="button"
        className="iconButton"
        title={refusal ? refusal.text : 'Share this project'}
        aria-label={`Share ${project.name}`}
        aria-disabled={refusal ? true : undefined}
        onClick={(e) => {
          e.stopPropagation()
          if (!refusal) setShareTarget({ id: project.id, name: project.name })
        }}
      >
        <Share2 size={14} />
      </button>
    )
  }

  // A shared project's card names its owner and the person's level, and offers no delete (the
  // owner's alone), wherever it is listed.
  const renderCard = (project: ProjectListItem) => {
    const sharedRow = isSharedWithMe(project)
    return (
      <ProjectCard
        key={project.id}
        id={project.id}
        name={project.name}
        target={projectTargetLabel(project)}
        description={project.description}
        createdAt={project.createdAt}
        sharedBy={sharedRow ? sharedByLabel(project) : undefined}
        accessLabel={sharedRow && project.myAccess ? accessBadge(project.myAccess) : undefined}
        extraActions={shareControl(project)}
        onSelect={() => handleSelectProject(project)}
        onDelete={sharedRow ? undefined : () => handleDeleteProject(project.id)}
      />
    )
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <FolderOpen size={20} />
          <h1 className={styles.title}>Projects</h1>
          <WikiInfoButton target="projects" title="Open Creating a Project wiki page" />
        </div>
        <div className={styles.headerActions}>
          <button
            className="iconButton"
            onClick={() => refetch()}
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
          {userId && (
            <button
              className="secondaryButton"
              onClick={() => setShowImportModal(true)}
              title="Import project from backup"
            >
              <Upload size={14} />
              Import Project
            </button>
          )}
          {userId ? (
            <Link href="/projects/new" className="primaryButton">
              <Plus size={14} />
              New Project
            </Link>
          ) : (
            <button className="primaryButton" disabled>
              <Plus size={14} />
              New Project
            </button>
          )}
        </div>
      </div>

      {canReadUsers && (
        <div className={styles.userSelector}>
          <div className={styles.userSelectorLabel}>
            <Users size={14} />
            <span>User:</span>
          </div>
          <select
            className="select"
            aria-label="User"
            value={userId || ''}
            onChange={(e) => {
              const id = e.target.value || null
              // The act-as dialog names the account by name, email and type, not by its id.
              const target = rbacOn && id ? actAsTarget(id) : undefined
              void setUserId(id, target ? { target } : undefined)
            }}
            disabled={!canSwitchUser}
            title={canSwitchUser ? undefined : 'Acting as another user needs the users:impersonate permission'}
          >
            <option value="">Select a user</option>
            {users?.map((user) => (
              <option key={user.id} value={user.id}>
                {user.name} ({user.email})
              </option>
            ))}
          </select>
          {canCreateUsers && (sharingInForce ? (
            // ID-12: with sharing in force no passwordless account is offered, and this quick form
            // makes nothing else; the Users page creates one with a password or an invite.
            <Link
              href="/settings/users"
              className="secondaryButton"
              title="With sharing on, accounts are created with a password or an invite on the Users page"
            >
              <Plus size={12} />
              New User
            </Link>
          ) : (
            <button
              className="secondaryButton"
              onClick={() => setShowUserModal(true)}
            >
              <Plus size={12} />
              New User
            </button>
          ))}
          {canDeleteUsers && userId && (
            <button
              className="iconButton"
              onClick={handleDeleteUser}
              disabled={deleteUserMutation.isPending}
              title="Delete selected user"
              aria-label="Delete selected user"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      )}

      {isLoading ? (
        <div className={styles.loading}>Loading...</div>
      ) : projectsError && !projects ? (
        <div className={styles.empty} role="alert">
          <AlertTriangle size={48} />
          <h2>Could not load the projects</h2>
          <p>{errorMessage(projectsError, 'Failed to fetch projects')}</p>
          <button className="secondaryButton" onClick={() => refetch()}>
            <RefreshCw size={14} />
            Retry
          </button>
        </div>
      ) : showFilter ? (
        <>
          <div className={styles.listFilter} role="group" aria-label="Show projects">
            {filters.map(f => (
              <button
                key={f.value}
                type="button"
                className={`secondaryButton ${listFilter === f.value ? styles.listFilterActive : ''}`}
                aria-pressed={listFilter === f.value}
                onClick={() => setListFilter(f.value)}
              >
                {f.label}
              </button>
            ))}
          </div>
          {listFilter === 'oversight' && (
            <section className={styles.listSection} aria-labelledby="projects-oversight-heading">
              <h2 id="projects-oversight-heading" className={styles.sectionTitle}>All projects (oversight)</h2>
              <p className={styles.sectionNote}>
                Read only, without raw data and files. Opening a project is recorded in its activity, which its owner sees.
              </p>
              {oversight.isLoading && !oversight.data ? (
                <div className={styles.loading} role="status">Loading every project...</div>
              ) : oversight.error && !oversight.data ? (
                <div className={styles.sectionEmpty} role="alert">
                  <p>{errorMessage(oversight.error, 'Could not list every project')}</p>
                  <button className="secondaryButton" onClick={() => oversight.refetch()}>
                    <RefreshCw size={14} />
                    Retry
                  </button>
                </div>
              ) : oversight.data && oversight.data.length > 0 ? (
                <div className={styles.grid}>{oversight.data.map(renderOversightCard)}</div>
              ) : (
                <div className={styles.sectionEmpty}><p>There are no projects on this instance yet.</p></div>
              )}
            </section>
          )}
          {listFilter !== 'shared' && listFilter !== 'oversight' && (
            <section className={styles.listSection} aria-labelledby="projects-owned-heading">
              <h2 id="projects-owned-heading" className={styles.sectionTitle}>My projects</h2>
              {owned.length > 0 ? (
                <div className={styles.grid}>{owned.map(renderCard)}</div>
              ) : (
                <div className={styles.sectionEmpty}>
                  <p>You have no projects of your own yet.</p>
                  {userId && (
                    <Link href="/projects/new" className="secondaryButton">
                      <Plus size={14} />
                      Create Project
                    </Link>
                  )}
                </div>
              )}
            </section>
          )}
          {listFilter !== 'owned' && listFilter !== 'oversight' && showShared && (
            <section className={styles.listSection} aria-labelledby="projects-shared-heading">
              <h2 id="projects-shared-heading" className={styles.sectionTitle}>Shared with me</h2>
              <div className={styles.grid}>{shared.map(renderCard)}</div>
            </section>
          )}
        </>
      ) : projects && projects.length > 0 ? (
        <div className={styles.grid}>{projects.map(renderCard)}</div>
      ) : (
        <div className={styles.empty}>
          <FolderOpen size={48} />
          <h2>No Projects Yet</h2>
          <p>Create your first project to get started with reconnaissance.</p>
          {userId ? (
            <Link href="/projects/new" className="primaryButton">
              <Plus size={14} />
              Create Project
            </Link>
          ) : (
            <button className="primaryButton" disabled>
              <Plus size={14} />
              Create Project
            </button>
          )}
        </div>
      )}

      {shareTarget && <ShareDialog project={shareTarget} onClose={() => setShareTarget(null)} />}

      {glassTarget && (
        <BreakGlassDialog
          isOpen
          target={glassTarget}
          onConfirm={openBreakGlass}
          onClose={() => setGlassTarget(null)}
        />
      )}

      {userId && (
        <ImportModal
          isOpen={showImportModal}
          userId={userId}
          onClose={() => setShowImportModal(false)}
          onSuccess={() => refetch()}
        />
      )}

      {canCreateUsers && showUserModal && !sharingInForce && (
        <div className={styles.modalOverlay} onClick={() => setShowUserModal(false)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <h2 className={styles.modalTitle}>Create New User</h2>
            <form onSubmit={handleCreateUser}>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">Name</label>
                <input
                  type="text"
                  className="textInput"
                  value={newUserName}
                  onChange={(e) => setNewUserName(e.target.value)}
                  placeholder="Enter user name"
                  required
                />
              </div>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">Email</label>
                <input
                  type="email"
                  className="textInput"
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  placeholder="Enter email address"
                  required
                />
              </div>
              <InitialSetPicker idPrefix="projects-create-user" value={newUserSet} onChange={setNewUserSet} />
              <div className={styles.modalActions}>
                <button
                  type="button"
                  className="secondaryButton"
                  onClick={() => setShowUserModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primaryButton"
                  disabled={createUserMutation.isPending}
                >
                  {createUserMutation.isPending ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
