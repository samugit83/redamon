'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, FolderOpen, Users, RefreshCw, Trash2, Upload, AlertTriangle } from 'lucide-react'
import Link from 'next/link'
import { useProjects, useDeleteProject, type ProjectListItem } from '@/hooks/useProjects'
import { useUsers, useCreateUser, useDeleteUser } from '@/hooks/useUsers'
import { useProject } from '@/providers/ProjectProvider'
import { useCan } from '@/hooks/useCan'
import { ProjectCard } from '@/components/projects/ProjectCard'
import { InitialSetPicker, NO_INITIAL_SET, initialSetFields, type InitialSetChoice } from '@/components/admin/InitialSetPicker'
import { projectTargetLabel, toProjectSummary } from '@/lib/projectSummary'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { ImportModal } from './ImportModal'
import styles from './page.module.css'

export default function ProjectsPage() {
  const router = useRouter()
  const { userId, setUserId, setCurrentProject } = useProject()
  const { alertError, dangerConfirm } = useAlertModal()
  const toast = useToast()
  // The user bar is the directory's (UI-03): members never see it.
  const canReadUsers = useCan('users:read')
  const canSwitchUser = useCan('users:impersonate')
  const canCreateUsers = useCan('users:create')
  const canDeleteUsers = useCan('users:delete')
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

  // Clear stale userId if deleted, or auto-select first user on initial load
  useEffect(() => {
    if (!users) return
    if (userId && !users.find(u => u.id === userId)) {
      setUserId(users.length > 0 ? users[0].id : null)
      setCurrentProject(null)
    } else if (!hasAutoSelected.current && !userId && users.length > 0) {
      setUserId(users[0].id)
      hasAutoSelected.current = true
    }
  }, [userId, users, setUserId, setCurrentProject])

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
      setUserId(user.id)
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
            onChange={(e) => setUserId(e.target.value || null)}
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
          {canCreateUsers && (
            <button
              className="secondaryButton"
              onClick={() => setShowUserModal(true)}
            >
              <Plus size={12} />
              New User
            </button>
          )}
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
      ) : projects && projects.length > 0 ? (
        <div className={styles.grid}>
          {projects.map((project) => (
            <ProjectCard
              key={project.id}
              id={project.id}
              name={project.name}
              target={projectTargetLabel(project)}
              description={project.description}
              createdAt={project.createdAt}
              onSelect={() => handleSelectProject(project)}
              onDelete={() => handleDeleteProject(project.id)}
            />
          ))}
        </div>
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

      {userId && (
        <ImportModal
          isOpen={showImportModal}
          userId={userId}
          onClose={() => setShowImportModal(false)}
          onSuccess={() => refetch()}
        />
      )}

      {canCreateUsers && showUserModal && (
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
