'use client'

import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { ProjectForm } from '@/components/projects'
import { useProjectById, useUpdateProject } from '@/hooks/useProjects'
import { useProject } from '@/providers/ProjectProvider'
import { useOptionalAuth } from '@/providers/AuthProvider'
import { toProjectSummary } from '@/lib/projectSummary'
import { errorMessage } from '@/lib/apiError'
import styles from './page.module.css'

export default function ProjectSettingsPage() {
  const params = useParams()
  const router = useRouter()
  const projectId = params.id as string
  const { setCurrentProject } = useProject()

  const { data: project, isLoading, error } = useProjectById(projectId)
  const updateProjectMutation = useUpdateProject()
  const sharingInForce = useOptionalAuth()?.user?.sharing?.enabled === true

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const saveProject = async (data: any) => {
    const updated = await updateProjectMutation.mutateAsync({
      projectId,
      data
    })

    setCurrentProject(toProjectSummary(updated))

    return updated
  }

  // A failed save must reach the form, which alerts it and keeps the edits
  // marked unsaved. Swallowing it here made the form read "No unsaved changes"
  // after a refusal (a 409 from a stale form included) that saved nothing.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleSubmit = async (data: any) => {
    const updated = await saveProject(data)
    router.push(`/graph?project=${projectId}`)
    return updated
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleSaveAndStay = async (data: any) => {
    return saveProject(data)
  }

  const handleCancel = () => {
    router.back()
  }

  if (isLoading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Loading project settings...</div>
      </div>
    )
  }

  if (error || !project) {
    return (
      <div className={styles.container}>
        <div className={styles.error}>
          <p>Failed to load project settings.</p>
          {error && <p>{errorMessage(error, 'Failed to fetch project')}</p>}
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  // The feed answers the owner and an admin reading by oversight or break-glass, not a read
  // collaborator (step 4.13); it exists only while sharing is in force.
  const via = (project as { myAccess?: { via?: string } }).myAccess?.via
  const showActivity = sharingInForce && via !== undefined && via !== 'share'

  return (
    <div className={styles.container}>
      {showActivity && (
        <nav className={styles.pageLinks} aria-label="Project pages">
          <Link href={`/projects/${encodeURIComponent(projectId)}/activity`}>Activity</Link>
        </nav>
      )}
      <ProjectForm
        mode="edit"
        initialData={project}
        projectIdFromRoute={projectId}
        onSubmit={handleSubmit}
        onSaveAndStay={handleSaveAndStay}
        onCancel={handleCancel}
        isSubmitting={updateProjectMutation.isPending}
      />
    </div>
  )
}
