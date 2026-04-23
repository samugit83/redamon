'use client'

import { useParams, useRouter } from 'next/navigation'
import { ProjectForm } from '@/components/projects'
import { useProjectById, useUpdateProject } from '@/hooks/useProjects'
import { useProject } from '@/providers/ProjectProvider'
import { useAlertModal } from '@/components/ui'
import styles from './page.module.css'

export default function ProjectSettingsPage() {
  const params = useParams()
  const router = useRouter()
  const projectId = params.id as string
  const { setCurrentProject } = useProject()

  const { data: project, isLoading, error } = useProjectById(projectId)
  const updateProjectMutation = useUpdateProject()
  const { alertError } = useAlertModal()

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const saveProject = async (data: any) => {
    const updated = await updateProjectMutation.mutateAsync({
      projectId,
      data
    })

    setCurrentProject({
      id: updated.id,
      name: updated.name,
      targetDomain: updated.targetDomain,
      subdomainList: updated.subdomainList,
      description: updated.description || undefined,
      createdAt: updated.createdAt.toString(),
      updatedAt: updated.updatedAt.toString()
    })

    return updated
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleSubmit = async (data: any) => {
    try {
      await saveProject(data)
      router.push(`/graph?project=${projectId}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to update project'
      if (message.toLowerCase().includes('guardrail')) {
        throw error
      }
      alertError(message)
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleSaveAndStay = async (data: any) => {
    await saveProject(data)
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
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.container}>
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
