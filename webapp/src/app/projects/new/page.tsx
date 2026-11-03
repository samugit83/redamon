'use client'

import { useRouter } from 'next/navigation'
import { ProjectForm } from '@/components/projects'
import { useCreateProject } from '@/hooks/useProjects'
import { useProject } from '@/providers/ProjectProvider'
import { toProjectSummary } from '@/lib/projectSummary'
import type { Project } from '@prisma/client'
import { useAlertModal, useToast } from '@/components/ui'
import styles from './page.module.css'
import { rememberedDefaults } from '@/lib/agentInTheLoop'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

export default function NewProjectPage() {
  const router = useRouter()
  const { userId, setCurrentProject } = useProject()
  const createProjectMutation = useCreateProject()
  const { alertError, alertWarning } = useAlertModal()
  const toast = useToast()

  const createProject = async (data: ProjectFormData & { roeFile?: File | null }) => {
    if (!userId) {
      await alertWarning('Please select a user first')
      router.push('/projects')
      return null
    }

    const { roeFile, ...projectData } = data
    const project = await createProjectMutation.mutateAsync({
      ...projectData,
      userId,
      name: projectData.name,
      targetDomain: projectData.targetDomain,
      roeFile,
    })

    // Remember the chosen models so the next new project pre-fills them.
    // Fire-and-forget: a failure here must not block project creation.
    const defaults = rememberedDefaults(projectData.agentOpenaiModel, projectData.aiPipelineModel)
    if (defaults) {
      fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(defaults),
      }).catch(() => {})
    }

    setCurrentProject(toProjectSummary(project))

    return project
  }

  const handleSubmit = async (data: ProjectFormData & { roeFile?: File | null }) => {
    try {
      const project = await createProject(data)
      if (project) {
        toast.success('Project created')
        router.push(`/graph?project=${project.id}`)
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to create project'
      if (message.toLowerCase().includes('guardrail')) {
        throw error
      }
      alertError(message)
    }
  }

  const handleSaveAndStay = async (data: ProjectFormData & { roeFile?: File | null }) => {
    const project = await createProject(data)
    if (project) {
      toast.success('Project created')
      router.replace(`/projects/${project.id}/settings`)
    }
  }

  const handleCancel = () => {
    router.push('/projects')
  }

  if (!userId) {
    return (
      <div className={styles.container}>
        <div className={styles.message}>
          <p>Please select a user first before creating a project.</p>
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
        mode="create"
        onSubmit={handleSubmit}
        onSaveAndStay={handleSaveAndStay}
        onCancel={handleCancel}
        isSubmitting={createProjectMutation.isPending}
      />
    </div>
  )
}
