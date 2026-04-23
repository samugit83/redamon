import type { Project } from '@prisma/client'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

export interface ReconPreset {
  id: string
  name: string
  icon: string
  image?: string
  shortDescription: string
  fullDescription: string
  parameters: Partial<ProjectFormData>
}
