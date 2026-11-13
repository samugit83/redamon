'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Project } from '@prisma/client'
import { fetchJson, fetchOk } from '@/lib/apiError'
import type { MyAccess } from '@/lib/authz/projectAccess'

// Lighter type for project list
export interface ProjectListItem {
  id: string
  userId: string
  name: string
  description: string | null
  targetDomain: string
  subdomainList?: string[]
  /** The scope fields, when the list route sends them: a batch row's
   *  targetDomain is empty, and its target is derived from domainBatchHosts. */
  ipMode?: boolean
  targetIps?: string[]
  domainBatchMode?: boolean
  domainBatchHosts?: string[]
  createdAt: string
  updatedAt: string
  user: {
    id: string
    name: string
    email: string
  }
  /** RBAC_SHARING_ENABLED on: the person's own access (owner, or a share at read); absent off. */
  myAccess?: MyAccess
}

// Full project type
export type FullProject = Project & {
  user: {
    id: string
    name: string
    email: string
  }
}

// Every fetcher throws an ApiError, whose message carries the route's code and
// the HTTP status, so the callers' `error.message` displays name the cause.

// Fetch all projects or filter by userId
async function fetchProjects(userId?: string): Promise<ProjectListItem[]> {
  const url = userId ? `/api/projects?userId=${userId}` : '/api/projects'
  return fetchJson<ProjectListItem[]>(url, undefined, 'Failed to fetch projects')
}

// Fetch a single project by ID
async function fetchProject(projectId: string): Promise<FullProject> {
  return fetchJson<FullProject>(`/api/projects/${projectId}`, undefined, 'Failed to fetch project')
}

// Create a new project
async function createProject(data: {
  userId: string
  name: string
  targetDomain: string
  roeFile?: File | null
  [key: string]: unknown
}): Promise<FullProject> {
  const { roeFile, ...projectData } = data

  let init: RequestInit
  if (roeFile) {
    // Multipart: include the RoE document file
    const formData = new FormData()
    formData.append('data', JSON.stringify(projectData))
    formData.append('roeDocument', roeFile)
    init = {
      method: 'POST',
      body: formData,
    }
  } else {
    init = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(projectData),
    }
  }

  return fetchJson<FullProject>('/api/projects', init, 'Failed to create project')
}

// Update a project
async function updateProject(projectId: string, data: Partial<Project>): Promise<FullProject> {
  return fetchJson<FullProject>(`/api/projects/${projectId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }, 'Failed to update project')
}

// Delete a project
async function deleteProject(projectId: string): Promise<void> {
  await fetchOk(`/api/projects/${projectId}`, {
    method: 'DELETE'
  }, 'Failed to delete project')
}

// Hook to fetch all projects
export function useProjects(userId?: string) {
  return useQuery({
    queryKey: ['projects', userId],
    queryFn: () => fetchProjects(userId),
  })
}

// Hook to fetch a single project
export function useProjectById(projectId: string | null) {
  return useQuery({
    queryKey: ['project', projectId],
    queryFn: () => fetchProject(projectId!),
    enabled: !!projectId,
  })
}

// Hook for creating a project
export function useCreateProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: createProject,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] })
    }
  })
}

// Hook for updating a project
export function useUpdateProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ projectId, data }: { projectId: string; data: Partial<Project> }) =>
      updateProject(projectId, data),
    onSuccess: (project) => {
      queryClient.invalidateQueries({ queryKey: ['projects'] })
      queryClient.invalidateQueries({ queryKey: ['project', project.id] })
    }
  })
}

// Hook for deleting a project
export function useDeleteProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: deleteProject,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] })
    }
  })
}
