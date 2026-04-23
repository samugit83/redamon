'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface User {
  id: string
  name: string
  email: string
  role: string
  hasPassword: boolean
  createdAt: string
  updatedAt: string
  _count?: {
    projects: number
  }
}

export interface UserWithProjects extends User {
  projects: {
    id: string
    name: string
    targetDomain: string
    createdAt: string
    updatedAt: string
  }[]
}

// Fetch all users
async function fetchUsers(): Promise<User[]> {
  const response = await fetch('/api/users')
  if (!response.ok) {
    throw new Error('Failed to fetch users')
  }
  return response.json()
}

// Fetch a single user by ID
async function fetchUser(userId: string): Promise<UserWithProjects> {
  const response = await fetch(`/api/users/${userId}`)
  if (!response.ok) {
    throw new Error('Failed to fetch user')
  }
  return response.json()
}

// Create a new user
async function createUser(data: { name: string; email: string; password?: string; role?: string }): Promise<User> {
  const response = await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || 'Failed to create user')
  }
  return response.json()
}

// Update a user
async function updateUser(userId: string, data: Partial<{ name: string; email: string; role: string }>): Promise<User> {
  const response = await fetch(`/api/users/${userId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || 'Failed to update user')
  }
  return response.json()
}

// Delete a user
async function deleteUser(userId: string): Promise<void> {
  const response = await fetch(`/api/users/${userId}`, {
    method: 'DELETE'
  })
  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || 'Failed to delete user')
  }
}

// Change user password
async function changePassword(userId: string, data: { newPassword: string; currentPassword?: string }): Promise<void> {
  const response = await fetch(`/api/users/${userId}/password`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || 'Failed to change password')
  }
}

// Hook to fetch all users
export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: fetchUsers,
  })
}

// Hook to fetch a single user
export function useUserById(userId: string | null) {
  return useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetchUser(userId!),
    enabled: !!userId,
  })
}

// Hook for creating a user
export function useCreateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    }
  })
}

// Hook for updating a user
export function useUpdateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: Partial<{ name: string; email: string; role: string }> }) =>
      updateUser(userId, data),
    onSuccess: (user) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['user', user.id] })
    }
  })
}

// Hook for deleting a user
export function useDeleteUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    }
  })
}

// Hook for changing password
export function useChangePassword() {
  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: { newPassword: string; currentPassword?: string } }) =>
      changePassword(userId, data),
  })
}
