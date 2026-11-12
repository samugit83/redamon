'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchJson, fetchOk } from '@/lib/apiError'

export interface User {
  id: string
  name: string
  email: string
  role: string
  /** active | invited | disabled */
  status?: string
  hasPassword: boolean
  /** The last sign-in (ISO), null when none is recorded (step 2.12, ID-27). */
  lastLoginAt?: string | null
  /** Identity switch on only: the password must change at the next sign-in. */
  mustChangePassword?: boolean
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
  return fetchJson<User[]>('/api/users', undefined, 'Failed to fetch users')
}

// Fetch a single user by ID
async function fetchUser(userId: string): Promise<UserWithProjects> {
  return fetchJson<UserWithProjects>(`/api/users/${userId}`, undefined, 'Failed to fetch user')
}

/**
 * Creating an admin with the identity switch on carries Root's own password (step-up, step 2.6).
 */
export interface CreateUserData {
  name: string
  email: string
  password?: string
  role?: string
  stepUpPassword?: string
  /** Identity switch on: the password is temporary, changed at the first sign-in (default true). */
  requirePasswordChange?: boolean
}

// Create a new user
async function createUser(data: CreateUserData): Promise<User> {
  return fetchJson<User>('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }, 'Failed to create user')
}

/**
 * A role change of another admin, and with the identity switch on any change Root makes to
 * another admin or a promotion, carries the acting admin's own password (step-up).
 */
export type UpdateUserData = Partial<{ name: string; email: string; role: string; stepUpPassword: string }>

// Update a user
async function updateUser(userId: string, data: UpdateUserData): Promise<User> {
  return fetchJson<User>(`/api/users/${userId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }, 'Failed to update user')
}

/** Deleting another admin carries the acting admin's own password (step-up). */
export type DeleteUserArg = string | { userId: string; stepUpPassword: string }

async function deleteUser(arg: DeleteUserArg): Promise<void> {
  if (typeof arg === 'string') {
    await fetchOk(`/api/users/${arg}`, { method: 'DELETE' }, 'Failed to delete user')
    return
  }
  await fetchOk(`/api/users/${arg.userId}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ stepUpPassword: arg.stepUpPassword }),
  }, 'Failed to delete user')
}

/**
 * `currentPassword` for your own password; `stepUpPassword` (your own) when an admin
 * resets another admin's.
 */
export interface ChangePasswordData {
  newPassword: string
  currentPassword?: string
  stepUpPassword?: string
  /** Identity switch on, someone else's password: changed at the next sign-in (default true). */
  requirePasswordChange?: boolean
  /** Identity switch on, someone else's password (a reset, step 2.10): shown to the person. */
  reason?: string
}

async function changePassword(userId: string, data: ChangePasswordData): Promise<void> {
  await fetchOk(`/api/users/${userId}/password`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }, 'Failed to change password')
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
    mutationFn: ({ userId, data }: { userId: string; data: UpdateUserData }) =>
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
    mutationFn: ({ userId, data }: { userId: string; data: ChangePasswordData }) =>
      changePassword(userId, data),
  })
}
