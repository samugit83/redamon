'use client'

import { useState, useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { useUsers, useCreateUser, useDeleteUser, useChangePassword } from '@/hooks/useUsers'
import { Modal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { LegacyAccessCard } from '@/components/admin/LegacyAccessCard'
import { WhatChangedCard } from '@/components/admin/WhatChangedCard'
import { AccountStatusActions, AccountStatusBadge } from '@/components/admin/AccountStatusActions'
import { RoleControl } from '@/components/admin/RoleControl'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import styles from './page.module.css'

type ModalState =
  | { type: 'none' }
  | { type: 'create' }
  | { type: 'password'; userId: string; userName: string; targetIsAdmin: boolean }
  | { type: 'delete'; userId: string; userName: string }
  | { type: 'deleteAdmin'; userId: string; userName: string }
  | { type: 'changeOwn' }

export default function UsersPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { user: authUser, isAdmin, isLoading: authLoading } = useAuth()
  const { data: users, isLoading, error: usersError, refetch: refetchUsers } = useUsers()
  const createUser = useCreateUser()
  const deleteUser = useDeleteUser()
  const changePasswordMutation = useChangePassword()

  const [modal, setModal] = useState<ModalState>({ type: 'none' })
  const [formError, setFormError] = useState('')
  const [formSuccess, setFormSuccess] = useState('')

  // Form fields
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [role, setRole] = useState('standard')
  const [currentPassword, setCurrentPassword] = useState('')
  // The acting admin's own password, for a reset of another admin (step-up).
  const [stepUpPassword, setStepUpPassword] = useState('')

  const wantsPasswordChange = searchParams.get('changePassword') === 'true'

  // Handle ?changePassword=true from UserSelector for standard users
  useEffect(() => {
    if (wantsPasswordChange && authUser) {
      setModal({ type: 'changeOwn' })
      router.replace('/settings/users', { scroll: false })
    }
  }, [wantsPasswordChange, authUser, router])

  // Redirect non-admin to graph (unless they came for password change)
  useEffect(() => {
    if (!authLoading && !isAdmin && !wantsPasswordChange && modal.type !== 'changeOwn') {
      router.push('/graph')
    }
  }, [authLoading, isAdmin, wantsPasswordChange, modal, router])

  function resetForm() {
    setName('')
    setEmail('')
    setPassword('')
    setConfirmPassword('')
    setRole('standard')
    setCurrentPassword('')
    setStepUpPassword('')
    setFormError('')
    setFormSuccess('')
  }

  function openModal(state: ModalState) {
    resetForm()
    setModal(state)
  }

  function closeModal() {
    setModal({ type: 'none' })
    resetForm()
  }

  async function handleCreateUser() {
    setFormError('')
    if (!name || !email) {
      setFormError('Name and email are required')
      return
    }
    if (password) {
      const check = validateNewPassword(password)
      if (!check.ok) {
        setFormError(check.message)
        return
      }
    }
    if (password && password !== confirmPassword) {
      setFormError('Passwords do not match')
      return
    }

    // With the identity switch on only Root creates an admin, with its own password.
    const rootCreatesAdmin = authUser?.rbac?.identity === true && role === 'admin'
    if (rootCreatesAdmin && !stepUpPassword) {
      setFormError('Enter your password to create an admin')
      return
    }

    try {
      await createUser.mutateAsync({
        name,
        email,
        password: password || undefined,
        role,
        ...(rootCreatesAdmin ? { stepUpPassword } : {}),
      })
      closeModal()
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create user')
    }
  }

  async function handleSetPassword() {
    setFormError('')
    setFormSuccess('')
    const check = validateNewPassword(password)
    if (!check.ok) {
      setFormError(check.message)
      return
    }
    if (password !== confirmPassword) {
      setFormError('Passwords do not match')
      return
    }

    if (modal.type !== 'password') return
    const isOwnRow = modal.userId === authUser?.id
    if (isOwnRow && !currentPassword) {
      setFormError('Current password is required')
      return
    }
    if (!isOwnRow && modal.targetIsAdmin && !stepUpPassword) {
      setFormError('Enter your password to reset another admin\'s password')
      return
    }

    try {
      await changePasswordMutation.mutateAsync({
        userId: modal.userId,
        data: isOwnRow
          ? { newPassword: password, currentPassword }
          : modal.targetIsAdmin
            ? { newPassword: password, stepUpPassword }
            : { newPassword: password },
      })
      setFormSuccess('Password updated')
      setPassword('')
      setConfirmPassword('')
      setCurrentPassword('')
      setStepUpPassword('')
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to change password')
    }
  }

  async function handleChangeOwnPassword() {
    setFormError('')
    setFormSuccess('')
    if (!currentPassword) {
      setFormError('Current password is required')
      return
    }
    const check = validateNewPassword(password)
    if (!check.ok) {
      setFormError(check.message)
      return
    }
    if (password !== confirmPassword) {
      setFormError('Passwords do not match')
      return
    }
    if (!authUser) return

    try {
      await changePasswordMutation.mutateAsync({
        userId: authUser.id,
        data: { newPassword: password, currentPassword },
      })
      setFormSuccess('Password updated successfully')
      setCurrentPassword('')
      setPassword('')
      setConfirmPassword('')
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to change password')
    }
  }

  async function handleDeleteUser() {
    if (modal.type !== 'delete') return
    setFormError('')

    try {
      await deleteUser.mutateAsync(modal.userId)
      closeModal()
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to delete user')
    }
  }

  // Show change password modal for standard users
  if (!isAdmin && modal.type === 'changeOwn') {
    return (
      <div className={styles.page}>
        <Modal isOpen onClose={closeModal} title="Change Password" size="small">
          <div className={styles.form}>
            {formError && <div className={styles.error}>{formError}</div>}
            {formSuccess && <div className={styles.success}>{formSuccess}</div>}
            <div className={styles.field}>
              <label className={styles.label}>Current Password</label>
              <input
                type="password"
                className={styles.input}
                value={currentPassword}
                onChange={e => setCurrentPassword(e.target.value)}
                autoFocus
              />
            </div>
            <div className={styles.field}>
              <label className={styles.label}>New Password</label>
              <input
                type="password"
                className={styles.input}
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>
            <div className={styles.field}>
              <label className={styles.label}>Confirm New Password</label>
              <input
                type="password"
                className={styles.input}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
              />
            </div>
            <div className={styles.modalActions}>
              <button className={styles.actionButton} onClick={closeModal}>Cancel</button>
              <button
                className="primaryButton"
                onClick={handleChangeOwnPassword}
                disabled={changePasswordMutation.isPending}
              >
                {changePasswordMutation.isPending ? 'Saving...' : 'Change Password'}
              </button>
            </div>
          </div>
        </Modal>
      </div>
    )
  }

  if (!isAdmin) return null

  const setOwnRow = modal.type === 'password' && modal.userId === authUser?.id
  const setAnotherAdmin = modal.type === 'password' && !setOwnRow && modal.targetIsAdmin
  // Identity switch on: other admins' accounts are the confirmed Root's, with its password (step 2.6).
  const identity = authUser?.rbac?.identity === true
  const confirmedRoot = identity && authUser?.accountType === 'root' && authUser?.rbac?.root?.confirmed === true
  const manageAdmins = !identity || confirmedRoot
  const createsAdminWithPassword = identity && role === 'admin'

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>User Management</h1>
        <button className="primaryButton" onClick={() => openModal({ type: 'create' })}>
          Create User
        </button>
      </div>

      <WhatChangedCard />
      <LegacyAccessCard />

      {isLoading ? (
        <div className={styles.empty}>Loading users...</div>
      ) : usersError ? (
        <div className={styles.error} role="alert">{usersError.message}</div>
      ) : !users || users.length === 0 ? (
        <div className={styles.empty}>No users found</div>
      ) : (
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.th}>Name</th>
              <th className={styles.th}>Email</th>
              <th className={styles.th}>Role</th>
              <th className={styles.th}>Password</th>
              <th className={styles.th}>Projects</th>
              <th className={styles.th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className={styles.tr}>
                <td className={styles.td}>
                  {user.name}
                  {user.id === authUser?.id && <span className={styles.selfLabel}>(you)</span>}
                  <AccountStatusBadge status={user.status} className={`${styles.badge} ${styles.badgeDisabled}`} />
                </td>
                <td className={styles.td}>
                  <span className={styles.email}>{user.email}</span>
                </td>
                <td className={styles.td}>
                  {manageAdmins && user.id !== authUser?.id ? (
                    <RoleControl
                      user={user}
                      identity={identity}
                      className={styles.select}
                      onChanged={() => void refetchUsers?.()}
                    />
                  ) : (
                    <span className={`${styles.badge} ${user.role === 'admin' ? styles.badgeAdmin : styles.badgeStandard}`}>
                      {user.role}
                    </span>
                  )}
                </td>
                <td className={styles.td}>
                  {user.hasPassword ? (
                    <span className={`${styles.badge} ${styles.badgeYes}`}>Set</span>
                  ) : (
                    <span className={styles.badgeNo}>Not set</span>
                  )}
                </td>
                <td className={styles.td}>{user._count?.projects ?? 0}</td>
                <td className={styles.td}>
                  <div className={styles.actions}>
                    {(user.id === authUser?.id || user.role !== 'admin' || manageAdmins) && (
                      <button
                        className={styles.actionButton}
                        onClick={() => openModal({
                          type: 'password', userId: user.id, userName: user.name, targetIsAdmin: user.role === 'admin',
                        })}
                      >
                        Set Password
                      </button>
                    )}
                    {user.id !== authUser?.id && (user.role !== 'admin' || manageAdmins) && (
                      <button
                        className={`${styles.actionButton} ${styles.deleteButton}`}
                        onClick={() => openModal({
                          type: user.role === 'admin' ? 'deleteAdmin' : 'delete', userId: user.id, userName: user.name,
                        })}
                      >
                        Delete
                      </button>
                    )}
                    <AccountStatusActions
                      user={user}
                      selfId={authUser?.id}
                      identity={identity}
                      manageAdmins={confirmedRoot}
                      buttonClassName={styles.actionButton}
                      dangerClassName={styles.deleteButton}
                      onChanged={() => void refetchUsers?.()}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Create User Modal */}
      <Modal isOpen={modal.type === 'create'} onClose={closeModal} title="Create User">
        <div className={styles.form}>
          {formError && <div className={styles.error}>{formError}</div>}
          <div className={styles.field}>
            <label className={styles.label} htmlFor="create-user-name">Name *</label>
            <input
              id="create-user-name"
              className={styles.input}
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="John Doe"
              autoFocus
            />
          </div>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="create-user-email">Email *</label>
            <input
              id="create-user-email"
              type="email"
              className={styles.input}
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="john@example.com"
            />
          </div>
          <div className={styles.field}>
            <label className={styles.label}>Password</label>
            <input
              type="password"
              className={styles.input}
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Leave empty for passwordless user"
            />
            <span className={styles.hint}>Passwordless users can only be accessed via admin switching</span>
          </div>
          {password && (
            <div className={styles.field}>
              <label className={styles.label}>Confirm Password</label>
              <input
                type="password"
                className={styles.input}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
              />
            </div>
          )}
          <div className={styles.field}>
            <label className={styles.label} htmlFor="create-user-role">Role</label>
            <select id="create-user-role" className={styles.select} value={role} onChange={e => setRole(e.target.value)}>
              <option value="standard">Standard</option>
              {manageAdmins && <option value="admin">Admin</option>}
            </select>
            {!manageAdmins && <span className={styles.hint}>Only Root creates admin accounts.</span>}
          </div>
          {createsAdminWithPassword && (
            <div className={styles.field}>
              <label className={styles.label} htmlFor="create-user-step-up">Your password</label>
              <input
                id="create-user-step-up"
                type="password"
                className={styles.input}
                value={stepUpPassword}
                onChange={e => setStepUpPassword(e.target.value)}
                autoComplete="current-password"
              />
              <span className={styles.hint}>Creating an admin is Root&apos;s action: confirm it with your own password.</span>
            </div>
          )}
          <div className={styles.modalActions}>
            <button className={styles.actionButton} onClick={closeModal}>Cancel</button>
            <button
              className="primaryButton"
              onClick={handleCreateUser}
              disabled={createUser.isPending}
            >
              {createUser.isPending ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Set Password Modal */}
      <Modal
        isOpen={modal.type === 'password'}
        onClose={closeModal}
        title={`Set Password - ${modal.type === 'password' ? modal.userName : ''}`}
        size="small"
      >
        <div className={styles.form}>
          {formError && <div className={styles.error}>{formError}</div>}
          {formSuccess && <div className={styles.success}>{formSuccess}</div>}
          {setOwnRow && (
            <div className={styles.field}>
              <label className={styles.label} htmlFor="set-password-current">Current Password</label>
              <input
                id="set-password-current"
                type="password"
                className={styles.input}
                value={currentPassword}
                onChange={e => setCurrentPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            </div>
          )}
          <div className={styles.field}>
            <label className={styles.label} htmlFor="set-password-new">New Password</label>
            <input
              id="set-password-new"
              type="password"
              className={styles.input}
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="new-password"
              autoFocus={!setOwnRow}
            />
          </div>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="set-password-confirm">Confirm Password</label>
            <input
              id="set-password-confirm"
              type="password"
              className={styles.input}
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
            />
          </div>
          {setAnotherAdmin && (
            <div className={styles.field}>
              <label className={styles.label} htmlFor="set-password-step-up">Your password</label>
              <input
                id="set-password-step-up"
                type="password"
                className={styles.input}
                value={stepUpPassword}
                onChange={e => setStepUpPassword(e.target.value)}
                autoComplete="current-password"
              />
              <span className={styles.hint}>This account is an admin: confirm the reset with your own password.</span>
            </div>
          )}
          <div className={styles.modalActions}>
            <button className={styles.actionButton} onClick={closeModal}>Cancel</button>
            <button
              className="primaryButton"
              onClick={handleSetPassword}
              disabled={changePasswordMutation.isPending}
            >
              {changePasswordMutation.isPending ? 'Saving...' : 'Set Password'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={modal.type === 'delete'}
        onClose={closeModal}
        title="Delete User"
        size="small"
      >
        <div className={styles.form}>
          {formError && <div className={styles.error}>{formError}</div>}
          <p style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)' }}>
            Are you sure you want to delete <strong>{modal.type === 'delete' ? modal.userName : ''}</strong>?
            This will also delete all their projects, conversations, and settings.
          </p>
          <div className={styles.modalActions}>
            <button className={styles.actionButton} onClick={closeModal}>Cancel</button>
            <button
              className={`${styles.actionButton} ${styles.deleteButton}`}
              onClick={handleDeleteUser}
              disabled={deleteUser.isPending}
              style={{ borderColor: 'var(--status-error)' }}
            >
              {deleteUser.isPending ? 'Deleting...' : 'Delete User'}
            </button>
          </div>
        </div>
      </Modal>

      <StepUpModal
        isOpen={modal.type === 'deleteAdmin'}
        title="Delete an admin"
        message={`Delete ${modal.type === 'deleteAdmin' ? modal.userName : ''}, an admin account? This also deletes their projects, conversations and settings. Confirm with your own password.`}
        confirmLabel="Delete User"
        onConfirm={async (pw) => {
          if (modal.type !== 'deleteAdmin') return
          await deleteUser.mutateAsync({ userId: modal.userId, stepUpPassword: pw })
        }}
        onClose={closeModal}
      />
    </div>
  )
}
