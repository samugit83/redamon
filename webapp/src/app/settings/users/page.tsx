'use client'

import { useState, useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { useCan, useRbacFlags } from '@/hooks/useCan'
import { useUsers, useCreateUser, useDeleteUser, useChangePassword } from '@/hooks/useUsers'
import { Modal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { LegacyAccessCard } from '@/components/admin/LegacyAccessCard'
import { WhatChangedCard } from '@/components/admin/WhatChangedCard'
import { AccountStatusActions } from '@/components/admin/AccountStatusActions'
import { RoleControl } from '@/components/admin/RoleControl'
import { RootTransferAction } from '@/components/admin/RootTransferAction'
import { InviteRowActions, InviteUserModal } from '@/components/admin/InviteUserModal'
import { ResetCredentialsModal } from '@/components/admin/ResetCredentialsModal'
import { DeleteUserWizard, deletionWizardInForce } from '@/components/admin/DeleteUserWizard'
import { UserPermissionsPanel } from '@/components/admin/UserPermissionsPanel'
import { InitialSetPicker, NO_INITIAL_SET, initialSetFields, type InitialSetChoice } from '@/components/admin/InitialSetPicker'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { opensOwnPasswordDialog } from '@/components/auth/ownPasswordDialog'
import { ACCOUNT_TYPE_LABEL, IdentityLabel, accountTypeFor, type AccountType } from '@/components/auth/IdentityLabel'
import { BASE_PASSWORD_POLICY, validateNewPassword } from '@/lib/authz/passwordPolicy'
import { usePasswordPolicy } from '@/hooks/usePasswordPolicy'
import styles from './page.module.css'

type ModalState =
  | { type: 'none' }
  | { type: 'create' }
  | { type: 'invite' }
  | { type: 'password'; userId: string; userName: string; userEmail: string; targetIsAdmin: boolean }
  | { type: 'reset'; userId: string; userName: string; userEmail: string; targetIsAdmin: boolean }
  | { type: 'delete'; userId: string; userName: string }
  | { type: 'deleteAdmin'; userId: string; userName: string }
  | { type: 'deleteWizard'; userId: string; userName: string; targetIsAdmin: boolean }
  | { type: 'permissions'; userId: string; userName: string; userEmail: string }
  | { type: 'changeOwn' }

export default function UsersPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { user: authUser, isLoading: authLoading } = useAuth()
  // The page is the user directory's; each action shows only to whoever holds its permission.
  const canReadUsers = useCan('users:read')
  const canCreateUsers = useCan('users:create')
  const canDeleteUsers = useCan('users:delete')
  const canSwitchUser = useCan('users:impersonate')
  // Step 3.13: the permission panel, with the permissions switch on; an admin's is Root's or an
  // admins:manage holder's (the panel's API decides which admins).
  const permissionsOn = useRbacFlags()?.permissions === true
  const canAssignMembers = useCan('users:assign_permissions')
  const canManageAdmins = useCan('admins:manage')
  // Step 5.13: with write sharing switched on a delete goes through the deletion plan.
  const deletionWizard = deletionWizardInForce(useRbacFlags())
  const { data: users, isLoading, error: usersError, refetch: refetchUsers } = useUsers()
  const createUser = useCreateUser()
  const deleteUser = useDeleteUser()
  const changePasswordMutation = useChangePassword()
  // The policy in force (identity switch on); null keeps Phase 1's floor and shows no text.
  const passwordPolicy = usePasswordPolicy(authUser?.flags?.identity === true)
  const policyInForce = passwordPolicy ?? BASE_PASSWORD_POLICY

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
  // Identity switch on: a password set for someone else is temporary unless unticked (step 2.8).
  const [requireChange, setRequireChange] = useState(true)
  // Identity switch on, someone else's password: a reset, whose reason the person reads (step 2.10).
  const [reason, setReason] = useState('')
  // Permissions switch on: the set a new member starts with (step 3.13, ID-28).
  const [setChoice, setSetChoice] = useState<InitialSetChoice>(NO_INITIAL_SET)

  const wantsPasswordChange = searchParams.get('changePassword') === 'true'
  // Step 4.12 (ID-12, D-12): with sharing in force the create form stops offering passwordless
  // (managed) accounts; the route still takes one (OQ-12).
  const sharingInForce = authUser?.sharing?.enabled === true

  // Handle ?changePassword=true from UserSelector for standard users
  useEffect(() => {
    if (wantsPasswordChange && authUser) {
      setModal({ type: 'changeOwn' })
      router.replace('/settings/users', { scroll: false })
    }
  }, [wantsPasswordChange, authUser, router])

  // Redirect anyone who may not read the directory to graph (unless they came for password change)
  useEffect(() => {
    if (!authLoading && !canReadUsers && !wantsPasswordChange && modal.type !== 'changeOwn') {
      router.push('/graph')
    }
  }, [authLoading, canReadUsers, wantsPasswordChange, modal, router])

  function resetForm() {
    setName('')
    setEmail('')
    setPassword('')
    setConfirmPassword('')
    setRole('standard')
    setCurrentPassword('')
    setStepUpPassword('')
    setRequireChange(true)
    setReason('')
    setSetChoice(NO_INITIAL_SET)
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
    if (sharingInForce && !password) {
      setFormError('Enter a password: with sharing on, every new account signs in with its own password')
      return
    }
    if (password) {
      const check = validateNewPassword(password, policyInForce, { email })
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
    // The picker shows for a member only; an admin's sets are set afterwards in its panel.
    const setFields = role === 'standard' ? initialSetFields(setChoice) : {}
    if ('error' in setFields) {
      setFormError(setFields.error)
      return
    }

    try {
      await createUser.mutateAsync({
        name,
        email,
        password: password || undefined,
        role,
        ...(rootCreatesAdmin ? { stepUpPassword } : {}),
        ...(authUser?.rbac?.identity === true && password ? { requirePasswordChange: requireChange } : {}),
        ...setFields,
      })
      closeModal()
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create user')
    }
  }

  async function handleSetPassword() {
    setFormError('')
    setFormSuccess('')
    if (modal.type !== 'password') return
    const check = validateNewPassword(password, policyInForce, { email: modal.userEmail })
    if (!check.ok) {
      setFormError(check.message)
      return
    }
    if (password !== confirmPassword) {
      setFormError('Passwords do not match')
      return
    }

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
          : {
              newPassword: password,
              ...(modal.targetIsAdmin ? { stepUpPassword } : {}),
              ...(authUser?.rbac?.identity === true ? { requirePasswordChange: requireChange } : {}),
              ...(authUser?.rbac?.identity === true && reason.trim() ? { reason: reason.trim() } : {}),
            },
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
    const check = validateNewPassword(password, policyInForce, { email: authUser?.email })
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

  // ?changePassword=true opens it by the rule the user menu's Change Password follows.
  const ownPasswordOpen = modal.type === 'changeOwn'
    && opensOwnPasswordDialog({ readUsers: canReadUsers, switchUser: canSwitchUser, permissionsOn })
  const ownPasswordModal = (
        <Modal isOpen={ownPasswordOpen} onClose={closeModal} title="Change Password" size="small">
          <div className={styles.form}>
            {formError && <div className={styles.error}>{formError}</div>}
            {formSuccess && <div className={styles.success}>{formSuccess}</div>}
            <div className={styles.field}>
              <label className={styles.label} htmlFor="change-own-current">Current Password</label>
              <input
                id="change-own-current"
                type="password"
                className={styles.input}
                value={currentPassword}
                onChange={e => setCurrentPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            </div>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="change-own-new">New Password</label>
              <input
                id="change-own-new"
                type="password"
                className={styles.input}
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="new-password"
                aria-describedby={passwordPolicy ? 'change-own-policy' : undefined}
              />
              {passwordPolicy && <span id="change-own-policy" className={styles.hint}>{passwordPolicy.description}</span>}
            </div>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="change-own-confirm">Confirm New Password</label>
              <input
                id="change-own-confirm"
                type="password"
                className={styles.input}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
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
  )

  // Without the directory the dialog is the whole page; with it, the dialog opens over the directory.
  if (!canReadUsers && ownPasswordOpen) return <div className={styles.page}>{ownPasswordModal}</div>

  if (!canReadUsers) return null

  const setOwnRow = modal.type === 'password' && modal.userId === authUser?.id
  const setAnotherAdmin = modal.type === 'password' && !setOwnRow && modal.targetIsAdmin
  // Identity switch on: other admins' accounts are the confirmed Root's, with its password (step 2.6).
  const identity = authUser?.rbac?.identity === true
  const confirmedRoot = identity && authUser?.accountType === 'root' && authUser?.rbac?.root?.confirmed === true
  const manageAdmins = !identity || confirmedRoot
  const createsAdminWithPassword = identity && role === 'admin'
  // Identity switch on (step 2.11, ID-31): a dialog acting on an account names it by email and type.
  const targetId = identity && (modal.type === 'password' || modal.type === 'delete') ? modal.userId : null
  const modalTarget = targetId ? users?.find(u => u.id === targetId) ?? null : null
  // Nobody changes their own permissions, nor Root's (step 3.11); My account lists one's own.
  const mayAssign = (u: { id: string; role: string; email: string }) => {
    if (!permissionsOn || u.id === authUser?.id) return false
    const type = accountTypeFor(u, authUser?.rbac?.root)
    return type === 'member' ? canAssignMembers : type === 'admin' && canManageAdmins
  }
  const targetLabel = modalTarget && (
    <p className={styles.hint}>
      <IdentityLabel
        name={modalTarget.name}
        email={modalTarget.email}
        accountType={accountTypeFor(modalTarget, authUser?.rbac?.root)}
      />
    </p>
  )

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>User Management</h1>
        {!canCreateUsers ? null : identity ? (
          // Step 2.9 (ID-36): a link is the default, so the admin never knows a working password.
          <div className={styles.actions}>
            <button className="primaryButton" onClick={() => openModal({ type: 'invite' })}>
              Invite user
            </button>
            <button className={styles.actionButton} onClick={() => openModal({ type: 'create' })}>
              Create with a temporary password
            </button>
          </div>
        ) : (
          <button className="primaryButton" onClick={() => openModal({ type: 'create' })}>
            Create User
          </button>
        )}
      </div>

      <WhatChangedCard />
      <LegacyAccessCard />

      {isLoading ? (
        <div className={styles.empty} role="status">Loading users...</div>
      ) : forbiddenPermission(usersError) ? (
        <ForbiddenNotice permission={forbiddenPermission(usersError)!} />
      ) : usersError ? (
        <div className={styles.errorState}>
          <div className={styles.error} role="alert">{usersError.message}</div>
          <button type="button" className={styles.actionButton} onClick={() => void refetchUsers?.()}>Retry</button>
        </div>
      ) : !users || users.length === 0 ? (
        <div className={styles.empty}>No users found</div>
      ) : (
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.th}>Name</th>
              <th className={styles.th}>Email</th>
              {/* Identity switch on: Root, Admin or Member (ID-31); off, Phase 1's stored role. */}
              <th className={styles.th}>{identity ? 'Type' : 'Role'}</th>
              <th className={styles.th}>Status</th>
              <th className={styles.th}>Password</th>
              <th className={styles.th}>Projects</th>
              <th className={styles.th}>Last login</th>
              <th className={styles.th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className={styles.tr}>
                <td className={styles.td}>
                  {user.name}
                  {user.id === authUser?.id && <span className={styles.selfLabel}>(you)</span>}
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
                  ) : identity ? (
                    <AccountTypeBadge
                      type={accountTypeFor(user, authUser?.rbac?.root)}
                      unconfirmed={authUser?.rbac?.root?.confirmed === false}
                    />
                  ) : (
                    <span className={`${styles.badge} ${user.role === 'admin' ? styles.badgeAdmin : styles.badgeStandard}`}>
                      {user.role}
                    </span>
                  )}
                </td>
                <td className={styles.td}>
                  <AccountStatusCell status={user.status} mustChange={identity && user.mustChangePassword === true} />
                </td>
                <td className={styles.td}>
                  {user.hasPassword ? (
                    <span className={`${styles.badge} ${styles.badgeYes}`}>Set</span>
                  ) : (
                    <span className={styles.badgeNo}>Not set</span>
                  )}
                </td>
                <td className={styles.td}>{user._count?.projects ?? 0}</td>
                <td className={styles.td}><LastLogin at={user.lastLoginAt} /></td>
                <td className={styles.td}>
                  <div className={styles.actions}>
                    {identity && user.status === 'invited' && (
                      <InviteRowActions
                        user={user}
                        buttonClassName={styles.actionButton}
                        dangerClassName={styles.deleteButton}
                        onChanged={() => void refetchUsers?.()}
                      />
                    )}
                    {(user.id === authUser?.id || user.role !== 'admin' || manageAdmins) && !(identity && user.status === 'invited') && (
                      <button
                        className={styles.actionButton}
                        onClick={() => openModal({
                          type: 'password', userId: user.id, userName: user.name, userEmail: user.email,
                          targetIsAdmin: user.role === 'admin',
                        })}
                      >
                        Set Password
                      </button>
                    )}
                    {identity && user.id !== authUser?.id && user.status !== 'invited' && (user.role !== 'admin' || confirmedRoot) && (
                      <button
                        className={styles.actionButton}
                        aria-label={`Reset the credentials of ${user.name}`}
                        onClick={() => openModal({
                          type: 'reset', userId: user.id, userName: user.name, userEmail: user.email,
                          targetIsAdmin: user.role === 'admin',
                        })}
                      >
                        Reset credentials
                      </button>
                    )}
                    {canDeleteUsers && user.id !== authUser?.id && (user.role !== 'admin' || manageAdmins) && (
                      <button
                        className={`${styles.actionButton} ${styles.deleteButton}`}
                        onClick={() => openModal(deletionWizard
                          ? { type: 'deleteWizard', userId: user.id, userName: user.name, targetIsAdmin: user.role === 'admin' }
                          : { type: user.role === 'admin' ? 'deleteAdmin' : 'delete', userId: user.id, userName: user.name })}
                      >
                        Delete
                      </button>
                    )}
                    {mayAssign(user) && (
                      <button
                        className={styles.actionButton}
                        aria-label={`Permissions of ${user.name}`}
                        onClick={() => openModal({ type: 'permissions', userId: user.id, userName: user.name, userEmail: user.email })}
                      >
                        Permissions
                      </button>
                    )}
                    {confirmedRoot && user.id === authUser?.id && (
                      <RootTransferAction selfId={user.id} users={users} className={styles.actionButton} />
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

      {ownPasswordModal}

      <InviteUserModal isOpen={modal.type === 'invite'} onClose={closeModal} onInvited={() => void refetchUsers?.()} selfId={authUser?.id} />

      <Modal
        isOpen={modal.type === 'permissions'}
        onClose={closeModal}
        title={`Permissions - ${modal.type === 'permissions' ? modal.userName : ''}`}
        size="large"
      >
        {modal.type === 'permissions' && authUser && (
          <UserPermissionsPanel
            user={{ id: modal.userId, name: modal.userName, email: modal.userEmail }}
            selfId={authUser.id}
            onChanged={() => void refetchUsers?.()}
          />
        )}
      </Modal>

      {modal.type === 'reset' && (
        <ResetCredentialsModal
          isOpen
          user={{ id: modal.userId, name: modal.userName, email: modal.userEmail }}
          targetIsAdmin={modal.targetIsAdmin}
          policy={passwordPolicy}
          onClose={closeModal}
          onDone={() => void refetchUsers?.()}
        />
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
            <label className={styles.label} htmlFor="create-user-password">{sharingInForce ? 'Password *' : 'Password'}</label>
            <input
              id="create-user-password"
              type="password"
              className={styles.input}
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder={sharingInForce ? undefined : 'Leave empty for passwordless user'}
              required={sharingInForce}
              autoComplete="new-password"
              aria-describedby={passwordPolicy ? 'create-user-password-hint create-user-password-policy' : 'create-user-password-hint'}
            />
            <span id="create-user-password-hint" className={styles.hint}>
              {sharingInForce
                ? 'Sharing is on: every new account signs in with its own password, so projects are shared with a person, not reached by switching into an account.'
                : 'Passwordless users can only be accessed via admin switching'}
            </span>
            {passwordPolicy && <span id="create-user-password-policy" className={styles.hint}>{passwordPolicy.description}</span>}
          </div>
          {password && (
            <div className={styles.field}>
              <label className={styles.label} htmlFor="create-user-confirm">Confirm Password</label>
              <input
                id="create-user-confirm"
                type="password"
                className={styles.input}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
              />
            </div>
          )}
          {password && identity && (
            <RequireChangeField id="create-user-require-change" checked={requireChange} onChange={setRequireChange} />
          )}
          <div className={styles.field}>
            <label className={styles.label} htmlFor="create-user-role">Role</label>
            <select id="create-user-role" className={styles.select} value={role} onChange={e => setRole(e.target.value)}>
              <option value="standard">Standard</option>
              {manageAdmins && <option value="admin">Admin</option>}
            </select>
            {!manageAdmins && <span className={styles.hint}>Only Root creates admin accounts.</span>}
          </div>
          {role === 'standard' && (
            <InitialSetPicker idPrefix="create-user" selfId={authUser?.id} value={setChoice} onChange={setSetChoice} />
          )}
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
          {targetLabel}
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
              aria-describedby={passwordPolicy ? 'set-password-policy' : undefined}
            />
            {passwordPolicy && <span id="set-password-policy" className={styles.hint}>{passwordPolicy.description}</span>}
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
          {identity && modal.type === 'password' && !setOwnRow && (
            <RequireChangeField id="set-password-require-change" checked={requireChange} onChange={setRequireChange} />
          )}
          {identity && modal.type === 'password' && !setOwnRow && (
            <div className={styles.field}>
              <label className={styles.label} htmlFor="set-password-reason">Reason</label>
              <textarea
                id="set-password-reason"
                className={styles.input}
                value={reason}
                onChange={e => setReason(e.target.value)}
                maxLength={500}
                rows={2}
                aria-describedby="set-password-reason-hint"
              />
              <span id="set-password-reason-hint" className={styles.hint}>
                Setting someone&apos;s password resets their credentials: required once they have signed in before.
                They will read it at their next sign-in.
              </span>
            </div>
          )}
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
          {targetLabel}
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

      {modal.type === 'deleteWizard' && (
        <DeleteUserWizard
          isOpen
          userId={modal.userId}
          userName={modal.userName}
          targetIsAdmin={modal.targetIsAdmin}
          onClose={closeModal}
          onDeleted={() => {
            closeModal()
            void refetchUsers()
          }}
        />
      )}
    </div>
  )
}

const TYPE_BADGE: Record<AccountType, string> = {
  root: styles.badgeRoot,
  admin: styles.badgeAdmin,
  member: styles.badgeStandard,
}

/** Root, Admin or Member (identity switch on). An unconfirmed Root has no Root powers yet (step 2.5). */
function AccountTypeBadge({ type, unconfirmed }: { type: AccountType; unconfirmed: boolean }) {
  return (
    <span className={styles.cellStack}>
      <span className={`${styles.badge} ${TYPE_BADGE[type]}`}>{ACCOUNT_TYPE_LABEL[type]}</span>
      {type === 'root' && unconfirmed && <span className={styles.hint}>unconfirmed</span>}
    </span>
  )
}

const STATUS: Record<string, { label: string; tone: string }> = {
  active: { label: 'Active', tone: styles.badgeYes },
  invited: { label: 'Invited', tone: styles.badgeStandard },
  disabled: { label: 'Disabled', tone: styles.badgeWarn },
}

/** The account's status; a row from an older server has none and reads as active. */
function AccountStatusCell({ status, mustChange }: { status?: string; mustChange: boolean }) {
  const known = STATUS[status || 'active'] ?? { label: status ?? '', tone: styles.badgeStandard }
  return (
    <span className={styles.cellStack}>
      <span className={`${styles.badge} ${known.tone}`}>{known.label}</span>
      {mustChange && <span className={`${styles.badge} ${styles.badgeWarn}`}>Must change password</span>}
    </span>
  )
}

/**
 * The last sign-in (ID-27). Sign-ins are recorded from the identity schema on (step 2.2), so an
 * account without one may have signed in before that: "Not recorded", never "Never".
 */
function LastLogin({ at }: { at?: string | null }) {
  const when = at ? new Date(at) : null
  if (!when || Number.isNaN(when.getTime())) {
    return <span className={styles.badgeNo} title="No sign-in recorded since this version">Not recorded</span>
  }
  return (
    <time dateTime={when.toISOString()} title={when.toLocaleString()}>
      {when.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
    </time>
  )
}

/** "Require a change at first sign-in": the person replaces the password the admin chose (step 2.8). */
function RequireChangeField({ id, checked, onChange }: { id: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className={styles.field}>
      <label className={styles.checkboxLabel} htmlFor={id}>
        <input id={id} type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} aria-describedby={`${id}-hint`} />
        {' '}Require a change at first sign-in
      </label>
      <span id={`${id}-hint`} className={styles.hint}>
        Until then the person can only reach the page that changes it.
      </span>
    </div>
  )
}
