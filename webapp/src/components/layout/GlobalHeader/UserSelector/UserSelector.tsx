'use client'

import { useState, useRef, useEffect } from 'react'
import { ChevronDown, Users, LogOut, KeyRound, UserRound } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useAuth } from '@/providers/AuthProvider'
import { useCan, useRbacFlags } from '@/hooks/useCan'
import { useUsers } from '@/hooks/useUsers'
import { useGuardedRouter, useNavigationGuard } from '@/context/NavigationGuardContext'
import { useErrorToast } from '@/hooks/useErrorToast'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { IdentityLabel, accountTypeFor, identityText, ACCOUNT_TYPE_LABEL } from '@/components/auth/IdentityLabel'
import { opensOwnPasswordDialog } from '@/components/auth/ownPasswordDialog'
import styles from './UserSelector.module.css'

export function UserSelector() {
  const router = useGuardedRouter()
  const guard = useNavigationGuard()
  const [isOpen, setIsOpen] = useState(false)
  // Another admin to act as, waiting for the signed-in admin's own password.
  const [stepUpTarget, setStepUpTarget] = useState<{ id: string; name: string } | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { userId, setUserId, setCurrentProject, userSwitchError } = useProject()
  const { user: authUser, logout, sessionError } = useAuth()
  const canSwitchUser = useCan('users:impersonate')
  const canReadUsers = useCan('users:read')
  // Permissions switch on (step 3.14): every switch goes through the act-as dialog (reason,
  // duration, password), which the project provider opens; the step-up prompt below is Phase 2's.
  const viaDialog = useRbacFlags()?.permissions === true
  // The Users page opens the dialog by this same rule, so the item never leads to nothing.
  const offersChangePassword = opensOwnPasswordDialog({ readUsers: canReadUsers, switchUser: canSwitchUser, permissionsOn: viaDialog })
  const { data: users } = useUsers()
  // Both providers sit above the toast layer, so their failures are shown here.
  useErrorToast(userSwitchError, 'User not switched')
  useErrorToast(sessionError, 'Your session could not be read')

  const currentUser = users?.find(u => u.id === userId)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelectUser = async (user: { id: string; name: string; role?: string; email?: string }) => {
    if (user.id !== userId) {
      // Switching user resets project context and reloads data - confirm first
      // if a dirty form would lose edits.
      if (guard?.hasGuards() && !(await guard.confirmAllGuards())) return
      if (viaDialog) {
        setIsOpen(false)
        const other = user.id !== authUser?.id
        // The provider clears the project once the switch happened; a cancelled dialog changes nothing.
        await setUserId(user.id, other ? { target: { id: user.id, name: user.name, email: user.email ?? '', accountType: typeOf(user) } } : undefined)
        return
      }
      if (user.role === 'admin' && user.id !== authUser?.id) {
        setStepUpTarget({ id: user.id, name: user.name })
        setIsOpen(false)
        return
      }
      setUserId(user.id)
      setCurrentProject(null)
    }
    setIsOpen(false)
  }

  const confirmActAsAdmin = async (password: string) => {
    if (!stepUpTarget) return
    const refusal = await setUserId(stepUpTarget.id, { stepUpPassword: password })
    if (refusal) throw refusal
    setCurrentProject(null)
  }

  const handleManageUsers = () => {
    router.push('/settings/users')
    setIsOpen(false)
  }

  // Identity switch on (the session carries an account type): the My account page (step 2.11).
  const hasAccountPage = authUser?.accountType !== undefined
  const handleMyAccount = () => {
    router.push('/account')
    setIsOpen(false)
  }

  const handleChangePassword = () => {
    router.push('/settings/users?changePassword=true')
    setIsOpen(false)
  }

  const handleLogout = async () => {
    // Logging out abandons everything - confirm if a dirty form is open.
    if (guard?.hasGuards() && !(await guard.confirmAllGuards())) return
    setIsOpen(false)
    logout()
  }

  const displayUser = currentUser || authUser
  const initials = displayUser
    ? displayUser.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
    : '?'
  // Identity switch on (step 2.11, ID-31): accounts are named by email and type, not by name alone.
  const identity = authUser?.rbac?.identity === true
  const rootRef = authUser?.rbac?.root ?? null
  const typeOf = (u: { role?: string; email?: string }) => accountTypeFor({ role: u.role ?? 'standard', email: u.email ?? '' }, rootRef)
  const displayType = identity && displayUser
    ? (currentUser ? typeOf(currentUser) : authUser?.accountType ?? typeOf(authUser ?? {}))
    : null

  return (
    <div className={styles.container} ref={dropdownRef}>
      <button
        className={styles.trigger}
        onClick={() => setIsOpen(!isOpen)}
        title="User Menu"
        aria-label={displayType && displayUser
          ? `User menu: ${identityText({ name: displayUser.name, email: displayUser.email ?? '', accountType: displayType })}`
          : undefined}
      >
        <div className={styles.avatar}>
          <span>{initials}</span>
        </div>
        <span className={styles.userName}>
          {displayUser?.name || 'No User'}
        </span>
        {displayType && (
          <span className={`${styles.roleBadge} ${displayType === 'member' ? styles.roleBadgeStandard : styles.roleBadgeAdmin}`}>
            {ACCOUNT_TYPE_LABEL[displayType]}
          </span>
        )}
        <ChevronDown size={14} className={isOpen ? styles.iconOpen : ''} />
      </button>

      {isOpen && (
        <div className={styles.dropdown}>
          {!canSwitchUser && (
            <div className={styles.header}>
              <span className={styles.headerTitle}>Account</span>
            </div>
          )}
          {canSwitchUser && (
            <>
              <div className={styles.header}>
                <span className={styles.headerTitle}>Users</span>
              </div>

              <div className={styles.list}>
                {users && users.length > 0 ? (
                  users.map((user) => (
                    <button
                      key={user.id}
                      className={`${styles.item} ${userId === user.id ? styles.itemActive : ''}`}
                      onClick={() => handleSelectUser(user)}
                    >
                      <div className={styles.itemAvatar}>
                        <span>{user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)}</span>
                      </div>
                      {identity ? (
                        <div className={styles.itemContent}>
                          <IdentityLabel name={user.name} email={user.email} accountType={typeOf(user)} className={styles.identityStacked} />
                        </div>
                      ) : (
                        <div className={styles.itemContent}>
                          <span className={styles.itemName}>
                            {user.name}
                            {' '}
                            <span className={`${styles.roleBadge} ${user.role === 'admin' ? styles.roleBadgeAdmin : styles.roleBadgeStandard}`}>
                              {user.role}
                            </span>
                          </span>
                          <span className={styles.itemEmail}>{user.email}</span>
                        </div>
                      )}
                    </button>
                  ))
                ) : (
                  <div className={styles.empty}>
                    No users yet
                  </div>
                )}
              </div>
            </>
          )}

          {(hasAccountPage || canReadUsers || (!canSwitchUser && offersChangePassword)) && (
            <div className={styles.menu}>
              {hasAccountPage && (
                <button className={styles.menuItem} onClick={handleMyAccount}>
                  <UserRound size={16} />
                  My account
                </button>
              )}
              {/* The switcher never offered it (DV-30); opensOwnPasswordDialog keeps the rest in step with the Users page. */}
              {!canSwitchUser && offersChangePassword && (
                <button className={styles.menuItem} onClick={handleChangePassword}>
                  <KeyRound size={16} />
                  Change Password
                </button>
              )}
              {canReadUsers && (
                <button className={styles.menuItem} onClick={handleManageUsers}>
                  <Users size={16} />
                  Manage Users
                </button>
              )}
            </div>
          )}

          <div className={styles.menu}>
            <button className={`${styles.menuItem} ${styles.menuItemDanger}`} onClick={handleLogout}>
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>
      )}

      <StepUpModal
        isOpen={stepUpTarget !== null}
        title="Act as an admin"
        message={`${stepUpTarget?.name ?? ''} is an admin: acting as them needs your own password.`}
        confirmLabel="Switch user"
        onConfirm={confirmActAsAdmin}
        onClose={() => setStepUpTarget(null)}
      />
    </div>
  )
}

export default UserSelector
