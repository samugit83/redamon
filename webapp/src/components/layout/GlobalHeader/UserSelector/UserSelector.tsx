'use client'

import { useState, useRef, useEffect } from 'react'
import { ChevronDown, Users, LogOut, KeyRound } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useAuth } from '@/providers/AuthProvider'
import { useUsers } from '@/hooks/useUsers'
import { useGuardedRouter, useNavigationGuard } from '@/context/NavigationGuardContext'
import { useErrorToast } from '@/hooks/useErrorToast'
import { StepUpModal } from '@/components/auth/StepUpModal'
import styles from './UserSelector.module.css'

export function UserSelector() {
  const router = useGuardedRouter()
  const guard = useNavigationGuard()
  const [isOpen, setIsOpen] = useState(false)
  // Another admin to act as, waiting for the signed-in admin's own password.
  const [stepUpTarget, setStepUpTarget] = useState<{ id: string; name: string } | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { userId, setUserId, setCurrentProject, userSwitchError } = useProject()
  const { user: authUser, isAdmin, logout, sessionError } = useAuth()
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

  const handleSelectUser = async (user: { id: string; name: string; role?: string }) => {
    if (user.id !== userId) {
      // Switching user resets project context and reloads data - confirm first
      // if a dirty form would lose edits.
      if (guard?.hasGuards() && !(await guard.confirmAllGuards())) return
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

  return (
    <div className={styles.container} ref={dropdownRef}>
      <button
        className={styles.trigger}
        onClick={() => setIsOpen(!isOpen)}
        title="User Menu"
      >
        <div className={styles.avatar}>
          <span>{initials}</span>
        </div>
        <span className={styles.userName}>
          {displayUser?.name || 'No User'}
        </span>
        <ChevronDown size={14} className={isOpen ? styles.iconOpen : ''} />
      </button>

      {isOpen && (
        <div className={styles.dropdown}>
          {isAdmin ? (
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
                    </button>
                  ))
                ) : (
                  <div className={styles.empty}>
                    No users yet
                  </div>
                )}
              </div>

              <div className={styles.footer}>
                <button className={styles.footerButton} onClick={handleManageUsers}>
                  <Users size={12} />
                  Manage Users
                </button>
                <button className={styles.logoutButton} onClick={handleLogout}>
                  <LogOut size={12} />
                  Logout
                </button>
              </div>
            </>
          ) : (
            <>
              <div className={styles.header}>
                <span className={styles.headerTitle}>Account</span>
              </div>

              <div className={styles.list}>
                <button className={styles.item} onClick={handleChangePassword}>
                  <KeyRound size={14} />
                  <div className={styles.itemContent}>
                    <span className={styles.itemName}>Change Password</span>
                  </div>
                </button>
              </div>

              <div className={styles.footer}>
                <button className={styles.logoutButton} onClick={handleLogout}>
                  <LogOut size={12} />
                  Logout
                </button>
              </div>
            </>
          )}
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
