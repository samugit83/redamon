'use client'

import { useState, useRef, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { ChevronDown, Users, LogOut, KeyRound } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useAuth } from '@/providers/AuthProvider'
import { useUsers } from '@/hooks/useUsers'
import styles from './UserSelector.module.css'

export function UserSelector() {
  const router = useRouter()
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { userId, setUserId, setCurrentProject } = useProject()
  const { user: authUser, isAdmin, logout } = useAuth()
  const { data: users } = useUsers()

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

  const handleSelectUser = (user: { id: string; name: string }) => {
    if (user.id !== userId) {
      setUserId(user.id)
      setCurrentProject(null)
    }
    setIsOpen(false)
  }

  const handleManageUsers = () => {
    router.push('/settings/users')
    setIsOpen(false)
  }

  const handleChangePassword = () => {
    router.push('/settings/users?changePassword=true')
    setIsOpen(false)
  }

  const handleLogout = () => {
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
    </div>
  )
}

export default UserSelector
