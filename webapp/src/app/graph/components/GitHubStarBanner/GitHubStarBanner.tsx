'use client'

import { useState, useEffect } from 'react'
import { Star, X } from 'lucide-react'
import styles from './GitHubStarBanner.module.css'

const STORAGE_KEY = 'redamon-github-star-dismissed'

interface GitHubStarBannerProps {
  hasAttackChain: boolean
}

export function GitHubStarBanner({ hasAttackChain }: GitHubStarBannerProps) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    if (!hasAttackChain) return
    const dismissed = localStorage.getItem(STORAGE_KEY)
    if (!dismissed) {
      setVisible(true)
    }
  }, [hasAttackChain])

  const handleDismiss = () => {
    localStorage.setItem(STORAGE_KEY, '1')
    setVisible(false)
  }

  if (!visible) return null

  return (
    <div className={styles.banner}>
      <Star size={16} className={styles.icon} />
      <span className={styles.text}>
        Enjoying RedAmon? A <a href="https://github.com/samugit83/redamon" target="_blank" rel="noopener noreferrer">GitHub star</a> helps others discover the project.
      </span>
      <button className={styles.close} onClick={handleDismiss} aria-label="Dismiss">
        <X size={14} />
      </button>
    </div>
  )
}
