'use client'

import type { ReactNode } from 'react'
import { Globe, Calendar, Settings, Trash2, UserRound } from 'lucide-react'
import Link from 'next/link'
import styles from './ProjectCard.module.css'

interface ProjectCardProps {
  id: string
  name: string
  /** One line naming the target (projectTargetLabel): a batch has no targetDomain. */
  target: string
  description?: string | null
  createdAt: string
  isSelected?: boolean
  /** A project shared with the person: who shared it ("Name (email)") and their level badge. */
  sharedBy?: string
  accessLabel?: string
  /** "Owner: Name (email)" on a project reached by oversight or break-glass, instead of sharedBy. */
  ownedBy?: string
  /** More controls beside settings (Root's break-glass on the oversight list); each stops its click's propagation. */
  extraActions?: ReactNode
  onSelect?: () => void
  onDelete?: () => void
}

export function ProjectCard({
  id,
  name,
  target,
  description,
  createdAt,
  isSelected,
  sharedBy,
  accessLabel,
  ownedBy,
  extraActions,
  onSelect,
  onDelete
}: ProjectCardProps) {
  const formattedDate = new Date(createdAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })

  return (
    <div
      className={`card cardClickable ${isSelected ? 'cardSelected' : ''} ${styles.projectCard}`}
      onClick={onSelect}
    >
      <div className="cardHeader">
        <div>
          <h3 className="cardTitle">{name}</h3>
          {description && <p className="cardSubtitle">{description}</p>}
        </div>
        <div className={styles.actions}>
          {accessLabel && <span className="tag" title="Your access to this project">{accessLabel}</span>}
          {extraActions}
          <Link
            href={`/projects/${id}/settings`}
            className="iconButton"
            onClick={(e) => e.stopPropagation()}
            title="Project Settings"
          >
            <Settings size={14} />
          </Link>
          {onDelete && (
            <button
              className="iconButton"
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
              title="Delete Project"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>
      <div className="cardBody">
        <div className={styles.meta}>
          <div className={styles.metaItem}>
            <Globe size={12} />
            <span>{target || 'No target set'}</span>
          </div>
          <div className={styles.metaItem}>
            <Calendar size={12} />
            <span>{formattedDate}</span>
          </div>
          {sharedBy && (
            <div className={styles.metaItem}>
              <UserRound size={12} />
              <span>Shared by {sharedBy}</span>
            </div>
          )}
          {ownedBy && (
            <div className={styles.metaItem}>
              <UserRound size={12} />
              <span>Owner: {ownedBy}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ProjectCard
