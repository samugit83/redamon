'use client'

import { useState, useRef, useEffect } from 'react'
import { usePathname } from 'next/navigation'
import { ChevronDown, FolderOpen, Plus, Settings, Share2 } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useOptionalAuth } from '@/providers/AuthProvider'
import { useProjects, type ProjectListItem } from '@/hooks/useProjects'
import { useRefusal } from '@/hooks/useRefusal'
import { ShareDialog } from '@/components/sharing/ShareDialog'
import { LeaveShareButton } from '@/components/sharing/LeaveShareButton'
import { shareActions } from '@/components/sharing/sharePresets'
import { projectTargetLabel, toProjectSummary } from '@/lib/projectSummary'
import { useGuardedRouter, useNavigationGuard } from '@/context/NavigationGuardContext'
import styles from './ProjectSelector.module.css'

export function ProjectSelector() {
  const router = useGuardedRouter()
  const guard = useNavigationGuard()
  const pathname = usePathname()
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { currentProject, setCurrentProject, userId, checkAccessNow } = useProject()
  const { data: projects, refetch } = useProjects(userId || undefined)
  // Step 4.12: the open project's share control, only while sharing is in force (DV-30).
  const sharingInForce = useOptionalAuth()?.user?.sharing?.enabled === true
  const actions = shareActions(currentProject, sharingInForce)
  const shareRefusal = useRefusal('project:share', currentProject?.id)
  const [shareOpen, setShareOpen] = useState(false)

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelectProject = async (project: ProjectListItem) => {
    // Switching the active project abandons whatever dirty form is open, so
    // confirm before mutating context (not just before navigating).
    if (guard?.hasGuards() && !(await guard.confirmAllGuards())) return
    setCurrentProject(toProjectSummary(project))
    setIsOpen(false)

    // If on a project settings page, navigate to the new project's settings.
    // The guard already ran above, so push directly (avoid a second prompt).
    if (pathname.match(/\/projects\/[^/]+\/settings/)) {
      router.pushUnguarded(`/projects/${project.id}/settings`)
    }
  }

  const handleSettings = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (currentProject) {
      router.push(`/projects/${currentProject.id}/settings`)
      setIsOpen(false)
    }
  }

  const handleNewProject = () => {
    router.push('/projects/new')
    setIsOpen(false)
  }

  const handleViewAll = () => {
    router.push('/projects')
    setIsOpen(false)
  }

  return (
    <div className={styles.container} ref={dropdownRef}>
      <div className={styles.triggerGroup}>
        <button
          className={styles.trigger}
          onClick={() => setIsOpen(!isOpen)}
          title="Select Project"
        >
          <FolderOpen size={14} />
          <span className={styles.projectName}>
            {currentProject?.name || 'No Project'}
          </span>
          <ChevronDown size={12} className={isOpen ? styles.iconOpen : ''} />
        </button>
        {currentProject && (
          <button
            className={styles.settingsIconButton}
            onClick={handleSettings}
            title="Project Settings"
          >
            <Settings size={13} />
          </button>
        )}
        {currentProject && actions.share && (
          <button
            type="button"
            className={styles.settingsIconButton}
            onClick={() => { if (!shareRefusal) setShareOpen(true) }}
            title={shareRefusal ? shareRefusal.text : 'Share this project'}
            aria-label={`Share ${currentProject.name}`}
            aria-disabled={shareRefusal ? true : undefined}
          >
            <Share2 size={13} />
          </button>
        )}
        {currentProject && actions.leave && (
          // The open project: the access check that follows leads out and says the access ended.
          <LeaveShareButton
            project={{ id: currentProject.id, name: currentProject.name }}
            className={styles.settingsIconButton}
            announce={false}
            onLeft={() => {
              void checkAccessNow()
              void refetch()
            }}
          />
        )}
      </div>
      {shareOpen && currentProject && actions.share && (
        <ShareDialog project={{ id: currentProject.id, name: currentProject.name }} onClose={() => setShareOpen(false)} />
      )}

      {isOpen && (
        <div className={styles.dropdown}>
          <div className={styles.header}>
            <span className={styles.headerTitle}>Projects</span>
            {currentProject && (
              <button
                className={styles.settingsButton}
                onClick={handleSettings}
                title="Project Settings"
              >
                <Settings size={12} />
              </button>
            )}
          </div>

          <div className={styles.list}>
            {!userId ? (
              <div className={styles.empty}>
                Select a user to view projects
              </div>
            ) : projects && projects.length > 0 ? (
              projects.map((project) => (
                <button
                  key={project.id}
                  className={`${styles.item} ${currentProject?.id === project.id ? styles.itemActive : ''}`}
                  onClick={() => handleSelectProject(project)}
                >
                  <div className={styles.itemContent}>
                    <span className={styles.itemName}>{project.name}</span>
                    <span className={styles.itemDomain}>{projectTargetLabel(project)}</span>
                  </div>
                </button>
              ))
            ) : (
              <div className={styles.empty}>
                No projects yet
              </div>
            )}
          </div>

          <div className={styles.footer}>
            <button className={styles.footerButton} onClick={handleNewProject} disabled={!userId}>
              <Plus size={12} />
              New Project
            </button>
            <button className={styles.footerButton} onClick={handleViewAll}>
              Manage Projects
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default ProjectSelector
