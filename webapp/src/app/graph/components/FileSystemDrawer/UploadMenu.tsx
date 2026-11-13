'use client'

import { useRef, type KeyboardEvent } from 'react'
import {
  ChevronDown,
  File as FileIcon,
  Folder as FolderIcon,
  FileArchive as ArchiveIcon,
  Link2 as LinkIcon,
  Upload as UploadIcon,
} from 'lucide-react'
import { Menu, MenuDivider, MenuItem } from '@/components/ui'
import styles from './FileSystemDrawer.module.css'

export interface UploadMenuProps {
  onFiles: () => void
  onFolder: () => void
  onArchive: () => void
  onImportUrl: () => void
  /** Why nothing may be uploaded or imported here (a read share), or null: the control is disabled. */
  disabledReason?: string | null
}

const TRIGGER = '[aria-haspopup="menu"]'

/**
 * The toolbar's upload control: one click on the icon still opens the file
 * picker, and the chevron beside it opens the menu of every upload kind and
 * of the import from a URL.
 */
export function UploadMenu({ onFiles, onFolder, onArchive, onImportUrl, disabledReason = null }: UploadMenuProps) {
  const wrapRef = useRef<HTMLSpanElement>(null)

  if (disabledReason) {
    return (
      <span className={styles.uploadSplit}>
        <button className={styles.actionBtn} disabled title={disabledReason} aria-label="Upload">
          <UploadIcon size={12} />
        </button>
      </span>
    )
  }

  // Menu opens on Enter/Space but leaves focus on its trigger, and its items
  // are out of the tab order, so a keyboard user could not reach them. Keys
  // from inside the portalled menu bubble here through the React tree too.
  const handleKeyDown = (ev: KeyboardEvent<HTMLSpanElement>) => {
    const trigger = wrapRef.current?.querySelector<HTMLElement>(TRIGGER)
    if (!trigger) return
    if (ev.key === 'Escape') {
      trigger.focus()
      return
    }
    if (ev.target !== trigger) return
    if (ev.key === 'ArrowDown' && trigger.getAttribute('aria-expanded') !== 'true') {
      ev.preventDefault()
      trigger.click()
    } else if (ev.key !== 'Enter' && ev.key !== ' ' && ev.key !== 'ArrowDown') {
      return
    }
    window.setTimeout(() => {
      if (trigger.getAttribute('aria-expanded') !== 'true') return
      const menus = document.querySelectorAll<HTMLElement>('[role="menu"]')
      menus[menus.length - 1]?.querySelector<HTMLElement>('[role="menuitem"]')?.focus()
    }, 0)
  }

  return (
    <span ref={wrapRef} className={styles.uploadSplit} onKeyDown={handleKeyDown}>
      <button
        className={styles.actionBtn}
        onClick={onFiles}
        title="Upload file(s) to current directory"
      >
        <UploadIcon size={12} />
      </button>
      <Menu
        align="right"
        ariaLabel="Upload options"
        trigger={<span className={styles.uploadCaret}><ChevronDown size={12} /></span>}
      >
        <MenuItem icon={<FileIcon size={12} />} onClick={onFiles}>Upload files…</MenuItem>
        <MenuItem icon={<FolderIcon size={12} />} onClick={onFolder}>Upload folder…</MenuItem>
        <MenuItem icon={<ArchiveIcon size={12} />} onClick={onArchive}>Upload archive and extract…</MenuItem>
        <MenuDivider />
        <MenuItem icon={<LinkIcon size={12} />} onClick={onImportUrl}>Import from URL…</MenuItem>
      </Menu>
    </span>
  )
}
