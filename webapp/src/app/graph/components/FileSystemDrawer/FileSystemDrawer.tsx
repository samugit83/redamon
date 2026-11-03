'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  File as FileIcon,
  Folder as FolderIcon,
  Download as DownloadIcon,
  Pencil as PencilIcon,
  Trash2 as TrashIcon,
  Link2 as SymlinkIcon,
  ChevronRight,
  RefreshCw,
  XCircle,
  Eye,
  FolderOpen,
  Briefcase,
  FolderPlus,
  Upload as UploadIcon,
  FileArchive as ArchiveIcon,
  AlertTriangle,
  Lock,
  Info,
  ArrowLeft,
  Eraser,
} from 'lucide-react'
import { Drawer } from '@/components/ui/Drawer'
import { useAlertModal, WikiInfoButton } from '@/components/ui'
import { errorMessage, fetchJson, readApiError, toApiError } from '@/lib/apiError'
import styles from './FileSystemDrawer.module.css'

// =============================================================================
// Types
// =============================================================================

interface Entry {
  name: string
  path: string
  isDir: boolean
  isSymlink: boolean
  size: number
  mtime: string
}

interface JobRow {
  job_id: string
  project_id: string
  tool_name: string
  args: Record<string, unknown>
  label: string | null
  status: 'running' | 'done' | 'failed' | 'cancelled' | 'interrupted'
  started_at: string
  ended_at: string | null
  exit_code: number | null
  output_path: string
  error: string | null
  size_bytes?: number
}

type Tab = 'files' | 'jobs'

export interface FileSystemDrawerProps {
  isOpen: boolean
  onClose: () => void
  projectId: string
  /** When set, the drawer opens with the Files tab focused on this path. */
  initialPath?: string
  /** When set, the drawer opens on the Jobs tab. */
  initialTab?: Tab
}

// Protected default subdirs - these cannot be renamed or deleted. Mirrors
// PROTECTED_SUBDIRS in agentic/workspace_fs.py (backend also enforces).
const PROTECTED_SUBDIRS = new Set(['notes', 'tool-outputs', 'jobs', 'uploads'])
// A bulk delete's alert names this many failed entries with their cause.
const BULK_FAILURES_SHOWN = 5

const WIDTH_STORAGE_KEY = 'redamon-filesystem-drawer-width'
const DEFAULT_WIDTH_PX = 494
const MIN_WIDTH_PX = 320
const MAX_WIDTH_PX = 1200

function isProtectedPath(path: string): boolean {
  const norm = path.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/^\.\//, '')
  const trimmed = norm.replace(/^\/+|\/+$/g, '')
  if (!trimmed || trimmed === '.') return true
  const parts = trimmed.split('/')
  return parts.length === 1 && PROTECTED_SUBDIRS.has(parts[0])
}

// =============================================================================
// Helpers
// =============================================================================

function formatSize(bytes: number | undefined): string {
  if (bytes === undefined || bytes === null) return '-'
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}M`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}G`
}

function formatMtime(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function formatElapsed(started: string, ended: string | null): string {
  try {
    const start = new Date(started).getTime()
    const end = ended ? new Date(ended).getTime() : Date.now()
    const secs = Math.max(0, Math.round((end - start) / 1000))
    if (secs < 60) return `${secs}s`
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`
  } catch {
    return '-'
  }
}

function statusClass(status: string): string {
  switch (status) {
    case 'running': return styles.statusRunning
    case 'done': return styles.statusDone
    case 'failed': return styles.statusFailed
    case 'cancelled': return styles.statusCancelled
    case 'interrupted': return styles.statusInterrupted
    default: return ''
  }
}

// =============================================================================
// Component
// =============================================================================

export function FileSystemDrawer({
  isOpen,
  onClose,
  projectId,
  initialPath = '.',
  initialTab = 'files',
}: FileSystemDrawerProps) {
  // RedAmon-styled modal dialogs (replaces browser-native alert/confirm).
  // Provider is mounted in app/layout.tsx.
  const { alertError, alertWarning, dangerConfirm } = useAlertModal()

  const [tab, setTab] = useState<Tab>(initialTab)
  const [currentPath, setCurrentPath] = useState(initialPath)
  const [entries, setEntries] = useState<Entry[]>([])
  // Set when the agent capped the listing: the folder holds more than it sent.
  const [listingTotal, setListingTotal] = useState<number | null>(null)
  const [entriesLoading, setEntriesLoading] = useState(false)
  const [entriesError, setEntriesError] = useState<string | null>(null)
  const [renamingPath, setRenamingPath] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')

  // Stage B state
  const [mkdirInput, setMkdirInput] = useState<string | null>(null)  // null = hidden
  const [isDragging, setIsDragging] = useState(false)
  const [uploadingCount, setUploadingCount] = useState(0)
  const [deletePending, setDeletePending] = useState<Entry | null>(null)
  const [overwritePending, setOverwritePending] = useState<{
    file: File; destDir: string;
  } | null>(null)

  // Stage C state
  const [previewing, setPreviewing] = useState<{
    path: string; content: string; isBinary: boolean; truncated: boolean;
    mime: string; size: number;
  } | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [propertiesFor, setPropertiesFor] = useState<{
    path: string; type: string; size: number; mtime: string; mode: string;
    sha256?: string; target?: string;
  } | null>(null)
  const [propertiesLoading, setPropertiesLoading] = useState(false)
  const [propertiesError, setPropertiesError] = useState<string | null>(null)

  // Stage D state
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set())
  const [sortBy, setSortBy] = useState<'name' | 'size' | 'mtime'>('name')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [filterText, setFilterText] = useState('')
  const [bulkDeletePending, setBulkDeletePending] = useState<Entry[] | null>(null)
  const [bulkActionLoading, setBulkActionLoading] = useState(false)

  const [jobs, setJobs] = useState<JobRow[]>([])
  const [jobsLoading, setJobsLoading] = useState(false)
  const [jobsError, setJobsError] = useState<string | null>(null)

  // Drawer width - persisted per-user via localStorage so it survives reloads
  // and project switches. Lazy init reads the stored value once on mount.
  const [drawerWidth, setDrawerWidth] = useState<number>(() => {
    if (typeof window === 'undefined') return DEFAULT_WIDTH_PX
    const raw = window.localStorage.getItem(WIDTH_STORAGE_KEY)
    if (!raw) return DEFAULT_WIDTH_PX
    const n = parseInt(raw, 10)
    if (!Number.isFinite(n)) return DEFAULT_WIDTH_PX
    return Math.min(Math.max(n, MIN_WIDTH_PX), MAX_WIDTH_PX)
  })

  const handleResizeEnd = useCallback((widthPx: number) => {
    const clamped = Math.min(Math.max(Math.round(widthPx), MIN_WIDTH_PX), MAX_WIDTH_PX)
    try {
      window.localStorage.setItem(WIDTH_STORAGE_KEY, String(clamped))
    } catch {
      // localStorage unavailable (private mode, quota) - width still applies for the session.
    }
  }, [])

  // Reset when the drawer "context" changes (reopen, projectId switch, or
  // initialPath/initialTab override). Without resetting preview/properties
  // here, stale content from the prior session/project would show up
  // (bug #19 - caught by stage-C review).
  useEffect(() => {
    if (isOpen) {
      setCurrentPath(initialPath)
      setTab(initialTab)
      setPreviewing(null)
      setPreviewError(null)
      setPropertiesFor(null)
      setPropertiesError(null)
      setSelectedPaths(new Set())
      setFilterText('')
    }
  }, [isOpen, projectId, initialPath, initialTab])

  // Reset selection + filter when path changes (the entries shown are
  // different so the selection set would point at unrelated paths).
  useEffect(() => {
    setSelectedPaths(new Set())
    setFilterText('')
  }, [currentPath])

  // Computed: filter + sort applied to the raw entries list
  const displayedEntries = useMemo(() => {
    let out = entries
    if (filterText.trim()) {
      const needle = filterText.toLowerCase()
      out = out.filter(e => e.name.toLowerCase().includes(needle))
    }
    const dir = sortDir === 'asc' ? 1 : -1
    out = [...out].sort((a, b) => {
      // Always keep dirs above files - matches the convention of native
      // file managers. Sort within each group by the chosen column.
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
      if (sortBy === 'name') return a.name.localeCompare(b.name) * dir
      if (sortBy === 'size') return (a.size - b.size) * dir
      // mtime is ISO 8601 - string comparison is chronologically correct
      return (a.mtime < b.mtime ? -1 : a.mtime > b.mtime ? 1 : 0) * dir
    })
    return out
  }, [entries, filterText, sortBy, sortDir])

  // ---- Fetchers ---------------------------------------------------------

  // `silent` skips the loading/error state toggle - used for the 5s background
  // poll so the entry list doesn't unmount/remount on every tick (which
  // produced a visible flash). The current list stays on screen; if the
  // poll fails we keep the stale data rather than wiping it.
  const fetchEntries = useCallback(async (path: string, silent = false) => {
    if (!projectId) return
    if (!silent) {
      setEntriesLoading(true)
      setEntriesError(null)
    }
    try {
      const url = `/api/agent/workspace/list?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}`
      const data = await fetchJson<{ entries?: Entry[]; total?: number; truncated?: boolean }>(
        url, { cache: 'no-store' }, 'Failed to list workspace')
      setEntries(data.entries || [])
      setListingTotal(data.truncated && typeof data.total === 'number' ? data.total : null)
      if (silent) setEntriesError(null)
    } catch (e) {
      if (!silent) {
        setEntriesError(errorMessage(e, 'Failed to load'))
        setEntries([])
        setListingTotal(null)
      }
    } finally {
      if (!silent) setEntriesLoading(false)
    }
  }, [projectId])

  const fetchJobs = useCallback(async (silent = false) => {
    if (!projectId) return
    if (!silent) {
      setJobsLoading(true)
      setJobsError(null)
    }
    try {
      const url = `/api/agent/workspace/jobs?projectId=${encodeURIComponent(projectId)}`
      const data = await fetchJson<{ jobs?: JobRow[] }>(url, { cache: 'no-store' }, 'Failed to fetch jobs')
      setJobs(data.jobs || [])
      if (silent) setJobsError(null)
    } catch (e) {
      if (!silent) {
        setJobsError(errorMessage(e, 'Failed to load'))
        setJobs([])
      }
    } finally {
      if (!silent) setJobsLoading(false)
    }
  }, [projectId])

  // Files tab: initial fetch when path or open state changes
  useEffect(() => {
    if (isOpen && tab === 'files') {
      fetchEntries(currentPath)
    }
  }, [isOpen, tab, currentPath, fetchEntries])

  // Files tab: auto-refresh every 5s while visible so the agent's
  // fs_write / fs_mkdir / fs_delete operations (and host-side drops into
  // uploads/) appear without the user having to hit the refresh button.
  // Paused while previewing a file (preview content doesn't depend on the
  // listing, and refetching would risk a flicker if entries change).
  useEffect(() => {
    if (!(isOpen && tab === 'files')) return
    if (previewing !== null) return
    const handle = setInterval(() => fetchEntries(currentPath, true), 5000)
    return () => clearInterval(handle)
  }, [isOpen, tab, currentPath, fetchEntries, previewing])

  // Jobs tab: poll every 5s while open (WS push lands in a follow-up; polling
  // is the fallback even when WS works).
  useEffect(() => {
    if (!(isOpen && tab === 'jobs')) return
    fetchJobs()
    const handle = setInterval(() => fetchJobs(true), 5000)
    return () => clearInterval(handle)
  }, [isOpen, tab, fetchJobs])

  // ---- Actions ----------------------------------------------------------

  const handleEnterDir = useCallback((path: string) => {
    setCurrentPath(path)
  }, [])

  const handleGoUp = useCallback(() => {
    if (currentPath === '.' || currentPath === '') return
    const segments = currentPath.split('/').filter(Boolean)
    segments.pop()
    setCurrentPath(segments.length ? segments.join('/') : '.')
  }, [currentPath])

  const handleDownload = useCallback((entry: Entry) => {
    const url = `/api/agent/files?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(entry.path)}`
    // Use an anchor click rather than setting window.location.href - if the
    // server returns a JSON error response, location.href would NAVIGATE the
    // page away from the graph view (losing session state). An anchor with
    // the download attribute either triggers the download dialog (happy path)
    // or downloads the error JSON as a file (graceful failure), but never
    // navigates.
    const a = document.createElement('a')
    a.href = url
    a.download = entry.name
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }, [projectId])

  const startRename = useCallback((entry: Entry) => {
    setRenamingPath(entry.path)
    setRenameValue(entry.name)
  }, [])

  const commitRename = useCallback(async (entry: Entry) => {
    if (!renameValue || renameValue === entry.name) {
      setRenamingPath(null)
      return
    }
    try {
      await fetchJson('/api/agent/workspace/rename', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          path: entry.path,
          newName: renameValue,
        }),
      }, 'rename failed')
      setRenamingPath(null)
      fetchEntries(currentPath)
    } catch (e) {
      alertError(errorMessage(e, 'rename failed'), 'Rename failed')
    }
  }, [projectId, renameValue, currentPath, fetchEntries, alertError])

  // Opens the delete-confirm modal. Actual DELETE goes through performDelete
  // once the user confirms - lets us use a real in-drawer modal instead of
  // window.confirm (better UX, especially for directory wipes).
  const handleDeleteRequest = useCallback((entry: Entry) => {
    setDeletePending(entry)
  }, [])

  const performDelete = useCallback(async (entry: Entry) => {
    try {
      const url = `/api/agent/workspace/delete?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(entry.path)}&recursive=${entry.isDir}`
      await fetchJson(url, { method: 'DELETE' }, 'delete failed')
      fetchEntries(currentPath)
    } catch (e) {
      alertError(errorMessage(e, 'delete failed'), 'Delete failed')
    } finally {
      setDeletePending(null)
    }
  }, [projectId, currentPath, fetchEntries, alertError])

  // --- New folder: inline input toggled by the toolbar button --------------

  const handleMkdirToggle = useCallback(() => {
    setMkdirInput((cur) => (cur === null ? '' : null))
  }, [])

  const handleMkdirCommit = useCallback(async () => {
    const name = (mkdirInput || '').trim()
    if (!name) {
      setMkdirInput(null)
      return
    }
    if (name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
      alertWarning('Folder name cannot contain / \\ or be . / ..', 'Invalid folder name')
      return
    }
    const fullPath = currentPath === '.' || currentPath === '' ? name : `${currentPath}/${name}`
    try {
      await fetchJson('/api/agent/workspace/mkdir', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, path: fullPath }),
      }, 'mkdir failed')
      setMkdirInput(null)
      fetchEntries(currentPath)
    } catch (e) {
      alertError(errorMessage(e, 'mkdir failed'), 'Create folder failed')
    }
  }, [mkdirInput, projectId, currentPath, fetchEntries, alertWarning, alertError])

  // --- Upload (file picker + drag-drop share this) -------------------------

  const doUpload = useCallback(async (file: File, destDir: string, overwrite = false) => {
    setUploadingCount((n) => n + 1)
    try {
      const fd = new FormData()
      fd.append('projectId', projectId)
      fd.append('path', destDir)
      fd.append('overwrite', overwrite ? 'true' : 'false')
      fd.append('file', file)
      const resp = await fetch('/api/agent/workspace/upload', {
        method: 'POST',
        body: fd,
      })
      if (resp.status === 409) {
        // Server reports name collision - queue an overwrite confirm
        setOverwritePending({ file, destDir })
        return
      }
      if (!resp.ok) throw await readApiError(resp, 'upload failed')
      fetchEntries(currentPath)
    } catch (e) {
      alertError(toApiError(e, 'upload failed').message, 'Upload failed')
    } finally {
      setUploadingCount((n) => Math.max(0, n - 1))
    }
  }, [projectId, currentPath, fetchEntries, alertError])

  const handleUploadPick = useCallback(() => {
    // Programmatic file picker - no permanent <input> in the DOM
    const input = document.createElement('input')
    input.type = 'file'
    input.multiple = true
    input.onchange = () => {
      const files = Array.from(input.files || [])
      for (const f of files) doUpload(f, currentPath, false)
    }
    input.click()
  }, [doUpload, currentPath])

  const handleConfirmOverwrite = useCallback(() => {
    if (!overwritePending) return
    const { file, destDir } = overwritePending
    setOverwritePending(null)
    doUpload(file, destDir, true)
  }, [overwritePending, doUpload])

  // --- Drag-and-drop --------------------------------------------------------

  const handleDragOver = useCallback((ev: React.DragEvent) => {
    if (ev.dataTransfer.types.includes('Files')) {
      ev.preventDefault()
      ev.dataTransfer.dropEffect = 'copy'
      setIsDragging(true)
    }
  }, [])

  const handleDragLeave = useCallback((ev: React.DragEvent) => {
    // Only clear when leaving the entire drawer, not just a child element
    if (ev.currentTarget === ev.target) setIsDragging(false)
  }, [])

  const handleDrop = useCallback((ev: React.DragEvent) => {
    ev.preventDefault()
    setIsDragging(false)
    const files = Array.from(ev.dataTransfer.files || [])
    for (const f of files) doUpload(f, currentPath, false)
  }, [doUpload, currentPath])

  // --- Preview (file row click) --------------------------------------------

  const openPreview = useCallback(async (entry: Entry) => {
    setPreviewing({ path: entry.path, content: '', isBinary: false, truncated: false, mime: '', size: 0 })
    setPreviewLoading(true)
    setPreviewError(null)
    try {
      const url = `/api/agent/workspace/preview?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(entry.path)}`
      const data = await fetchJson<Record<string, any>>(url, { cache: 'no-store' }, 'preview failed')
      setPreviewing({
        path: entry.path,
        content: data.content,
        isBinary: data.isBinary,
        truncated: data.truncated,
        mime: data.mime,
        size: data.size,
      })
    } catch (e) {
      setPreviewError(errorMessage(e, 'preview failed'))
    } finally {
      setPreviewLoading(false)
    }
  }, [projectId])

  const closePreview = useCallback(() => {
    setPreviewing(null)
    setPreviewError(null)
  }, [])

  // --- Properties popover --------------------------------------------------

  const openProperties = useCallback(async (entry: Entry) => {
    setPropertiesFor({ path: entry.path, type: '', size: 0, mtime: '', mode: '' })
    setPropertiesLoading(true)
    setPropertiesError(null)
    try {
      const url = `/api/agent/workspace/properties?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(entry.path)}`
      setPropertiesFor(await fetchJson(url, { cache: 'no-store' }, 'fetch failed'))
    } catch (e) {
      setPropertiesError(errorMessage(e, 'fetch failed'))
    } finally {
      setPropertiesLoading(false)
    }
  }, [projectId])

  const closeProperties = useCallback(() => {
    setPropertiesFor(null)
    setPropertiesError(null)
  }, [])

  // --- Multi-select (Stage D) ---------------------------------------------

  const toggleSelect = useCallback((path: string) => {
    setSelectedPaths(prev => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  }, [])

  const selectAll = useCallback(() => {
    // Only select currently-displayed entries (respects filter)
    setSelectedPaths(new Set(displayedEntries.map(e => e.path)))
  }, [displayedEntries])

  const clearSelection = useCallback(() => {
    setSelectedPaths(new Set())
  }, [])

  const handleSortClick = useCallback((col: 'name' | 'size' | 'mtime') => {
    if (col === sortBy) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortBy(col)
      setSortDir('asc')
    }
  }, [sortBy])

  const handleBulkDeleteRequest = useCallback(() => {
    // Filter out protected entries - bulk delete can't touch them, mirror
    // the per-row behaviour. The confirm modal explains the filter.
    const allSelected = entries.filter(e => selectedPaths.has(e.path))
    const deletable = allSelected.filter(e => !isProtectedPath(e.path))
    if (deletable.length === 0) {
      alertWarning('All selected entries are protected default folders; nothing to delete.', 'Nothing to delete')
      return
    }
    setBulkDeletePending(deletable)
  }, [entries, selectedPaths, alertWarning])

  const performBulkDelete = useCallback(async (toDelete: Entry[]) => {
    setBulkActionLoading(true)
    const failures: string[] = []
    for (const e of toDelete) {
      try {
        const url = `/api/agent/workspace/delete?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(e.path)}&recursive=${e.isDir}`
        await fetchJson(url, { method: 'DELETE' }, 'delete failed')
      } catch (err) {
        failures.push(`${e.path}: ${errorMessage(err, 'delete failed')}`)
      }
    }
    setBulkActionLoading(false)
    setBulkDeletePending(null)
    setSelectedPaths(new Set())
    fetchEntries(currentPath)
    if (failures.length > 0) {
      const shown = failures.slice(0, BULK_FAILURES_SHOWN)
      const more = failures.length - shown.length
      alertError(
        `${failures.length} entries failed to delete:\n${shown.join('\n')}${more > 0 ? `\n…and ${more} more` : ''}`,
        'Bulk delete',
      )
    }
  }, [projectId, currentPath, fetchEntries, alertError])

  const handleBulkDownload = useCallback(async () => {
    const paths = Array.from(selectedPaths)
    if (paths.length === 0) return
    setBulkActionLoading(true)
    try {
      const resp = await fetch('/api/agent/workspace/bulk-archive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          paths,
          format: 'tar.gz',
          archiveName: paths.length === 1 ? paths[0].split('/').pop() || 'bundle' : 'bundle',
        }),
      })
      if (!resp.ok) throw await readApiError(resp, 'Could not build the archive')
      // Stream the blob to an anchor download
      const blob = await resp.blob()
      const cd = resp.headers.get('Content-Disposition') || ''
      const m = /filename="?([^";]+)"?/.exec(cd)
      const filename = m?.[1] || 'bundle.tar.gz'
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (e) {
      alertError(toApiError(e, 'Could not build the archive').message, 'Bulk download failed')
    } finally {
      setBulkActionLoading(false)
    }
  }, [projectId, selectedPaths, alertError])

  // --- Folder download (archive as tar.gz) ---------------------------------

  const handleFolderDownload = useCallback((entry: Entry) => {
    const url = `/api/agent/workspace/archive-download?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(entry.path)}&format=tar.gz`
    const a = document.createElement('a')
    a.href = url
    a.download = `${entry.name}.tar.gz`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }, [projectId])

  const handleViewJobLog = useCallback((job: JobRow) => {
    // Switch to Files tab + navigate to the log's directory; the user can then
    // click the .log entry to inspect.
    const segments = (job.output_path || '').split('/').filter(Boolean)
    // output_path is /workspace/<projectId>/jobs/<id>.log -> grab last 2 segments after projectId
    const projIdx = segments.indexOf(projectId)
    if (projIdx >= 0 && projIdx + 1 < segments.length) {
      const rel = segments.slice(projIdx + 1, -1).join('/') || '.'
      setCurrentPath(rel)
    } else {
      setCurrentPath('jobs')
    }
    setTab('files')
  }, [projectId])

  // Clean All: wipes every entry under the project root and recreates the
  // four PROTECTED_SUBDIRS empty. Always behind a confirmation modal.
  const handleCleanAll = useCallback(async () => {
    const ok = await dangerConfirm(
      'This will permanently delete every file and folder in the project workspace and reset it to the four empty default folders (jobs, notes, tool-outputs, uploads). This cannot be undone.',
      'Clean entire workspace?',
    )
    if (!ok) return
    try {
      await fetchJson('/api/agent/workspace/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId }),
      }, 'reset failed')
      setSelectedPaths(new Set())
      setFilterText('')
      setCurrentPath('.')
      fetchEntries('.')
    } catch (e) {
      alertError(errorMessage(e, 'reset failed'), 'Clean all failed')
    }
  }, [projectId, fetchEntries, dangerConfirm, alertError])

  const handleCancelJob = useCallback(async (job: JobRow) => {
    const ok = await dangerConfirm(
      `Cancel the running ${job.tool_name} job? Any work done so far will be discarded.`,
      'Cancel job',
    )
    if (!ok) return
    try {
      const url = `/api/agent/workspace/jobs/${encodeURIComponent(job.job_id)}/cancel?projectId=${encodeURIComponent(projectId)}`
      await fetchJson(url, { method: 'POST' }, 'cancel failed')
      fetchJobs()
    } catch (e) {
      alertError(errorMessage(e, 'cancel failed'), 'Cancel failed')
    }
  }, [projectId, fetchJobs, dangerConfirm, alertError])

  // ---- Breadcrumb -------------------------------------------------------

  const crumbs = useMemo(() => {
    if (currentPath === '.' || currentPath === '') return []
    const parts = currentPath.split('/').filter(Boolean)
    return parts.map((name, idx) => ({
      name,
      path: parts.slice(0, idx + 1).join('/'),
    }))
  }, [currentPath])

  // ---- Render -----------------------------------------------------------

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      position="left"
      mode="overlay"
      width={`${drawerWidth}px`}
      title="Agent Workspace"
      headerActions={
        <WikiInfoButton
          target="https://github.com/samugit83/redamon/wiki/Agent-Workspace"
          title="Open Agent Workspace wiki page"
        />
      }
      resizable
      minWidth={MIN_WIDTH_PX}
      maxWidth={MAX_WIDTH_PX}
      onResize={setDrawerWidth}
      onResizeEnd={handleResizeEnd}
    >
      <div className={styles.tabs}>
        <button
          className={`${styles.tab} ${tab === 'files' ? styles.tabActive : ''}`}
          onClick={() => setTab('files')}
        >
          <FolderOpen size={14} /> Files
        </button>
        <button
          className={`${styles.tab} ${tab === 'jobs' ? styles.tabActive : ''}`}
          onClick={() => setTab('jobs')}
        >
          <Briefcase size={14} /> Jobs
        </button>
      </div>

      {tab === 'files' && previewing !== null && (
        <div className={styles.previewView}>
          <div className={styles.previewHeader}>
            <button
              className={styles.actionBtn}
              onClick={closePreview}
              title="Back to files"
            >
              <ArrowLeft size={14} />
            </button>
            <span className={styles.previewPath} title={previewing.path}>
              {previewing.path}
            </span>
          </div>
          <div className={styles.previewMeta}>
            <span>{formatSize(previewing.size)}</span>
            {previewing.mime && <span>· {previewing.mime}</span>}
            {previewing.truncated && (
              <span className={styles.previewTruncated}>· truncated</span>
            )}
          </div>
          {previewLoading && <div className={styles.loading}>Loading…</div>}
          {previewError && <div className={styles.error}>Error: {previewError}</div>}
          {!previewLoading && !previewError && previewing.isBinary && (
            <div className={styles.previewBinary}>
              <AlertTriangle size={16} />
              <div>Binary file ({formatSize(previewing.size)}).</div>
              <div>Use Download to inspect locally.</div>
            </div>
          )}
          {!previewLoading && !previewError && !previewing.isBinary && (
            <pre className={styles.previewText}>{previewing.content}</pre>
          )}
        </div>
      )}

      {tab === 'files' && previewing === null && (
        <>
          <div className={styles.breadcrumb}>
            <button
              className={styles.crumb}
              onClick={() => setCurrentPath('.')}
              title="Project root"
            >
              /workspace
            </button>
            {crumbs.map((c, i) => (
              <span key={c.path} style={{ display: 'flex', alignItems: 'center' }}>
                <span className={styles.crumbSep}><ChevronRight size={12} /></span>
                <button
                  className={styles.crumb}
                  onClick={() => setCurrentPath(c.path)}
                  disabled={i === crumbs.length - 1}
                >
                  {c.name}
                </button>
              </span>
            ))}
            <div className={styles.toolbarSpacer} />
            <button
              className={styles.actionBtn}
              onClick={handleMkdirToggle}
              title="New folder in current directory"
            >
              <FolderPlus size={12} />
            </button>
            <button
              className={styles.actionBtn}
              onClick={handleUploadPick}
              title="Upload file(s) to current directory"
            >
              <UploadIcon size={12} />
            </button>
            <button
              className={styles.actionBtn}
              onClick={() => fetchEntries(currentPath)}
              title="Refresh"
            >
              <RefreshCw size={12} />
            </button>
            <button
              className={`${styles.actionBtn} ${styles.actionBtnDanger}`}
              onClick={handleCleanAll}
              title="Clean all - reset workspace to 4 empty default folders"
            >
              <Eraser size={12} />
            </button>
          </div>

          {mkdirInput !== null && (
            <div className={styles.mkdirRow}>
              <FolderPlus size={14} />
              <input
                autoFocus
                className={styles.renameInput}
                value={mkdirInput}
                placeholder="new folder name"
                onChange={(ev) => setMkdirInput(ev.target.value)}
                onKeyDown={(ev) => {
                  if (ev.key === 'Enter') handleMkdirCommit()
                  else if (ev.key === 'Escape') setMkdirInput(null)
                }}
                onBlur={() => {
                  // Slight delay so onClick of commit button (if any) wins
                  setTimeout(() => setMkdirInput(null), 100)
                }}
              />
            </div>
          )}

          {uploadingCount > 0 && (
            <div className={styles.uploadingHint}>
              Uploading {uploadingCount} file{uploadingCount > 1 ? 's' : ''}…
            </div>
          )}

          {/* Stage D: filter input - hides non-matching names in current dir */}
          <div className={styles.filterRow}>
            <input
              className={styles.filterInput}
              type="text"
              placeholder="Filter files…"
              value={filterText}
              onChange={(ev) => setFilterText(ev.target.value)}
              aria-label="Filter files"
            />
            {filterText && (
              <button
                className={styles.actionBtn}
                onClick={() => setFilterText('')}
                title="Clear filter"
              >
                <XCircle size={12} />
              </button>
            )}
          </div>

          {/* Stage D: sort header - click to toggle column / direction */}
          <div className={styles.sortHeader}>
            <button
              className={`${styles.sortBtn} ${sortBy === 'name' ? styles.sortBtnActive : ''}`}
              onClick={() => handleSortClick('name')}
            >
              Name {sortBy === 'name' ? (sortDir === 'asc' ? '▲' : '▼') : ''}
            </button>
            <button
              className={`${styles.sortBtn} ${sortBy === 'size' ? styles.sortBtnActive : ''}`}
              onClick={() => handleSortClick('size')}
            >
              Size {sortBy === 'size' ? (sortDir === 'asc' ? '▲' : '▼') : ''}
            </button>
            <button
              className={`${styles.sortBtn} ${sortBy === 'mtime' ? styles.sortBtnActive : ''}`}
              onClick={() => handleSortClick('mtime')}
            >
              Modified {sortBy === 'mtime' ? (sortDir === 'asc' ? '▲' : '▼') : ''}
            </button>
          </div>

          {/* Stage D: bulk action bar - sticky above the list when any
              entries are selected. */}
          {selectedPaths.size > 0 && (
            <div className={styles.bulkBar}>
              <span className={styles.bulkCount}>
                {selectedPaths.size} selected
              </span>
              <button
                className={styles.bulkBtn}
                onClick={handleBulkDownload}
                disabled={bulkActionLoading}
                title="Download selected as one tar.gz"
              >
                <DownloadIcon size={12} /> Download
              </button>
              <button
                className={`${styles.bulkBtn} ${styles.bulkBtnDanger}`}
                onClick={handleBulkDeleteRequest}
                disabled={bulkActionLoading}
                title="Delete selected (protected entries are skipped)"
              >
                <TrashIcon size={12} /> Delete
              </button>
              <button
                className={styles.bulkBtn}
                onClick={clearSelection}
                title="Clear selection"
              >
                Clear
              </button>
            </div>
          )}

          {entriesLoading && <div className={styles.loading}>Loading…</div>}
          {entriesError && <div className={styles.error}>Error: {entriesError}</div>}
          {!entriesLoading && !entriesError && (
            <div className={styles.entryList}>
              {currentPath !== '.' && currentPath !== '' && (
                <div className={styles.entry} onClick={handleGoUp}>
                  <span />
                  <FolderIcon size={14} />
                  <span className={styles.entryName}>..</span>
                  <span />
                </div>
              )}
              {displayedEntries.length === 0 ? (
                <div className={styles.empty}>
                  {filterText ? `No matches for "${filterText}"` : '(empty)'}
                </div>
              ) : (
                displayedEntries.map((e) => (
                  <div
                    key={e.path}
                    data-name={e.name}
                    className={`${styles.entry} ${selectedPaths.has(e.path) ? styles.entrySelected : ''}`}
                    onClick={() => e.isDir ? handleEnterDir(e.path) : openPreview(e)}
                  >
                    <input
                      type="checkbox"
                      className={styles.entryCheckbox}
                      checked={selectedPaths.has(e.path)}
                      onChange={() => toggleSelect(e.path)}
                      onClick={(ev) => ev.stopPropagation()}
                      aria-label={`Select ${e.name}`}
                    />
                    {e.isSymlink ? <SymlinkIcon size={14} /> :
                      e.isDir ? <FolderIcon size={14} /> : <FileIcon size={14} />}
                    {renamingPath === e.path ? (
                      <input
                        autoFocus
                        className={styles.renameInput}
                        value={renameValue}
                        onChange={(ev) => setRenameValue(ev.target.value)}
                        onKeyDown={(ev) => {
                          if (ev.key === 'Enter') commitRename(e)
                          else if (ev.key === 'Escape') setRenamingPath(null)
                        }}
                        onBlur={() => setRenamingPath(null)}
                        onClick={(ev) => ev.stopPropagation()}
                      />
                    ) : (
                      <span className={styles.entryName} title={e.path}>
                        {e.name}
                        <span className={styles.entryMeta} style={{ marginLeft: 8 }}>
                          {!e.isDir && <span>{formatSize(e.size)}</span>}
                          <span>{formatMtime(e.mtime)}</span>
                        </span>
                      </span>
                    )}
                    <span className={styles.entryActions}>
                      {!e.isDir && (
                        <button
                          className={styles.actionBtn}
                          onClick={(ev) => { ev.stopPropagation(); handleDownload(e) }}
                          title="Download"
                        >
                          <DownloadIcon size={12} />
                        </button>
                      )}
                      {e.isDir && !e.isSymlink && (
                        <button
                          className={styles.actionBtn}
                          onClick={(ev) => { ev.stopPropagation(); handleFolderDownload(e) }}
                          title="Download folder as .tar.gz"
                        >
                          <ArchiveIcon size={12} />
                        </button>
                      )}
                      <button
                        className={styles.actionBtn}
                        onClick={(ev) => { ev.stopPropagation(); openProperties(e) }}
                        title="Properties (size, hash, modified)"
                      >
                        <Info size={12} />
                      </button>
                      {isProtectedPath(e.path) ? (
                        <span
                          className={styles.protectedBadge}
                          title="Protected default folder - cannot be renamed or deleted"
                        >
                          <Lock size={12} />
                        </span>
                      ) : (
                        <>
                          <button
                            className={styles.actionBtn}
                            onClick={(ev) => { ev.stopPropagation(); startRename(e) }}
                            title="Rename"
                          >
                            <PencilIcon size={12} />
                          </button>
                          <button
                            className={`${styles.actionBtn} ${styles.actionBtnDanger}`}
                            onClick={(ev) => { ev.stopPropagation(); handleDeleteRequest(e) }}
                            title="Delete"
                          >
                            <TrashIcon size={12} />
                          </button>
                        </>
                      )}
                    </span>
                  </div>
                ))
              )}
              {listingTotal !== null && (
                <div className={styles.truncatedNotice} role="status">
                  Showing the first {entries.length.toLocaleString()} of {listingTotal.toLocaleString()} entries.
                  Narrow the folder or download it. The filter searches only the entries shown.
                </div>
              )}
            </div>
          )}
        </>
      )}

      {tab === 'jobs' && (
        <>
          <div className={styles.breadcrumb}>
            <span style={{ flex: 1 }}>Background jobs</span>
            <button
              className={styles.actionBtn}
              onClick={() => fetchJobs()}
              title="Refresh"
            >
              <RefreshCw size={12} />
            </button>
          </div>
          {jobsLoading && jobs.length === 0 && <div className={styles.loading}>Loading…</div>}
          {jobsError && <div className={styles.error}>Error: {jobsError}</div>}
          {!jobsError && (
            <div className={styles.jobList}>
              {jobs.length === 0 ? (
                <div className={styles.empty}>No background jobs.</div>
              ) : (
                jobs.map((j) => (
                  <div key={j.job_id} className={styles.job}>
                    <Briefcase size={14} />
                    <span className={styles.jobName} title={j.tool_name}>
                      {j.label || j.tool_name}
                      <span className={styles.jobMeta} style={{ marginLeft: 8 }}>
                        <span className={`${styles.statusBadge} ${statusClass(j.status)}`}>
                          {j.status}
                        </span>
                        <span>{formatElapsed(j.started_at, j.ended_at)}</span>
                        {j.size_bytes !== undefined && (
                          <span>{formatSize(j.size_bytes)}</span>
                        )}
                      </span>
                    </span>
                    <span className={styles.jobActions}>
                      <button
                        className={styles.actionBtn}
                        onClick={() => handleViewJobLog(j)}
                        title="View log in Files tab"
                      >
                        <Eye size={12} />
                      </button>
                      {j.status === 'running' && (
                        <button
                          className={`${styles.actionBtn} ${styles.actionBtnDanger}`}
                          onClick={() => handleCancelJob(j)}
                          title="Cancel job"
                        >
                          <XCircle size={12} />
                        </button>
                      )}
                    </span>
                  </div>
                ))
              )}
            </div>
          )}
        </>
      )}

      {/* Drag-drop overlay - rendered on top of whichever tab is active. */}
      <div
        className={`${styles.dropZone} ${isDragging ? styles.dropZoneActive : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {isDragging && (
          <div className={styles.dropHint}>
            <UploadIcon size={32} />
            <div>Drop to upload to {currentPath === '.' ? 'workspace root' : currentPath}</div>
          </div>
        )}
      </div>

      {/* Delete confirmation modal - replaces window.confirm so the user
          sees a clear in-context dialog (especially for recursive folder
          deletes that wipe many files). */}
      {deletePending && (
        <div className={styles.modalBackdrop} onClick={() => setDeletePending(null)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <AlertTriangle size={18} />
              <span>Delete {deletePending.isDir ? 'folder' : 'file'}?</span>
            </div>
            <div className={styles.modalBody}>
              {deletePending.isDir ? (
                <>
                  <code>{deletePending.path}</code> and <strong>all its contents</strong>{' '}
                  will be permanently deleted. This cannot be undone.
                </>
              ) : (
                <>
                  <code>{deletePending.path}</code> will be permanently deleted.
                </>
              )}
            </div>
            <div className={styles.modalActions}>
              <button
                className={styles.modalBtn}
                onClick={() => setDeletePending(null)}
              >
                Cancel
              </button>
              <button
                className={`${styles.modalBtn} ${styles.modalBtnDanger}`}
                onClick={() => performDelete(deletePending)}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk delete confirmation - lists how many will be deleted +
          whether the dir-recursion warning applies. */}
      {bulkDeletePending && (
        <div className={styles.modalBackdrop} onClick={() => setBulkDeletePending(null)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <AlertTriangle size={18} />
              <span>Delete {bulkDeletePending.length} {bulkDeletePending.length === 1 ? 'entry' : 'entries'}?</span>
            </div>
            <div className={styles.modalBody}>
              {bulkDeletePending.some(e => e.isDir) && (
                <p>One or more directories will be deleted <strong>recursively</strong>.</p>
              )}
              <p>This cannot be undone. Entries to delete:</p>
              <ul className={styles.bulkList}>
                {bulkDeletePending.slice(0, 10).map(e => (
                  <li key={e.path}><code>{e.path}</code>{e.isDir ? ' /' : ''}</li>
                ))}
                {bulkDeletePending.length > 10 && (
                  <li>… and {bulkDeletePending.length - 10} more</li>
                )}
              </ul>
              {selectedPaths.size > bulkDeletePending.length && (
                <p className={styles.bulkHint}>
                  {selectedPaths.size - bulkDeletePending.length} protected default folder(s) will be skipped.
                </p>
              )}
            </div>
            <div className={styles.modalActions}>
              <button
                className={styles.modalBtn}
                onClick={() => setBulkDeletePending(null)}
                disabled={bulkActionLoading}
              >
                Cancel
              </button>
              <button
                className={`${styles.modalBtn} ${styles.modalBtnDanger}`}
                onClick={() => performBulkDelete(bulkDeletePending)}
                disabled={bulkActionLoading}
              >
                {bulkActionLoading ? 'Deleting…' : `Delete ${bulkDeletePending.length}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Properties popover - read-only metadata (size, mtime, mode, sha256,
          symlink target). Triggered by the Info button per row. */}
      {propertiesFor && (
        <div className={styles.modalBackdrop} onClick={closeProperties}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <Info size={18} />
              <span>Properties</span>
            </div>
            <div className={styles.modalBody}>
              {propertiesLoading && <div>Loading…</div>}
              {propertiesError && (
                <div className={styles.error}>Error: {propertiesError}</div>
              )}
              {!propertiesLoading && !propertiesError && (
                <table className={styles.propertiesTable}>
                  <tbody>
                    <tr>
                      <th>Path</th>
                      <td><code>{propertiesFor.path}</code></td>
                    </tr>
                    <tr><th>Type</th><td>{propertiesFor.type}</td></tr>
                    {propertiesFor.type !== 'dir' && (
                      <tr><th>Size</th><td>{formatSize(propertiesFor.size)} ({propertiesFor.size} B)</td></tr>
                    )}
                    <tr><th>Modified</th><td>{formatMtime(propertiesFor.mtime)}</td></tr>
                    <tr><th>Mode</th><td><code>{propertiesFor.mode}</code></td></tr>
                    {propertiesFor.sha256 && (
                      <tr>
                        <th>SHA-256</th>
                        <td><code className={styles.hashCode}>{propertiesFor.sha256}</code></td>
                      </tr>
                    )}
                    {propertiesFor.target && (
                      <tr>
                        <th>Symlink target</th>
                        <td><code>{propertiesFor.target}</code></td>
                      </tr>
                    )}
                  </tbody>
                </table>
              )}
            </div>
            <div className={styles.modalActions}>
              <button className={styles.modalBtn} onClick={closeProperties}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Overwrite confirmation modal - shown when upload returns 409. */}
      {overwritePending && (
        <div className={styles.modalBackdrop} onClick={() => setOverwritePending(null)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <AlertTriangle size={18} />
              <span>File already exists</span>
            </div>
            <div className={styles.modalBody}>
              <code>{overwritePending.file.name}</code> already exists in{' '}
              <code>{overwritePending.destDir === '.' ? 'workspace root' : overwritePending.destDir}</code>.
              Replace it?
            </div>
            <div className={styles.modalActions}>
              <button
                className={styles.modalBtn}
                onClick={() => setOverwritePending(null)}
              >
                Cancel
              </button>
              <button
                className={`${styles.modalBtn} ${styles.modalBtnDanger}`}
                onClick={handleConfirmOverwrite}
              >
                Overwrite
              </button>
            </div>
          </div>
        </div>
      )}
    </Drawer>
  )
}
