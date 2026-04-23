'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { ChevronDown, FolderSearch, Upload, X, Loader2, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

const BUILTIN_WORDLISTS = [
  { name: 'common.txt', path: '/usr/share/seclists/Discovery/Web-Content/common.txt' },
  { name: 'directory-list-2.3-small.txt', path: '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt' },
  { name: 'raft-medium-directories.txt', path: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt' },
]

const DEFAULT_WORDLIST = BUILTIN_WORDLISTS[0].path

interface CustomWordlist {
  name: string
  path: string
  size: number
}

interface FfufSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode: 'create' | 'edit'
  onRun?: () => void
}

export function FfufSection({ data, updateField, projectId, mode, onRun }: FfufSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [customWordlists, setCustomWordlists] = useState<CustomWordlist[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const canUpload = !!projectId

  const fetchCustomWordlists = useCallback(async () => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}/wordlists`)
      if (res.ok) {
        const json = await res.json()
        setCustomWordlists(json.wordlists || [])
      }
    } catch {
      // Silently fail -- custom wordlists just won't appear
    }
  }, [projectId])

  useEffect(() => {
    fetchCustomWordlists()
  }, [fetchCustomWordlists])

  const handleUpload = async (file: File) => {
    if (!projectId) return
    setIsUploading(true)
    setUploadError(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const res = await fetch(`/api/projects/${projectId}/wordlists`, {
        method: 'POST',
        body: formData,
      })

      const result = await res.json()

      if (!res.ok) {
        setUploadError(result.error || 'Upload failed')
        return
      }

      setCustomWordlists(result.wordlists || [])
      if (result.uploaded?.path) {
        updateField('ffufWordlist', result.uploaded.path)
      }
    } catch {
      setUploadError('Upload failed. Please try again.')
    } finally {
      setIsUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleDelete = async (name: string) => {
    if (!projectId) return

    try {
      const res = await fetch(
        `/api/projects/${projectId}/wordlists?name=${encodeURIComponent(name)}`,
        { method: 'DELETE' }
      )

      if (res.ok) {
        const result = await res.json()
        setCustomWordlists(result.wordlists || [])

        const deletedPath = `/app/recon/wordlists/${projectId}/${name}`
        if (data.ffufWordlist === deletedPath) {
          updateField('ffufWordlist', DEFAULT_WORDLIST)
        }
      }
    } catch {
      // Silently fail
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <FolderSearch size={16} />
          FFuf Directory Fuzzer
          <NodeInfoTooltip section="Ffuf" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.ffufEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run FFuf"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.ffufEnabled}
              onChange={(checked) => updateField('ffufEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Fast directory and endpoint fuzzer that brute-forces common paths using wordlists. Discovers hidden content (admin panels, backup files, configs, undocumented APIs) that crawlers cannot find. Runs after crawlers complete and can target discovered base paths for smart fuzzing.
          </p>

          {data.ffufEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufThreads}
                    onChange={(e) => updateField('ffufThreads', parseInt(e.target.value) || 40)}
                    min={1}
                    max={200}
                  />
                  <span className={styles.fieldHint}>Concurrent request threads</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit (req/s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufRate}
                    onChange={(e) => updateField('ffufRate', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Max requests per second (0 = unlimited)</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Parallelism</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufParallelism ?? 3}
                    onChange={(e) => updateField('ffufParallelism', parseInt(e.target.value) || 3)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Number of targets to fuzz in parallel</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Timeout (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufTimeout}
                    onChange={(e) => updateField('ffufTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Per-request timeout</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Time (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufMaxTime}
                    onChange={(e) => updateField('ffufMaxTime', parseInt(e.target.value) || 600)}
                    min={60}
                  />
                  <span className={styles.fieldHint}>Maximum total execution time per target</span>
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>
                  Wordlist <span style={{ fontWeight: 400, color: 'var(--text-tertiary)' }}>(built-in or upload)</span>
                </label>
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 'var(--space-2)',
                    alignItems: 'stretch',
                  }}
                >
                  <div style={{ flex: '1 1 220px', minWidth: 0 }}>
                    <select
                      className="select"
                      value={data.ffufWordlist}
                      onChange={(e) => updateField('ffufWordlist', e.target.value || DEFAULT_WORDLIST)}
                      aria-label="FFuf wordlist"
                    >
                      <optgroup label="Built-in (SecLists in recon image)">
                        {BUILTIN_WORDLISTS.map((wl) => (
                          <option key={wl.path} value={wl.path}>
                            {wl.name}
                          </option>
                        ))}
                      </optgroup>
                      {canUpload && customWordlists.length === 0 && (
                        <optgroup label="Your custom lists">
                          <option disabled value="__ffuf_no_custom_yet__">
                            (None yet — use Upload .txt →)
                          </option>
                        </optgroup>
                      )}
                      {customWordlists.length > 0 && (
                        <optgroup label="Your custom lists">
                          {customWordlists.map((wl) => (
                            <option key={wl.path} value={wl.path}>
                              {wl.name} ({formatSize(wl.size)})
                            </option>
                          ))}
                        </optgroup>
                      )}
                    </select>
                  </div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,text/plain"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) handleUpload(file)
                    }}
                  />
                  <button
                    type="button"
                    className="primaryButton"
                    style={{
                      whiteSpace: 'nowrap',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      flex: '0 0 auto',
                      alignSelf: 'flex-start',
                    }}
                    onClick={() => (canUpload ? fileInputRef.current?.click() : undefined)}
                    disabled={isUploading || !canUpload}
                    title={
                      !canUpload
                        ? 'Save the project first to upload custom wordlists'
                        : 'Upload a .txt wordlist — it will appear under “Your custom lists” in the menu'
                    }
                  >
                    {isUploading ? <Loader2 size={14} className={styles.spinner} /> : <Upload size={14} />}
                    {isUploading ? 'Uploading...' : 'Upload .txt'}
                  </button>
                </div>
                {uploadError && (
                  <span className={styles.fieldHint} style={{ color: 'var(--status-error)' }}>
                    {uploadError}
                  </span>
                )}
                {!uploadError && !canUpload && (
                  <span className={styles.fieldHint}>
                    Save the project first; then you can upload .txt payload lists (max 50MB) and select them in the menu
                    above.
                  </span>
                )}
                {!uploadError && canUpload && (
                  <span className={styles.fieldHint}>
                    Custom files are <strong>not</strong> listed until you upload them. Click <strong>Upload .txt</strong>,
                    then choose your file under <strong>Your custom lists</strong> in the dropdown.
                  </span>
                )}
              </div>

              {customWordlists.length > 0 && canUpload && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Uploaded Wordlists</label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                    {customWordlists.map((wl) => (
                      <div
                        key={wl.name}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: 'var(--space-1) var(--space-2)',
                          background: 'var(--bg-tertiary)',
                          borderRadius: 'var(--radius-default)',
                          fontSize: 'var(--text-xs)',
                          border: data.ffufWordlist === wl.path ? '1px solid var(--accent-secondary)' : '1px solid var(--border-default)',
                        }}
                      >
                        <span style={{ color: 'var(--text-primary)' }}>
                          {wl.name}
                          <span style={{ color: 'var(--text-tertiary)', marginLeft: 'var(--space-2)' }}>
                            {formatSize(wl.size)}
                          </span>
                        </span>
                        <button
                          type="button"
                          onClick={() => handleDelete(wl.name)}
                          style={{
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            color: 'var(--text-tertiary)',
                            padding: '2px',
                            display: 'flex',
                            alignItems: 'center',
                          }}
                          title={`Delete ${wl.name}`}
                        >
                          <X size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Match Status Codes</label>
                  <input
                    type="text"
                    className="textInput"
                    value={(data.ffufMatchCodes ?? []).join(', ')}
                    onChange={(e) => updateField('ffufMatchCodes', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                  />
                  <span className={styles.fieldHint}>Include these HTTP status codes (comma-separated)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Filter Status Codes</label>
                  <input
                    type="text"
                    className="textInput"
                    value={(data.ffufFilterCodes ?? []).join(', ')}
                    onChange={(e) => updateField('ffufFilterCodes', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                  />
                  <span className={styles.fieldHint}>Exclude these HTTP status codes (comma-separated)</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Filter Response Size</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.ffufFilterSize}
                    onChange={(e) => updateField('ffufFilterSize', e.target.value)}
                    placeholder="e.g., 0 or 4242"
                  />
                  <span className={styles.fieldHint}>Exclude responses of this size (bytes). Useful for uniform error pages</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Extensions</label>
                  <input
                    type="text"
                    className="textInput"
                    value={(data.ffufExtensions ?? []).join(', ')}
                    onChange={(e) => updateField('ffufExtensions', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                    placeholder=".php, .bak, .env, .json"
                  />
                  <span className={styles.fieldHint}>File extensions to append to each word (comma-separated)</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Options</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Auto-Calibrate</span>
                    <p className={styles.toggleDescription}>Automatically filter false positives based on response patterns</p>
                  </div>
                  <Toggle
                    checked={data.ffufAutoCalibrate}
                    onChange={(checked) => updateField('ffufAutoCalibrate', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Smart Fuzz (Post-Crawler)</span>
                    <p className={styles.toggleDescription}>Also fuzz under base paths discovered by crawlers (e.g., /api/v1/FUZZ)</p>
                  </div>
                  <Toggle
                    checked={data.ffufSmartFuzz}
                    onChange={(checked) => updateField('ffufSmartFuzz', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Follow Redirects</span>
                    <p className={styles.toggleDescription}>Follow HTTP redirects. May lead to out-of-scope domains (filtered post-hoc)</p>
                  </div>
                  <Toggle
                    checked={data.ffufFollowRedirects}
                    onChange={(checked) => updateField('ffufFollowRedirects', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Recursion</span>
                    <p className={styles.toggleDescription}>Recursively fuzz discovered directories</p>
                  </div>
                  <Toggle
                    checked={data.ffufRecursion}
                    onChange={(checked) => updateField('ffufRecursion', checked)}
                  />
                </div>
                {data.ffufRecursion && (
                  <div className={styles.fieldGroup} style={{ marginTop: '0.5rem' }}>
                    <label className={styles.fieldLabel}>Recursion Depth</label>
                    <input
                      type="number"
                      className="textInput"
                      value={data.ffufRecursionDepth}
                      onChange={(e) => updateField('ffufRecursionDepth', parseInt(e.target.value) || 2)}
                      min={1}
                      max={5}
                    />
                  </div>
                )}
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Headers</label>
                  <textarea
                    className="textarea"
                    value={(data.ffufCustomHeaders ?? []).join('\n')}
                    onChange={(e) => updateField('ffufCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                    placeholder="Cookie: session=abc123&#10;Authorization: Bearer token..."
                    rows={3}
                  />
                  <span className={styles.fieldHint}>One header per line. Sent with every request</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
