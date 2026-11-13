'use client'

import React, { useState } from 'react'
import { Download, FileCode, Loader2, AlertCircle, CheckCircle } from 'lucide-react'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './FileDownloadCard.module.css'

interface FileDownloadCardProps {
  filepath: string
  filename: string
  description: string
  source: string
  /** The run's project, whose workspace holds the file. A card from an older message has none. */
  projectId?: string
}

/**
 * Cards of messages written before downloads were scoped to a project point at the shared
 * sandbox's /tmp and name no project: the route refuses them, so say why instead of asking.
 */
const OUTSIDE_WORKSPACE = 'This file was saved outside the project\'s workspace and cannot be downloaded from the chat. Ask the agent to save it again.'

export function FileDownloadCard({ filepath, filename, description, source, projectId }: FileDownloadCardProps) {
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [downloaded, setDownloaded] = useState(false)

  const handleDownload = async () => {
    if (!projectId) {
      setError(OUTSIDE_WORKSPACE)
      return
    }
    setDownloading(true)
    setError(null)

    try {
      const resp = await fetch(`/api/agent/files?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(filepath)}`)

      if (!resp.ok) throw await readApiError(resp, 'Download failed')

      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      setDownloaded(true)
    } catch (err) {
      setError(toApiError(err, 'Download failed').message)
    } finally {
      setDownloading(false)
    }
  }

  const ext = filename.split('.').pop()?.toLowerCase() || ''
  const dangerExts = ['exe', 'elf', 'apk', 'hta', 'lnk', 'ps1', 'vba', 'war', 'macho']
  const isDangerous = dangerExts.includes(ext)

  return (
    <div className={styles.card} style={{ position: 'relative' }}>
      <div className={styles.iconContainer}>
        <FileCode size={20} className={isDangerous ? styles.iconDanger : styles.iconNormal} />
      </div>
      <div className={styles.info}>
        <div className={styles.filename}>{filename}</div>
        <div className={styles.description}>{description}</div>
        <div className={styles.meta}>
          <span className={styles.source}>{source}</span>
          <span className={styles.path}>{filepath}</span>
        </div>
      </div>
      <button
        className={`${styles.downloadButton} ${downloaded ? styles.downloaded : ''}`}
        onClick={handleDownload}
        disabled={downloading}
        title={downloaded ? 'Download again' : 'Download file'}
      >
        {downloading ? (
          <Loader2 size={16} className={styles.spinner} />
        ) : downloaded ? (
          <CheckCircle size={16} />
        ) : (
          <Download size={16} />
        )}
      </button>
      {error && (
        <div className={styles.error}>
          <AlertCircle size={12} />
          <span>{error}</span>
        </div>
      )}
    </div>
  )
}
