'use client'

import { useEffect, useState } from 'react'
import { Braces, ChevronDown, Play, Plus, Trash2 } from 'lucide-react'
import type { Project } from '@prisma/client'
import { Toggle, WikiInfoButton } from '@/components/ui'
import { field } from '@/lib/reconSettings/registry'
import { documentInProjectScope } from '@/lib/openapiSourceStatus'
import { useOpenApiSourceLabels } from '@/hooks/useOpenApiSourceLabels'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { numericDefault } from '../formDefaults'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface OpenApiSource {
  id?: string
  url: string
  serverOverride?: string
  enabled?: boolean
}

interface OpenApiSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
  /** Edit mode: the last runs' per-document status is read for this project. */
  projectId?: string
}

export const OPENAPI_IDLE_MESSAGE = 'No documents configured and Auto-discover is off'

const DEFAULT_DISCOVERY_PATHS: string[] = (() => {
  const value = field('openapiDiscoveryPaths')?.default
  return Array.isArray(value) ? value.filter((p): p is string => typeof p === 'string') : []
})()

function arrayValue<T>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : []
}

// ProjectForm's pattern: crypto.randomUUID is missing on a plain-HTTP origin.
function newSourceId(): string {
  return typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : `src-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}

function clamp(raw: string, min: number, max: number, cleared: number): number {
  const n = Number.parseInt(raw, 10)
  return Number.isNaN(n) ? cleared : Math.min(max, Math.max(min, n))
}

const BADGE_TONES: Record<string, string> = {
  Imported: 'success',
  'Not fetched yet': 'muted',
}

function StatusBadge({ label }: { label: string }) {
  return (
    <span className={styles.statusBadge} data-tone={BADGE_TONES[label] ?? 'warning'}>
      {label}
    </span>
  )
}

export function OpenApiSection({ data, updateField, onRun, projectId }: OpenApiSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [statusEntries, setStatusEntries] = useState<unknown>(undefined)
  const enabled = data.openapiEnabled ?? true
  const autoDiscover = data.openapiAutoDiscover ?? false
  const discoveryPaths = data.openapiDiscoveryPaths ?? DEFAULT_DISCOVERY_PATHS
  const sources = arrayValue<OpenApiSource>(data.openapiSources)
  const idle = enabled && !autoDiscover && !sources.some(s => s?.enabled !== false && s?.url)
  const labels = useOpenApiSourceLabels(statusEntries, sources)

  useEffect(() => {
    if (!projectId) return
    let cancelled = false
    fetch(`/api/recon/${projectId}/graph-inputs/OpenAPI`)
      .then(res => (res.ok ? res.json() : null))
      .then(body => { if (!cancelled) setStatusEntries(body?.openapiSourceStatus ?? null) })
      .catch(() => { if (!cancelled) setStatusEntries(null) })
    return () => { cancelled = true }
  }, [projectId])

  const setSources = (next: OpenApiSource[]) => {
    updateField('openapiSources', next as unknown as FormData['openapiSources'])
  }
  const updateSource = (index: number, patch: Partial<OpenApiSource>) => {
    setSources(sources.map((source, sourceIndex) => sourceIndex === index ? { ...source, ...patch } : source))
  }
  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Braces size={16} /> OpenAPI Import
          <NodeInfoTooltip section="OpenAPI" />
          <WikiInfoButton target="OpenAPI" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button type="button" onClick={(event) => { event.stopPropagation(); onRun() }} className={styles.runPartialButton} title="Run OpenAPI import">
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(event) => event.stopPropagation()}>
            <Toggle checked={enabled} onChange={(checked) => updateField('openapiEnabled', checked)} />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Imports the endpoints declared in Swagger 2.0 and OpenAPI 3.0/3.1 documents. OpenAPI never calls a
            declared operation. Later scanners request an endpoint known only from a specification with GET or HEAD
            only. Nuclei templates send their own requests to such an endpoint, as to any other target URL. It runs
            inside Resource Enumeration and follows its toggle and its conditions: no import without live targets,
            and none in stealth mode. A partial run imports a document without a full recon.
          </p>

          {enabled && idle && (
            <p className={styles.fieldHint} role="status">
              {OPENAPI_IDLE_MESSAGE}: this step has nothing to import.
            </p>
          )}

          {enabled && (
            <>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Auto-discover</span>
                  <p className={styles.toggleDescription}>Look for documents on live BaseURLs, crawled API documentation paths and the discovery paths below.</p>
                </div>
                <Toggle checked={autoDiscover} onChange={(checked) => updateField('openapiAutoDiscover', checked)} />
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Discovery paths</h3>
                <p className={styles.fieldHint}>Paths to try on each discovered HTTP origin, at most 200. Start with /, no query or fragment. An empty list skips common-path probes; discovered links and configured documents still work.</p>
                {discoveryPaths.length > 0 && (
                  <div className={styles.itemList}>
                    {discoveryPaths.map((path, index) => (
                      <div className={styles.listInputRow} key={`openapi-path-${index}`}>
                        <input className="textInput" aria-label={`Discovery path ${index + 1}`} value={path} placeholder="/api-docs/" onChange={(event) => updateField('openapiDiscoveryPaths', discoveryPaths.map((value, i) => i === index ? event.target.value : value))} />
                        <button type="button" className={styles.removeButton} aria-label={`Remove discovery path ${index + 1}`} title="Remove" onClick={() => updateField('openapiDiscoveryPaths', discoveryPaths.filter((_, i) => i !== index))}><Trash2 size={14} /></button>
                      </div>
                    ))}
                  </div>
                )}
                <div className={styles.controlRow}>
                  <button type="button" className={styles.actionButton} disabled={discoveryPaths.length >= 200} onClick={() => updateField('openapiDiscoveryPaths', [...discoveryPaths, ''])}><Plus size={14} /> Add path</button>
                  <button type="button" className="secondaryButton" onClick={() => updateField('openapiDiscoveryPaths', [...DEFAULT_DISCOVERY_PATHS])}>Restore defaults</button>
                </div>
              </div>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Fetch timeout (seconds)</label>
                  <input type="number" className="textInput" min={1} max={60} value={data.openapiTimeout ?? 10} onChange={(event) => updateField('openapiTimeout', clamp(event.target.value, 1, 60, numericDefault('openapiTimeout')))} />
                  <span className={styles.fieldHint}>Per-document HTTP timeout, from 1 to 60 seconds.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Maximum documents</label>
                  <input type="number" className="textInput" min={1} max={200} value={data.openapiMaxDocuments ?? 50} onChange={(event) => updateField('openapiMaxDocuments', clamp(event.target.value, 1, 200, numericDefault('openapiMaxDocuments')))} />
                  <span className={styles.fieldHint}>Specification documents imported per run, from 1 to 200.</span>
                </div>
              </div>

              <div className={styles.groupHeader}>
                <h3 className={styles.subSectionTitle}>Configured documents</h3>
                <p className={styles.fieldHint}>
                  Protected specifications use the project&apos;s Authenticated Session; its headers and cookies are
                  sent only to the exact document origin. A token in a document URL is stored and exported with the
                  project. Endpoints a removed document declared are cleared at the next full recon. Rows left blank
                  are not saved.
                </p>
              </div>
              {sources.map((source, index) => {
                const inScope = source.url ? documentInProjectScope(source.url, data) : null
                return (
                  <div className={styles.subSection} key={source.id ?? `openapi-source-${index}`}>
                    <div className={styles.docCardHead}>
                      <div className={styles.sourceCardHeading}>
                        <strong className={styles.sourceCardTitle}>Source {index + 1}</strong>
                        {projectId && labels[index] && <StatusBadge label={labels[index]!} />}
                      </div>
                      <div className={styles.controlRow}>
                        <Toggle checked={source.enabled ?? true} onChange={(checked) => updateSource(index, { enabled: checked })} />
                        <button type="button" className={styles.removeButton} onClick={() => setSources(sources.filter((_, i) => i !== index))} aria-label={`Remove source ${index + 1}`} title="Remove"><Trash2 size={14} /></button>
                      </div>
                    </div>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Document URL</label>
                        <input type="url" className="textInput" value={source.url} placeholder="https://docs.example.test/openapi.json" onChange={(event) => updateSource(index, { url: event.target.value })} />
                        {inScope === false && (
                          <span className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
                            Outside the project scope: this document will be skipped.
                          </span>
                        )}
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Server override (optional)</label>
                        <input type="url" className="textInput" value={source.serverOverride ?? ''} placeholder="https://api.example.test/v2" onChange={(event) => updateSource(index, { serverOverride: event.target.value || undefined })} />
                      </div>
                    </div>
                  </div>
                )
              })}
              <button type="button" className={styles.actionButton} onClick={() => setSources([...sources, { id: newSourceId(), url: '', enabled: true }])}><Plus size={14} /> Add document</button>
            </>
          )}
        </div>
      )}
    </div>
  )
}
