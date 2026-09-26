'use client'

import { DEFAULT_OPENAPI_DISCOVERY_PATHS } from '@/lib/openapi-defaults'
import { useState } from 'react'
import { Braces, ChevronDown, Play, Plus, Trash2 } from 'lucide-react'
import type { Project } from '@prisma/client'
import { Toggle } from '@/components/ui'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

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
}

function arrayValue<T>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : []
}

export function OpenApiSection({ data, updateField, onRun }: OpenApiSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const discoveryPaths = data.openapiDiscoveryPaths ?? DEFAULT_OPENAPI_DISCOVERY_PATHS
  const sources = arrayValue<OpenApiSource>(data.openapiSources)

  const setSources = (next: OpenApiSource[]) => {
    updateField('openapiSources', next as unknown as FormData['openapiSources'])
  }
  const updateSource = (index: number, patch: Partial<OpenApiSource>) => {
    setSources(sources.map((source, sourceIndex) => sourceIndex === index ? { ...source, ...patch } : source))
  }
  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Braces size={16} /> OpenAPI Ingestion
          <NodeInfoTooltip section="OpenAPI" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && (data.openapiEnabled ?? true) && (
            <button type="button" onClick={(event) => { event.stopPropagation(); onRun() }} className="secondaryButton" title="Run OpenAPI ingestion">
              <Play size={11} /> Run partial recon
            </button>
          )}
          <div onClick={(event) => event.stopPropagation()}>
            <Toggle checked={data.openapiEnabled ?? true} onChange={(checked) => updateField('openapiEnabled', checked)} />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Imports endpoint declarations from Swagger 2.0 and OpenAPI 3.0/3.1 documents without invoking the declared operations. Only operations inside the project scope enter the graph.
          </p>

          {(data.openapiEnabled ?? true) && (
            <>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Automatic discovery</span>
                  <p className={styles.toggleDescription}>Inspect crawl results and bounded common paths for OpenAPI documents.</p>
                </div>
                <Toggle checked={data.openapiAutoDiscover ?? false} onChange={(checked) => updateField('openapiAutoDiscover', checked)} />
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Discovery paths</h3>
                <p className={styles.fieldHint}>Paths to try on each discovered HTTP origin. Start with /. An empty list skips common-path probes; discovered links and configured documents still work.</p>
                {discoveryPaths.map((path, index) => (
                  <div className={styles.fieldRow} key={`openapi-path-${index}`}>
                    <input className="textInput" aria-label={`Discovery path ${index + 1}`} value={path} placeholder="/api-docs/" onChange={(event) => updateField('openapiDiscoveryPaths', discoveryPaths.map((value, i) => i === index ? event.target.value : value))} />
                    <button type="button" className="iconButton" aria-label={`Remove discovery path ${index + 1}`} onClick={() => updateField('openapiDiscoveryPaths', discoveryPaths.filter((_, i) => i !== index))}><Trash2 size={14} /></button>
                  </div>
                ))}
                <button type="button" className="secondaryButton" disabled={discoveryPaths.length >= 200} onClick={() => updateField('openapiDiscoveryPaths', [...discoveryPaths, ''])}><Plus size={14} /> Add path</button>
                <button type="button" className="secondaryButton" onClick={() => updateField('openapiDiscoveryPaths', [...DEFAULT_OPENAPI_DISCOVERY_PATHS])}>Restore defaults</button>
              </div>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Fetch timeout (seconds)</label>
                  <input type="number" className="textInput" min={1} max={60} value={data.openapiTimeout ?? 10} onChange={(event) => updateField('openapiTimeout', Number.parseInt(event.target.value, 10) || 10)} />
                  <span className={styles.fieldHint}>Per-document HTTP timeout, from 1 to 60 seconds.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Maximum documents</label>
                  <input type="number" className="textInput" min={1} max={200} value={data.openapiMaxDocuments ?? 50} onChange={(event) => updateField('openapiMaxDocuments', Number.parseInt(event.target.value, 10) || 50)} />
                  <span className={styles.fieldHint}>Maximum specification documents to import.</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Configured documents</h3>
                <p className={styles.fieldHint}>Protected specifications use the project’s Authenticated Session. Configure credentials there; session headers and cookies are sent only to allowed origins.</p>
                {sources.map((source, index) => (
                  <div className={styles.subSection} key={`openapi-source-${index}`}>
                    <div className={styles.toggleRow}>
                      <span className={styles.toggleLabel}>Source {index + 1}</span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Toggle checked={source.enabled ?? true} onChange={(checked) => updateSource(index, { enabled: checked })} />
                        <button type="button" className="iconButton" onClick={() => setSources(sources.filter((_, i) => i !== index))} aria-label={`Remove source ${index + 1}`}><Trash2 size={14} /></button>
                      </div>
                    </div>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Document URL</label>
                        <input type="url" className="textInput" value={source.url} placeholder="https://docs.example.test/openapi.json" onChange={(event) => updateSource(index, { url: event.target.value })} />
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Server override (optional)</label>
                        <input type="url" className="textInput" value={source.serverOverride ?? ''} placeholder="https://api.example.test/v2" onChange={(event) => updateSource(index, { serverOverride: event.target.value || undefined })} />
                      </div>
                    </div>
                  </div>
                ))}
                <button type="button" className="secondaryButton" onClick={() => setSources([...sources, { id: crypto.randomUUID(), url: '', enabled: true }])}><Plus size={14} /> Add document</button>
              </div>

            </>
          )}
        </div>
      )}
    </div>
  )
}
