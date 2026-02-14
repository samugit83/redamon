'use client'

import { useState, useEffect, useCallback } from 'react'
import { Save, X, Loader2, AlertTriangle } from 'lucide-react'
import type { Project } from '@prisma/client'
import styles from './ProjectForm.module.css'

// Import sections
import { TargetSection } from './sections/TargetSection'
import { ScanModulesSection } from './sections/ScanModulesSection'
import { NaabuSection } from './sections/NaabuSection'
import { HttpxSection } from './sections/HttpxSection'
import { NucleiSection } from './sections/NucleiSection'
import { KatanaSection } from './sections/KatanaSection'
import { GauSection } from './sections/GauSection'
import { KiterunnerSection } from './sections/KiterunnerSection'
import { CveLookupSection } from './sections/CveLookupSection'
import { MitreSection } from './sections/MitreSection'
import { SecurityChecksSection } from './sections/SecurityChecksSection'
import { GithubSection } from './sections/GithubSection'
import { AgentBehaviourSection } from './sections/AgentBehaviourSection'
import { CveExploitSection } from './sections/CveExploitSection'
import { BruteForceSection } from './sections/BruteForceSection'
import { GvmScanSection } from './sections/GvmScanSection'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ConflictResult {
  hasConflict: boolean
  conflictType: 'full_scan_exists' | 'full_scan_requested' | 'subdomain_overlap' | null
  conflictingProject: {
    id: string
    name: string
    targetDomain: string
    subdomainList: string[]
  } | null
  overlappingSubdomains: string[]
  message: string | null
}

interface ProjectFormProps {
  initialData?: Partial<ProjectFormData> & { id?: string }
  onSubmit: (data: ProjectFormData) => Promise<void>
  onCancel: () => void
  isSubmitting?: boolean
  mode: 'create' | 'edit'
}

const TABS = [
  { id: 'target', label: 'Target & Modules' },
  { id: 'port', label: 'Port Scanning' },
  { id: 'http', label: 'HTTP Probing' },
  { id: 'resource', label: 'Resource Enumeration' },
  { id: 'vuln', label: 'Vulnerability Scanning' },
  { id: 'cve', label: 'CVE & MITRE' },
  { id: 'security', label: 'Security Checks' },
  { id: 'gvm', label: 'GVM Scan' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'agent', label: 'Agent Behaviour' },
  { id: 'attack', label: 'Attack Paths' },
] as const

type TabId = typeof TABS[number]['id']

// Minimal fallback defaults - only required fields
// Full defaults are fetched from /api/projects/defaults (served by recon backend)
const MINIMAL_DEFAULTS: Partial<ProjectFormData> = {
  name: '',
  description: '',
  targetDomain: '',
  subdomainList: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}

// Fetch defaults from the recon backend (single source of truth)
async function fetchDefaults(): Promise<Partial<ProjectFormData>> {
  try {
    const response = await fetch('/api/projects/defaults')
    if (!response.ok) {
      console.warn('Failed to fetch defaults, using minimal fallback')
      return MINIMAL_DEFAULTS
    }
    const defaults = await response.json()
    // Merge with minimal defaults to ensure required fields exist
    return { ...MINIMAL_DEFAULTS, ...defaults }
  } catch (error) {
    console.warn('Error fetching defaults:', error)
    return MINIMAL_DEFAULTS
  }
}

export function ProjectForm({
  initialData,
  onSubmit,
  onCancel,
  isSubmitting = false,
  mode
}: ProjectFormProps) {
  const [activeTab, setActiveTab] = useState<TabId>('target')
  const [isLoadingDefaults, setIsLoadingDefaults] = useState(mode === 'create')
  const [formData, setFormData] = useState<ProjectFormData>(() => ({
    ...MINIMAL_DEFAULTS,
    ...initialData
  } as ProjectFormData))

  // Domain conflict checking
  const [conflict, setConflict] = useState<ConflictResult | null>(null)
  const [isCheckingConflict, setIsCheckingConflict] = useState(false)

  // Extract project ID for edit mode (to exclude from conflict check)
  const projectId = (initialData as { id?: string } | undefined)?.id

  // Check for domain conflicts when targetDomain or subdomainList changes
  const checkConflict = useCallback(async (targetDomain: string, subdomainList: string[]) => {
    if (!targetDomain.trim()) {
      setConflict(null)
      return
    }

    setIsCheckingConflict(true)
    try {
      const response = await fetch('/api/projects/check-conflict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetDomain,
          subdomainList,
          excludeProjectId: mode === 'edit' ? projectId : undefined,
        }),
      })

      if (response.ok) {
        const result: ConflictResult = await response.json()
        setConflict(result.hasConflict ? result : null)
      }
    } catch (error) {
      console.error('Failed to check conflict:', error)
    } finally {
      setIsCheckingConflict(false)
    }
  }, [mode, projectId])

  // Debounced conflict check when form data changes
  useEffect(() => {
    const timer = setTimeout(() => {
      checkConflict(formData.targetDomain || '', formData.subdomainList || [])
    }, 500) // 500ms debounce

    return () => clearTimeout(timer)
  }, [formData.targetDomain, formData.subdomainList, checkConflict])

  // Fetch defaults from backend on mount (only for create mode)
  useEffect(() => {
    if (mode === 'create') {
      fetchDefaults().then(defaults => {
        setFormData(prev => ({ ...defaults, ...prev, ...initialData } as ProjectFormData))
        setIsLoadingDefaults(false)
      })
    }
  }, [mode, initialData])

  const updateField = <K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.name.trim()) {
      alert('Project name is required')
      return
    }

    if (!formData.targetDomain.trim()) {
      alert('Target domain is required')
      return
    }

    // Block submission if there's a domain conflict
    if (conflict?.hasConflict) {
      alert('Cannot save project: ' + conflict.message)
      return
    }

    await onSubmit(formData)
  }

  // Determine if form can be submitted
  const canSubmit = !isSubmitting && !isLoadingDefaults && !conflict?.hasConflict && !isCheckingConflict

  return (
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          {mode === 'create' ? 'Create New Project' : 'Project Settings'}
        </h1>
        <div className={styles.actions}>
          <button
            type="button"
            className="secondaryButton"
            onClick={onCancel}
            disabled={isSubmitting}
          >
            <X size={14} />
            Cancel
          </button>
          <button
            type="submit"
            className="primaryButton"
            disabled={!canSubmit}
          >
            {isLoadingDefaults ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Loading...
              </>
            ) : isCheckingConflict ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Checking...
              </>
            ) : (
              <>
                <Save size={14} />
                {isSubmitting ? 'Saving...' : 'Save Project'}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Domain conflict warning banner */}
      {conflict?.hasConflict && (
        <div className={styles.conflictBanner}>
          <AlertTriangle size={20} className={styles.conflictIcon} />
          <div className={styles.conflictContent}>
            <div className={styles.conflictTitle}>Domain Conflict Detected</div>
            <div className={styles.conflictMessage}>{conflict.message}</div>
            {conflict.conflictingProject && (
              <div className={styles.conflictProject}>
                Conflicting project: <strong>{conflict.conflictingProject.name}</strong>
                {conflict.overlappingSubdomains.length > 0 && (
                  <> (subdomains: {conflict.overlappingSubdomains.join(', ')})</>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {isLoadingDefaults ? (
        <div className={styles.loadingContainer}>
          <Loader2 size={24} className={styles.spinner} />
          <p>Loading configuration defaults...</p>
        </div>
      ) : (
        <>
          <div className={styles.tabs}>
            {TABS.map(tab => (
              <button
                key={tab.id}
                type="button"
                className={`tab ${activeTab === tab.id ? 'tabActive' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className={styles.content}>
            {activeTab === 'target' && (
          <>
            <TargetSection data={formData} updateField={updateField} />
            <ScanModulesSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'port' && (
          <NaabuSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'http' && (
          <HttpxSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'resource' && (
          <>
            <KatanaSection data={formData} updateField={updateField} />
            <GauSection data={formData} updateField={updateField} />
            <KiterunnerSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'vuln' && (
          <NucleiSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'cve' && (
          <>
            <CveLookupSection data={formData} updateField={updateField} />
            <MitreSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'security' && (
          <SecurityChecksSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'integrations' && (
          <GithubSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'gvm' && (
          <GvmScanSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'agent' && (
          <AgentBehaviourSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'attack' && (
          <>
            <CveExploitSection data={formData} updateField={updateField} />
            <BruteForceSection data={formData} updateField={updateField} />
          </>
        )}
          </div>
        </>
      )}
    </form>
  )
}

export default ProjectForm
