'use client'

import { useState, useCallback } from 'react'
import type { Project } from '@prisma/client'
import { Save, Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui'
import { WORKFLOW_TOOLS } from './workflowDefinition'

// Section component imports
import { SubdomainDiscoverySection } from '../sections/SubdomainDiscoverySection'
import { UrlscanSection } from '../sections/UrlscanSection'
import { ShodanSection } from '../sections/ShodanSection'
import { OsintEnrichmentSection } from '../sections/OsintEnrichmentSection'
import { NaabuSection } from '../sections/NaabuSection'
import { MasscanSection } from '../sections/MasscanSection'
import { NmapSection } from '../sections/NmapSection'
import { HttpxSection } from '../sections/HttpxSection'
import { KatanaSection } from '../sections/KatanaSection'
import { HakrawlerSection } from '../sections/HakrawlerSection'
import { JsluiceSection } from '../sections/JsluiceSection'
import { FfufSection } from '../sections/FfufSection'
import { GauSection } from '../sections/GauSection'
import { ParamSpiderSection } from '../sections/ParamSpiderSection'
import { KiterunnerSection } from '../sections/KiterunnerSection'
import { ArjunSection } from '../sections/ArjunSection'
import { JsReconSection } from '../sections/JsReconSection'
import { NucleiSection } from '../sections/NucleiSection'
import { GraphqlScanSection } from '../sections/GraphqlScanSection'
import { TakeoverSection } from '../sections/TakeoverSection'
import { CveLookupSection } from '../sections/CveLookupSection'
import { MitreSection } from '../sections/MitreSection'
import { SecurityChecksSection } from '../sections/SecurityChecksSection'
import { TargetSection } from '../sections/TargetSection'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface WorkflowNodeModalProps {
  toolId: string | null
  onClose: () => void
  onSave?: () => Promise<void>
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode: 'create' | 'edit'
}

export function WorkflowNodeModal({
  toolId,
  onClose,
  onSave,
  data,
  updateField,
  projectId,
  mode,
}: WorkflowNodeModalProps) {
  const [isSaving, setIsSaving] = useState(false)

  const handleSave = useCallback(async () => {
    if (!onSave || isSaving) return
    setIsSaving(true)
    try {
      await onSave()
      onClose()
    } catch {
      // errors handled by onSave caller
    } finally {
      setIsSaving(false)
    }
  }, [onSave, onClose, isSaving])

  if (!toolId) return null

  const isInput = toolId === 'input'
  const toolDef = isInput ? null : WORKFLOW_TOOLS.find(t => t.id === toolId)
  const title = isInput ? 'Target & Modules' : (toolDef?.label ?? toolId)

  function renderSection() {
    const baseProps = { data, updateField }
    const extendedProps = { ...baseProps, projectId, mode }

    switch (toolId) {
      case 'SubdomainDiscovery': return <SubdomainDiscoverySection {...baseProps} />
      case 'Urlscan':           return <UrlscanSection {...baseProps} />
      case 'Shodan':            return <ShodanSection {...baseProps} />
      case 'OsintEnrichment':   return <OsintEnrichmentSection {...baseProps} />
      case 'Naabu':             return <NaabuSection {...baseProps} />
      case 'Masscan':           return <MasscanSection {...baseProps} />
      case 'Nmap':              return <NmapSection {...baseProps} />
      case 'Httpx':             return <HttpxSection {...baseProps} />
      case 'Katana':            return <KatanaSection {...baseProps} />
      case 'Hakrawler':         return <HakrawlerSection {...baseProps} />
      case 'Jsluice':           return <JsluiceSection {...baseProps} />
      case 'Ffuf':              return <FfufSection {...extendedProps} />
      case 'Gau':               return <GauSection {...baseProps} />
      case 'ParamSpider':       return <ParamSpiderSection {...baseProps} />
      case 'Kiterunner':        return <KiterunnerSection {...baseProps} />
      case 'Arjun':             return <ArjunSection {...baseProps} />
      case 'JsRecon':           return <JsReconSection {...extendedProps} />
      case 'Nuclei':            return <NucleiSection {...baseProps} />
      case 'GraphqlScan':       return <GraphqlScanSection {...extendedProps} />
      case 'SubdomainTakeover': return <TakeoverSection {...baseProps} />
      case 'CveLookup':         return <CveLookupSection {...baseProps} />
      case 'Mitre':             return <MitreSection {...baseProps} />
      case 'SecurityChecks':    return <SecurityChecksSection {...baseProps} />
      case 'Uncover':           return <OsintEnrichmentSection {...baseProps} />
      case 'input':             return <TargetSection {...extendedProps} />
      default:                  return <p>No settings available for this module.</p>
    }
  }

  return (
    <Modal
      isOpen={!!toolId}
      onClose={onClose}
      title={title}
      size="large"
      closeOnOverlayClick={false}
      closeOnEscape={false}
      headerActions={onSave && (
        <button
          type="button"
          className="primaryButton"
          onClick={handleSave}
          disabled={isSaving}
          style={{ fontSize: '12px', padding: '4px 12px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
        >
          {isSaving ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <Save size={12} />}
          {isSaving ? 'Saving...' : 'Update Settings'}
        </button>
      )}
    >
      {renderSection()}
    </Modal>
  )
}
