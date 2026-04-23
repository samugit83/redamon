'use client'

import { useState, useEffect } from 'react'
import { Loader2, AlertTriangle, Sparkles, RotateCcw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useToast } from '@/components/ui'
import formStyles from './ProjectForm.module.css'
import styles from './GeneratePresetModal.module.css'

interface GeneratePresetModalProps {
  isOpen: boolean
  onClose: () => void
  onSaved: () => void
  userId: string | null | undefined
  model: string
}

/** Summarise the generated parameters for the review step. */
function buildSummary(params: Record<string, unknown>) {
  const enabled: string[] = []
  const disabled: string[] = []
  const tuned: string[] = []

  // Tool name map for readable labels
  const toolNames: Record<string, string> = {
    naabuEnabled: 'Naabu',
    masscanEnabled: 'Masscan',
    nmapEnabled: 'Nmap',
    httpxEnabled: 'httpx',
    wappalyzerEnabled: 'Wappalyzer',
    bannerGrabEnabled: 'Banner Grab',
    katanaEnabled: 'Katana',
    hakrawlerEnabled: 'Hakrawler',
    jsluiceEnabled: 'jsluice',
    jsReconEnabled: 'JS Recon',
    ffufEnabled: 'ffuf',
    arjunEnabled: 'Arjun',
    gauEnabled: 'GAU',
    paramspiderEnabled: 'ParamSpider',
    kiterunnerEnabled: 'Kiterunner',
    nucleiEnabled: 'Nuclei',
    cveLookupEnabled: 'CVE Lookup',
    mitreEnabled: 'MITRE',
    securityCheckEnabled: 'Security Checks',
    osintEnrichmentEnabled: 'OSINT Enrichment',
    shodanEnabled: 'Shodan',
    urlscanEnabled: 'URLScan',
    censysEnabled: 'Censys',
    fofaEnabled: 'FOFA',
    otxEnabled: 'OTX',
    netlasEnabled: 'Netlas',
    virusTotalEnabled: 'VirusTotal',
    zoomEyeEnabled: 'ZoomEye',
    criminalIpEnabled: 'CriminalIP',
    uncoverEnabled: 'Uncover',
    subdomainDiscoveryEnabled: 'Subdomain Discovery',
    crtshEnabled: 'crt.sh',
    hackerTargetEnabled: 'HackerTarget',
    knockpyReconEnabled: 'Knockpy',
    subfinderEnabled: 'Subfinder',
    amassEnabled: 'Amass',
    purednsEnabled: 'PureDNS',
    whoisEnabled: 'WHOIS',
    dnsEnabled: 'DNS',
    trufflehogEnabled: 'Trufflehog',
  }

  for (const [key, value] of Object.entries(params)) {
    if (key.endsWith('Enabled') && typeof value === 'boolean') {
      const name = toolNames[key] || key.replace(/Enabled$/, '')
      if (value) enabled.push(name)
      else disabled.push(name)
    } else if (!key.endsWith('Enabled')) {
      tuned.push(key)
    }
  }

  return { enabled, disabled, tunedCount: tuned.length }
}

export function GeneratePresetModal({
  isOpen,
  onClose,
  onSaved,
  userId,
  model,
}: GeneratePresetModalProps) {
  const toast = useToast()

  // Step state
  const [step, setStep] = useState<'describe' | 'review'>('describe')
  const [prompt, setPrompt] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [errorDetails, setErrorDetails] = useState<string[]>([])
  const [generatedParams, setGeneratedParams] = useState<Record<string, unknown> | null>(null)

  // Save fields
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Reset on open
  useEffect(() => {
    if (isOpen) {
      setStep('describe')
      setPrompt('')
      setError(null)
      setErrorDetails([])
      setGeneratedParams(null)
      setName('')
      setDescription('')
    }
  }, [isOpen])

  const handleGenerate = async () => {
    if (!prompt.trim() || !userId) return

    setIsGenerating(true)
    setError(null)
    setErrorDetails([])

    try {
      const res = await fetch('/api/presets/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, model, prompt: prompt.trim() }),
      })

      const data = await res.json()

      if (!res.ok) {
        setError(data.error || 'Failed to generate preset')
        if (data.details) setErrorDetails(data.details)
        return
      }

      setGeneratedParams(data.parameters)
      setDescription(prompt.trim())
      setStep('review')
    } catch {
      setError('Network error. Check your connection and try again.')
    } finally {
      setIsGenerating(false)
    }
  }

  const handleSave = async () => {
    if (!name.trim() || !userId || !generatedParams) return

    setIsSaving(true)
    try {
      const res = await fetch('/api/presets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: name.trim(),
          description: description.trim(),
          settings: generatedParams,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save preset')
      }

      toast.success(`Preset "${name.trim()}" saved`, 'Preset Created')
      onSaved()
      onClose()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save preset')
    } finally {
      setIsSaving(false)
    }
  }

  const handleRegenerate = () => {
    setStep('describe')
    setGeneratedParams(null)
    setError(null)
    setErrorDetails([])
    setName('')
  }

  const summary = generatedParams ? buildSummary(generatedParams) : null

  // -- Describe step --
  if (step === 'describe') {
    return (
      <Modal
        isOpen={isOpen}
        onClose={onClose}
        title="Generate Recon Preset with AI"
        size="large"
        closeOnOverlayClick={false}
        closeOnEscape={false}
        footer={
          <>
            <button type="button" className="secondaryButton" onClick={onClose} disabled={isGenerating}>
              Cancel
            </button>
            <button
              type="button"
              className="primaryButton"
              onClick={handleGenerate}
              disabled={isGenerating || !prompt.trim()}
            >
              {isGenerating ? (
                <>
                  <Loader2 size={14} className={formStyles.spinner} />
                  Generating...
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  Generate
                </>
              )}
            </button>
          </>
        }
      >
        <div className={styles.promptArea}>
          <div className={styles.modelBadge}>
            <Sparkles size={12} />
            Model: {model || 'Not configured'}
          </div>

          <textarea
            className={`textarea ${styles.promptTextarea}`}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="Describe the reconnaissance strategy you want, e.g.:\n- Fast passive scan focused on subdomain discovery and OSINT, no active probing\n- Deep web app pentest with full crawling, directory fuzzing, and nuclei on all severities\n- Stealth mode: minimal noise, only passive tools, no port scanning"
            rows={5}
            autoFocus
            disabled={isGenerating}
          />

          {error && (
            <div className={styles.errorBanner}>
              <AlertTriangle size={14} />
              <div>
                {error}
                {errorDetails.length > 0 && (
                  <ul className={styles.errorDetails}>
                    {errorDetails.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      </Modal>
    )
  }

  // -- Review & Save step --
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Review Generated Preset"
      size="large"
      closeOnOverlayClick={false}
      closeOnEscape={false}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={handleRegenerate} disabled={isSaving}>
            <RotateCcw size={14} />
            Regenerate
          </button>
          <button
            type="button"
            className="primaryButton"
            onClick={handleSave}
            disabled={isSaving || !name.trim()}
          >
            {isSaving ? (
              <>
                <Loader2 size={14} className={formStyles.spinner} />
                Saving...
              </>
            ) : (
              'Save Preset'
            )}
          </button>
        </>
      }
    >
      <div className={styles.reviewArea}>
        {/* Summary */}
        {summary && (
          <div className={styles.summaryBox}>
            <h4>Generated Configuration</h4>
            {summary.enabled.length > 0 && (
              <div className={styles.summaryRow}>
                <span className={styles.summaryLabel}>Enabled:</span>
                <span className={styles.summaryValue}>
                  {summary.enabled.map((t) => (
                    <span key={t} className={styles.enabledTag}>{t}</span>
                  ))}
                </span>
              </div>
            )}
            {summary.disabled.length > 0 && (
              <div className={styles.summaryRow}>
                <span className={styles.summaryLabel}>Disabled:</span>
                <span className={styles.summaryValue}>
                  {summary.disabled.map((t) => (
                    <span key={t} className={styles.disabledTag}>{t}</span>
                  ))}
                </span>
              </div>
            )}
            {summary.tunedCount > 0 && (
              <div className={styles.summaryRow}>
                <span className={styles.summaryLabel}>Tuned:</span>
                <span className={styles.summaryValue}>{summary.tunedCount} numeric/array parameters adjusted</span>
              </div>
            )}
          </div>
        )}

        {/* Name & Description */}
        <div className={styles.formFields}>
          <div>
            <label className={`${formStyles.fieldLabel} ${formStyles.fieldLabelRequired}`}>
              Name
            </label>
            <input
              type="text"
              className="textInput"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Fast OSINT Scan"
              autoFocus
            />
          </div>
          <div>
            <label className={formStyles.fieldLabel}>
              Description
            </label>
            <textarea
              className="textarea"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              rows={3}
            />
          </div>
        </div>
      </div>
    </Modal>
  )
}
