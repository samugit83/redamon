'use client'

import { useState } from 'react'
import { ChevronDown, Layers } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ScanModulesSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const SCAN_MODULE_OPTIONS = [
  { id: 'domain_discovery', label: 'Domain Discovery', description: 'Subdomain enumeration', indent: 0 },
  { id: 'port_scan', label: 'Port Scanning', description: 'Naabu port scanner', indent: 1 },
  { id: 'http_probe', label: 'HTTP Probing', description: 'httpx HTTP analysis', indent: 2 },
  { id: 'resource_enum', label: 'Resource Enumeration', description: 'Katana, GAU, Kiterunner', indent: 3 },
  { id: 'vuln_scan', label: 'Vulnerability Scanning', description: 'Nuclei vulnerability scanner', indent: 3 },
]

// Module dependency tree: child → parent
const MODULE_DEPENDENCIES: Record<string, string | null> = {
  domain_discovery: null,
  port_scan: 'domain_discovery',
  http_probe: 'port_scan',
  resource_enum: 'http_probe',
  vuln_scan: 'http_probe',
}

// Get all modules that depend on a given module (direct + transitive)
function getDependentModules(moduleId: string): string[] {
  const dependents: string[] = []
  for (const [id, parent] of Object.entries(MODULE_DEPENDENCIES)) {
    if (parent === moduleId) {
      dependents.push(id, ...getDependentModules(id))
    }
  }
  return dependents
}

// Check if a module's parent chain is all enabled
function isParentEnabled(moduleId: string, enabledModules: string[]): boolean {
  const parent = MODULE_DEPENDENCIES[moduleId]
  if (parent === null) return true
  if (!enabledModules.includes(parent)) return false
  return isParentEnabled(parent, enabledModules)
}

export function ScanModulesSection({ data, updateField }: ScanModulesSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const toggleModule = (moduleId: string) => {
    const current = data.scanModules
    if (current.includes(moduleId)) {
      // Disabling: also disable all dependent modules
      const dependents = getDependentModules(moduleId)
      const toRemove = new Set([moduleId, ...dependents])
      updateField('scanModules', current.filter(m => !toRemove.has(m)))
    } else {
      // Enabling: also enable all parent modules in the chain
      const toAdd = [moduleId]
      let parent = MODULE_DEPENDENCIES[moduleId]
      while (parent !== null) {
        if (!current.includes(parent)) {
          toAdd.push(parent)
        }
        parent = MODULE_DEPENDENCIES[parent]
      }
      updateField('scanModules', [...current, ...toAdd])
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Layers size={16} />
          Scan Modules
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Control the reconnaissance pipeline by enabling or disabling specific modules. Each module builds upon the results of its parent, creating a comprehensive attack surface map from domain discovery through vulnerability detection.
          </p>
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Enabled Modules</h3>
            <p className={styles.fieldHint} style={{ marginBottom: '0.75rem' }}>
              Modules have dependencies: disabling a parent disables all children
            </p>
            {SCAN_MODULE_OPTIONS.map(module => {
              const isEnabled = data.scanModules.includes(module.id)
              const parentEnabled = isParentEnabled(module.id, data.scanModules)
              const isDisabledByParent = !parentEnabled && !isEnabled

              return (
                <div
                  key={module.id}
                  className={styles.toggleRow}
                  style={{
                    paddingLeft: `${module.indent * 1.25}rem`,
                    opacity: isDisabledByParent ? 0.5 : 1,
                  }}
                >
                  <div>
                    <span className={styles.toggleLabel}>
                      {module.indent > 0 && '└ '}
                      {module.label}
                    </span>
                    <p className={styles.toggleDescription}>
                      {module.description}
                      {isDisabledByParent && ' (requires parent module)'}
                    </p>
                  </div>
                  <Toggle
                    checked={isEnabled}
                    onChange={() => toggleModule(module.id)}
                  />
                </div>
              )
            })}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>General Options</h3>
            <div className={styles.toggleRow} style={{ opacity: 0.7 }}>
              <div>
                <span className={styles.toggleLabel}>Update Graph Database</span>
                <p className={styles.toggleDescription}>
                  Store scan results in Neo4j graph database (always enabled)
                </p>
              </div>
              <Toggle
                checked={true}
                onChange={() => {}}
                disabled
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Use Tor for Recon</span>
                <p className={styles.toggleDescription}>
                  Route reconnaissance traffic through Tor network
                </p>
              </div>
              <Toggle
                checked={data.useTorForRecon}
                onChange={(checked) => updateField('useTorForRecon', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Use Bruteforce for Subdomains</span>
                <p className={styles.toggleDescription}>
                  Use wordlist-based subdomain bruteforcing
                </p>
                <TimeEstimate estimate="+5-30 min depending on wordlist size" />
              </div>
              <Toggle
                checked={data.useBruteforceForSubdomains}
                onChange={(checked) => updateField('useBruteforceForSubdomains', checked)}
              />
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>WHOIS Max Retries</label>
              <input
                type="number"
                className="textInput"
                value={data.whoisMaxRetries}
                onChange={(e) => updateField('whoisMaxRetries', parseInt(e.target.value) || 6)}
                min={1}
                max={20}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>DNS Max Retries</label>
              <input
                type="number"
                className="textInput"
                value={data.dnsMaxRetries}
                onChange={(e) => updateField('dnsMaxRetries', parseInt(e.target.value) || 3)}
                min={1}
                max={10}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
