'use client'

import { useState } from 'react'
import { ChevronDown, Play, Search } from 'lucide-react'
import { Toggle, WikiInfoButton, useAlertModal } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'
import { RegistryFields } from '../RegistryFields'
import { resolveScopeGroups } from '@/lib/scopeGroups'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SubdomainDiscoverySectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function SubdomainDiscoverySection({ data, updateField, onRun }: SubdomainDiscoverySectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { confirm } = useAlertModal()

  // When explicit Subdomain Prefixes are set in Target Configuration, the
  // backend runs in FILTERED mode and skips every discovery source. Lock the
  // master toggle OFF here so the UI matches actual pipeline behavior.
  // A Domain batch keeps its scope in domainBatchHosts and leaves subdomainList
  // EMPTY, so every check below reads as "no prefixes, no root" for it. That was
  // harmless while the backend force-disabled discovery for every batch; now the
  // toggle decides whether a `*` group may enumerate, so it needs its own branch
  // or it would promise single-domain behaviour a batch never performs.
  const batchMode = data.domainBatchMode === true
  // Counted as scope groups, not as `*` lines: a wildcard covered by a broader
  // one collapses into it, and an invalid line enumerates nothing.
  const batchEnumerated = batchMode
    ? resolveScopeGroups({ domainBatchMode: true, domainBatchHosts: data.domainBatchHosts ?? [] }).groups
      .filter(g => g.mode === 'enumerate').map(g => `*.${g.scanRoot}`)
    : []
  const batchWildcardCount = batchEnumerated.length
  const targetName = batchMode
    ? ''
    : resolveScopeGroups({ targetDomain: data.targetDomain, subdomainList: data.subdomainList }).groups[0]?.scanRoot
      || 'the target'

  const hasExplicitPrefixes = !batchMode && (data.subdomainList ?? []).some(
    (s) => s !== '.' && s.replace(/\.$/, '').length > 0
  )
  const lockReason = hasExplicitPrefixes
    ? 'Subdomain Discovery is disabled because explicit Subdomain Prefixes are set in Target Configuration. The pipeline runs in FILTERED mode and only resolves the prefixes you listed. Clear the prefixes to re-enable discovery.'
    : ''

  const includesRootDomain = (data.subdomainList ?? []).includes('.')

  // Intercept the master toggle. When switching OFF with no prefixes set and
  // "Include Root Domain" not already ON, warn the user that the pipeline
  // would have zero targets and that Include Root Domain will be auto-enabled
  // (TargetSection's forceIncludeRootDomain effect handles the actual flip).
  const handleMasterToggle = async (checked: boolean) => {
    if (!checked && batchMode) {
      // In a batch this toggle only ever governed the `*` groups; the literal
      // ones scan their own hostnames either way. Turning it off leaves a
      // wildcard group with nothing to enumerate, which the pipeline refuses
      // rather than silently reporting an empty group as a success.
      if (batchWildcardCount > 0) {
        const ok = await confirm(
          `You are turning off Subdomain Discovery while ${batchWildcardCount} scope ` +
          `group${batchWildcardCount === 1 ? ' is' : 's are'} set to be fully enumerated ` +
          `(${batchEnumerated.join(', ')}). Those groups exist to be enumerated, so the ` +
          'scan will refuse to run them. Remove the wildcards, or leave discovery on. Continue?',
          'Disable Subdomain Discovery?'
        )
        if (!ok) return
      }
      updateField('subdomainDiscoveryEnabled', checked)
      return
    }
    if (!checked && !hasExplicitPrefixes && !includesRootDomain) {
      const ok = await confirm(
        'You are turning off Subdomain Discovery while no Subdomain Prefixes are set. ' +
        'To keep the pipeline runnable, "Include Root Domain" will be automatically ' +
        `enabled and locked ON - ${targetName} itself becomes the only scan target. Continue?`,
        'Disable Subdomain Discovery?'
      )
      if (!ok) return
    }
    updateField('subdomainDiscoveryEnabled', checked)
  }

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          Subdomain Discovery
          <NodeInfoTooltip section="SubdomainDiscovery" />
          <WikiInfoButton target="SubdomainDiscovery" />
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.subdomainDiscoveryEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Subdomain Discovery"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div
            onClick={(e) => e.stopPropagation()}
            title={lockReason || undefined}
            style={hasExplicitPrefixes ? { cursor: 'not-allowed' } : undefined}
          >
            <Toggle
              checked={data.subdomainDiscoveryEnabled}
              onChange={handleMasterToggle}
              disabled={hasExplicitPrefixes}
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
            Configure which subdomain discovery sources to use. Passive sources query external
            databases without touching the target. Active discovery sends DNS queries directly.
          </p>

          {data.subdomainDiscoveryEnabled && (
          <>
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Sources <span className={styles.badgePassive}>Passive</span></h3>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>crt.sh</span>
                <p className={styles.toggleDescription}>
                  Certificate transparency logs - discovers subdomains from SSL/TLS certificates.
                  When crt.sh gives no answer, the same lookup is sent to crt.name instead.
                </p>
              </div>
              {data.crtshEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.crtshMaxResults}
                    onChange={(e) => updateField('crtshMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.crtshEnabled}
                onChange={(checked) => updateField('crtshEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>HackerTarget</span>
                <p className={styles.toggleDescription}>
                  DNS lookup database - discovers subdomains from HackerTarget&apos;s host search API
                </p>
              </div>
              {data.hackerTargetEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.hackerTargetMaxResults}
                    onChange={(e) => updateField('hackerTargetMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.hackerTargetEnabled}
                onChange={(checked) => updateField('hackerTargetEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Subdomains by Jsmon</span>
                <p className={styles.toggleDescription}>
                  Passive subdomain intelligence API with 5.4B+ subdomains (requires API key)
                </p>
              </div>
              {data.jsmonEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.jsmonMaxResults}
                    onChange={(e) => updateField('jsmonMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.jsmonEnabled}
                onChange={(checked) => updateField('jsmonEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Subfinder</span>
                <p className={styles.toggleDescription}>
                  Passive subdomain enumeration using 50+ online sources (certificate logs, DNS databases, web archives)
                </p>
              </div>
              {data.subfinderEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.subfinderMaxResults}
                    onChange={(e) => updateField('subfinderMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.subfinderEnabled}
                onChange={(checked) => updateField('subfinderEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Knockpy Recon</span>
                <p className={styles.toggleDescription}>
                  Passive wordlist-based subdomain enumeration using Knockpy&apos;s recon mode
                </p>
              </div>
              {data.knockpyReconEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.knockpyReconMaxResults}
                    onChange={(e) => updateField('knockpyReconMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.knockpyReconEnabled}
                onChange={(checked) => updateField('knockpyReconEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Amass</span>
                <p className={styles.toggleDescription}>
                  OWASP Amass - subdomain enumeration using 50+ data sources (certificate logs, DNS databases, web archives, WHOIS)
                </p>
              </div>
              {data.amassEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.amassMaxResults}
                    onChange={(e) => updateField('amassMaxResults', parseInt(e.target.value) || 50000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.amassEnabled}
                onChange={(checked) => updateField('amassEnabled', checked)}
              />
            </div>
          </div>

          {data.amassEnabled && (
            <div className={styles.subSection}>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Amass Timeout (minutes)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.amassTimeout}
                    onChange={(e) => updateField('amassTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                    max={120}
                  />
                </div>
              </div>
            </div>
          )}

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Discovery <span className={styles.badgeActive}>Active</span></h3>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Knockpy Bruteforce Mode</span>
                <p className={styles.toggleDescription}>
                  Use wordlist-based subdomain bruteforcing - sends thousands of DNS queries
                </p>
                <TimeEstimate estimate="+5-30 min depending on wordlist size" />
              </div>
              <Toggle
                checked={data.useBruteforceForSubdomains}
                onChange={(checked) => updateField('useBruteforceForSubdomains', checked)}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Amass Active Mode</span>
                <p className={styles.toggleDescription}>
                  Enable zone transfers and certificate name grabs - sends DNS queries directly to target
                </p>
              </div>
              <Toggle
                checked={data.amassActive}
                onChange={(checked) => updateField('amassActive', checked)}
                disabled={!data.amassEnabled}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Amass Bruteforce</span>
                <p className={styles.toggleDescription}>
                  DNS brute forcing after passive enumeration - significantly increases scan time
                </p>
                <TimeEstimate estimate="+10-60 min depending on target size" />
              </div>
              <Toggle
                checked={data.amassBrute}
                onChange={(checked) => updateField('amassBrute', checked)}
                disabled={!data.amassEnabled}
              />
            </div>

            {data.amassBrute && data.amassEnabled && (
              <div style={{ marginLeft: 'var(--space-6)', marginTop: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
                <span className={styles.toggleLabel}>Brute Force Wordlists</span>
                <p className={styles.toggleDescription}>
                  Select which wordlists to use. Amass Default is always active.
                </p>

                <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)', opacity: 0.6 }}>
                  <input type="checkbox" checked disabled />
                  <span>Amass Default (~8K entries)</span>
                  <span className={styles.itemMeta}>always active</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
                  <input
                    type="checkbox"
                    checked={(Array.isArray(data.amassBruteWordlists) ? data.amassBruteWordlists as string[] : ['default']).includes('jhaddix-all')}
                    onChange={(e) => {
                      const current = (Array.isArray(data.amassBruteWordlists) ? data.amassBruteWordlists as string[] : ['default']).filter((w: string) => w !== 'jhaddix-all')
                      if (e.target.checked) current.push('jhaddix-all')
                      if (!current.includes('default')) current.unshift('default')
                      updateField('amassBruteWordlists', current as any)
                    }}
                  />
                  <span>jhaddix all.txt (~2.18M entries)</span>
                </label>
                <TimeEstimate estimate="+30-60 min extra scan time" />
              </div>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Wildcard Filtering <span className={styles.badgeActive}>Active</span></h3>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Puredns Wildcard Filtering</span>
                <p className={styles.toggleDescription}>
                  Validates discovered subdomains against public DNS resolvers and removes wildcard
                  entries and DNS-poisoned results - runs after all discovery tools complete
                </p>
              </div>
              <Toggle
                checked={data.purednsEnabled}
                onChange={(checked) => updateField('purednsEnabled', checked)}
              />
            </div>

            {data.purednsEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads (0 = auto)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.purednsThreads}
                    onChange={(e) => updateField('purednsThreads', parseInt(e.target.value) || 0)}
                    min={0}
                    max={1000}
                  />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit (0 = unlimited)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.purednsRateLimit}
                    onChange={(e) => updateField('purednsRateLimit', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                </div>
              </div>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>DNS Performance</h3>

            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>DNS Max Workers</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.dnsMaxWorkers ?? 50}
                  onChange={(e) => updateField('dnsMaxWorkers', parseInt(e.target.value) || 50)}
                  min={1}
                  max={200}
                />
                <span className={styles.fieldHint}>Parallel DNS resolution workers</span>
              </div>
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>DNS Record Parallelism</span>
                <p className={styles.toggleDescription}>Query all DNS record types in parallel per hostname</p>
              </div>
              <Toggle
                checked={data.dnsRecordParallelism ?? true}
                onChange={(checked) => updateField('dnsRecordParallelism', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>DNS &amp; WHOIS <span className={styles.badgePassive}>Passive</span></h3>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>WHOIS Lookup</span>
                <p className={styles.toggleDescription}>
                  Query public WHOIS databases for domain registration info (registrar, dates, contacts)
                </p>
              </div>
              {data.whoisEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Retries</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.whoisMaxRetries}
                    onChange={(e) => updateField('whoisMaxRetries', parseInt(e.target.value) || 6)}
                    min={1}
                    max={20}
                  />
                </>
              )}
              <Toggle
                checked={data.whoisEnabled}
                onChange={(checked) => updateField('whoisEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>DNS Resolution</span>
                <p className={styles.toggleDescription}>
                  Resolve DNS records (A, AAAA, MX, NS, TXT) and reverse DNS for discovered hosts
                </p>
              </div>
              {data.dnsEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Retries</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.dnsMaxRetries}
                    onChange={(e) => updateField('dnsMaxRetries', parseInt(e.target.value) || 3)}
                    min={1}
                    max={10}
                  />
                </>
              )}
              <Toggle
                checked={data.dnsEnabled}
                onChange={(checked) => updateField('dnsEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>AI TXT/SPF/DKIM Hint</span>
                <p className={styles.toggleDescription}>
                  Regex captured TXT records (incl. SPF, DKIM, DMARC) for AI vendor domains: anthropic.com, openai.com, huggingface.co, replicate.com, langchain.com, langfuse.com, cohere.com, together.ai, groq.com, mistral.ai. On match, sets Subdomain.ai_service_hint.
                </p>
              </div>
              <Toggle
                checked={data.domainReconAiTxtHintEnabled ?? true}
                onChange={(checked) => updateField('domainReconAiTxtHintEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>AI NS Hint</span>
                <p className={styles.toggleDescription}>
                  Weak signal: tag Subdomain.ai_service_hint = "ai-hosting-candidate" when NS records point at AI-friendly hosts (Vercel, Netlify, Replit, Modal, HuggingFace Spaces). Never overrides a stronger TXT hint.
                </p>
              </div>
              <Toggle
                checked={data.domainReconAiNsHintEnabled ?? true}
                onChange={(checked) => updateField('domainReconAiNsHintEnabled', checked)}
              />
            </div>
          </div>
          </>
          )}

          <RegistryFields
            keys={['amassDockerImage', 'purednsDockerImage', 'purednsSkipValidation', 'purednsWildcardBatch', 'subfinderDockerImage']}
            data={data}
            updateField={updateField}
            title="Advanced"
            description="Settings this tool accepts that have no dedicated control. Bounds, options and descriptions come from the settings registry, so they are the same ones the API enforces."
          />
        </div>
      )}
    </div>
  )
}
