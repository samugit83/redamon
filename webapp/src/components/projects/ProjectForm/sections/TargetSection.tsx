'use client'

import { useState, useMemo, useEffect } from 'react'
import { ChevronDown, Target, ShieldAlert, AlertTriangle, Info, Globe, Network, Layers, Check, Lock, Plus, Minus, Gauge } from 'lucide-react'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { JevTokenPanel } from '../JevTokenPanel'
import aiStyles from '../AiPipelinePanel.module.css'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { firstHardBlocked } from '@/lib/hard-guardrail'
import { classifyIpTargets } from '@/lib/ip-target-utils'
import {
  validateDomainBatch, INVALID_REASON_TEXT, MAX_BATCH_HOSTS, MAX_BATCH_GROUPS, NESTED_WILDCARDS_ENABLED, normalizeHost,
} from '@/lib/domainBatch'
import {
  GRAPH_DOMAIN_IS_ORG, type ScopeFields, isScopeWidening, resolveScopeGroups, scopeGuardrailNames,
} from '@/lib/scopeGroups'
import { deriveRoeEnabled } from '@/lib/engagement'
import { isValidDomain } from '@/lib/validation'
import { FileImportButton } from '../FileImportButton'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TargetSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  mode?: 'create' | 'edit'
  /** Edit mode: the scope as last saved, to tell a widening apart. */
  savedScope?: ScopeFields
  /** Edit mode: whose schedules a widening would reach. */
  projectId?: string
}

// Helper to convert stored format (with dots) to display format (without dots)
function toDisplayPrefixes(subdomainList: string[]): string {
  return subdomainList
    .filter(s => s !== '.')  // Exclude root domain marker
    .map(s => s.endsWith('.') ? s.slice(0, -1) : s)  // Remove trailing dot
    .join(', ')
}

// Helper to convert display format to stored format (with trailing dots)
function toStoredPrefixes(displayValue: string, includeRoot: boolean): string[] {
  const prefixes = displayValue
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => s.endsWith('.') ? s : s + '.')  // Add trailing dot if missing

  if (includeRoot) {
    prefixes.push('.')
  }

  return prefixes
}

const WEEKDAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

// Helper to parse IP textarea into array
function parseIpList(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map(s => s.trim())
    .filter(Boolean)
}

/** Domain batch accepts one host per line as well as comma/semicolon/space
 *  separated, because operators paste from spreadsheets and scope documents. */
function parseHostList(text: string): string[] {
  return text
    .split(/[,;\s\n]+/)
    .map(s => s.trim())
    .filter(Boolean)
}

type TargetMode = 'domain' | 'ip' | 'batch'

/** Where the ownership TXT record may sit for a group (plan §4.8): the scan
 *  root, then its registrable domain when that differs. Recon accepts either. */
function ownershipRecordNames(g: { scanRoot: string; orgDomain: string }, prefix: string): string[] {
  return [`${prefix}.${g.scanRoot}`, ...(g.orgDomain !== g.scanRoot ? [`${prefix}.${g.orgDomain}`] : [])]
}

export function TargetSection({ data, updateField, mode = 'create', savedScope, projectId }: TargetSectionProps) {
  const jevStatus = useHasJevProvider()
  const isLocked = mode === 'edit'
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()

  const ipMode = data.ipMode || false
  const batchMode = data.domainBatchMode || false
  const targetMode: TargetMode = ipMode ? 'ip' : batchMode ? 'batch' : 'domain'

  // Whether the engagement's limits are live, DERIVED from whether any is set.
  // Computed for display only and never written into the form's data: a derived
  // value in `formData` would make the form permanently dirty and fire the
  // unsaved-changes guard on every navigation.
  const limitsActive = deriveRoeEnabled(data)
  const activeLimits = [
    data.roeGlobalMaxRps > 0 ? 'a rate ceiling' : null,
    (data.roeExcludedHosts || []).some(h => String(h).trim() !== '') ? 'an excluded-host list' : null,
    data.roeTimeWindowEnabled ? 'a scanning time window' : null,
  ].filter(Boolean) as string[]

  // The excluded-host editor writes the host and its reason together, because
  // the two arrays are positional: editing one without the other silently
  // re-pairs every reason below it with the wrong host.
  const addExcludedHost = () => {
    updateField('roeExcludedHosts', [...(data.roeExcludedHosts || []), ''])
    updateField('roeExcludedHostReasons', [...(data.roeExcludedHostReasons || []), ''])
  }

  const removeExcludedHost = (index: number) => {
    const hosts = [...(data.roeExcludedHosts || [])]
    const reasons = [...(data.roeExcludedHostReasons || [])]
    hosts.splice(index, 1)
    reasons.splice(index, 1)
    updateField('roeExcludedHosts', hosts)
    updateField('roeExcludedHostReasons', reasons)
  }

  const updateExcludedHost = (index: number, value: string) => {
    const hosts = [...(data.roeExcludedHosts || [])]
    hosts[index] = value
    updateField('roeExcludedHosts', hosts)
  }

  const updateExcludedReason = (index: number, value: string) => {
    const reasons = [...(data.roeExcludedHostReasons || [])]
    reasons[index] = value
    updateField('roeExcludedHostReasons', reasons)
  }

  const toggleDay = (day: string) => {
    const days = data.roeTimeWindowDays || []
    updateField(
      'roeTimeWindowDays',
      days.includes(day) ? days.filter(d => d !== day) : [...days, day]
    )
  }

  // Domain batch: group the pasted hostnames with the SAME helper the server uses
  // to persist them, so the preview cannot promise a grouping the scan won't run.
  const batchHosts = useMemo(() => data.domainBatchHosts || [], [data.domainBatchHosts])
  // The textarea keeps the operator's RAW text while they type. Deriving its value
  // from the parsed array instead re-rendered "a.com\n" back as "a.com", so every
  // separator was stripped the instant it was typed and a second host could never
  // be entered by hand. The parsed array stays authoritative for the preview, the
  // validation and what is saved; this only preserves the keystrokes in between.
  const [batchHostDraft, setBatchHostDraft] = useState<string | null>(null)
  const displayBatchHosts = batchHostDraft ?? batchHosts.join('\n')
  const batchResult = useMemo(
    () => (batchMode ? validateDomainBatch(batchHosts) : null),
    [batchMode, batchHosts]
  )
  // Every listed host and every group root gets the same non-disableable check
  // the single domain gets, and the message names the host that was listed.
  const batchBlocked = useMemo(() => {
    if (!batchResult) return null
    const hit = firstHardBlocked(scopeGuardrailNames({ domainBatchMode: true, domainBatchHosts: batchHosts }))
    return hit ? { domain: hit.name, reason: hit.reason } : null
  }, [batchResult, batchHosts])

  // Nothing caps how many domains may be enumerated, so the count is what the
  // operator is shown instead - here, and again in the start-scan confirmation.
  const wildcardGroupCount = useMemo(
    () => (batchResult?.groups ?? []).filter(g => g.mode === 'enumerate').length,
    [batchResult]
  )
  const batchOrgCount = useMemo(
    () => new Set((batchResult?.groups ?? []).map(g => g.orgDomain)).size,
    [batchResult]
  )

  // A single domain is one scope group; deriving it here, with the helper every
  // reader uses, lets the copy name the actual target and its domain.
  const singleScope = useMemo(
    () => (targetMode === 'domain'
      ? resolveScopeGroups({ targetDomain: data.targetDomain, subdomainList: data.subdomainList })
      : null),
    [targetMode, data.targetDomain, data.subdomainList]
  )
  const singleGroup = singleScope?.groups[0] ?? null

  // A save that widens the scope (D-21: a host the saved scope did not admit) is
  // what every enabled schedule will scan from its next run. Warn, never pause:
  // the operator may want exactly that (Q-15).
  const [enabledSchedules, setEnabledSchedules] = useState(0)
  useEffect(() => {
    if (mode !== 'edit' || !projectId) return
    let alive = true
    fetch(`/api/projects/${projectId}/schedules`)
      .then(res => (res.ok ? res.json() : null))
      .then(body => {
        const list: { enabled?: boolean }[] = Array.isArray(body?.schedules) ? body.schedules : []
        if (alive) setEnabledSchedules(list.filter(s => s.enabled).length)
      })
      .catch(() => {})
    return () => { alive = false }
  }, [mode, projectId])
  const widensScheduledScope = useMemo(() => {
    if (!savedScope || enabledSchedules === 0 || ipMode) return false
    const next = batchMode ? batchResult?.groups ?? [] : singleScope?.groups ?? []
    return next.length > 0 && isScopeWidening(resolveScopeGroups(savedScope).groups, next)
  }, [savedScope, enabledSchedules, ipMode, batchMode, batchResult, singleScope])
  const ownershipPrefix = (data.ownershipTxtPrefix || '').trim() || '_redamon-verify'
  // A half-typed name ("exam") is not yet a hostname, and calling it a public
  // suffix would be wrong: only a well-formed name gets the refusal reason.
  const targetInvalid = singleScope?.invalid.find(i => i.reason === 'ip_literal'
    || (i.reason !== 'invalid_prefix' && isValidDomain(i.entry.replace(/^\*\.?/, '')))) ?? null
  const prefixInvalid = singleScope?.invalid.filter(i => i.reason === 'invalid_prefix') ?? []
  const targetName = singleGroup?.scanRoot || 'the target'

  // Check if root domain is included in the list
  const includesRootDomain = useMemo(() => data.subdomainList.includes('.'), [data.subdomainList])

  // Display value without dots
  const displayPrefixes = useMemo(() => toDisplayPrefixes(data.subdomainList), [data.subdomainList])

  // Display value for IP textarea
  const displayIps = useMemo(() => (data.targetIps || []).join('\n'), [data.targetIps])

  // Classify the entered IPs so the form can warn when targets are on a
  // private/local network, where public OSINT + subdomain enumeration return
  // nothing. Only meaningful in IP mode.
  const ipTargetClass = useMemo(
    () => (ipMode ? classifyIpTargets(data.targetIps) : 'empty'),
    [ipMode, data.targetIps]
  )
  const hasLocalIps = ipTargetClass === 'private' || ipTargetClass === 'mixed'

  // Hard guardrail: deterministic check for government/public domains (non-disableable),
  // on the target AND every prefix host it makes: `isa.` under `org.jm` is blocked
  // although the target is not, and the submit check already refuses it.
  const hardBlockResult = useMemo(
    () => (ipMode ? null : firstHardBlocked(scopeGuardrailNames({
      targetDomain: data.targetDomain, subdomainList: data.subdomainList,
    }))),
    [ipMode, data.targetDomain, data.subdomainList]
  )

  const handlePrefixesChange = (value: string) => {
    updateField('subdomainList', toStoredPrefixes(value, includesRootDomain))
  }

  const handleRootDomainToggle = (checked: boolean) => {
    const currentPrefixes = toDisplayPrefixes(data.subdomainList)
    updateField('subdomainList', toStoredPrefixes(currentPrefixes, checked))
  }

  // When subdomain discovery is OFF and no prefixes are set, the only valid
  // target is the root domain. Force-enable "Include Root Domain" and lock it
  // so the pipeline cannot be started with zero targets (which would silently
  // produce empty results). Runs in edit mode too - it's a system-driven
  // safety net, not user editing of scope.
  // Single-domain only: a batch derives its prefixes per group and never uses
  // subdomainList, so nudging these fields there would write settings the batch
  // pipeline ignores.
  const forceIncludeRootDomain = targetMode === 'domain'
    && !data.subdomainDiscoveryEnabled
    && displayPrefixes.trim().length === 0

  // When the user supplies explicit Subdomain Prefixes, the pipeline runs in
  // FILTERED mode and the entire Subdomain Discovery group (Subfinder, Amass,
  // crt.sh, HackerTarget, Knockpy, puredns) is silently skipped. Force the
  // master toggle OFF so the UI matches what the backend actually does.
  const prefixesPresent = targetMode === 'domain' && !isLocked && displayPrefixes.trim().length > 0

  useEffect(() => {
    if (forceIncludeRootDomain && !includesRootDomain) {
      handleRootDomainToggle(true)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [forceIncludeRootDomain, includesRootDomain])

  useEffect(() => {
    if (prefixesPresent && data.subdomainDiscoveryEnabled) {
      updateField('subdomainDiscoveryEnabled', false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefixesPresent, data.subdomainDiscoveryEnabled])

  // One switch for three mutually exclusive modes. Each clears the fields the
  // other modes own, so a project can never carry two contradictory targets.
  const handleTargetModeChange = (next: TargetMode) => {
    updateField('ipMode', next === 'ip')
    updateField('domainBatchMode', next === 'batch')
    if (next !== 'domain') {
      updateField('targetDomain', '')
      updateField('subdomainList', [])
    }
    if (next !== 'ip') updateField('targetIps', [])
    if (next !== 'batch') {
      setBatchHostDraft(null)
      updateField('domainBatchHosts', [])
    }
  }

  const handleIpsChange = (text: string) => {
    updateField('targetIps', parseIpList(text))
  }

  const handleBatchHostsChange = (text: string) => {
    setBatchHostDraft(text)
    updateField('domainBatchHosts', parseHostList(text))
  }

  // "Also scan the wildcard's own name" for ONE wildcard group. Root inclusion is
  // per group, so this cannot be a single switch: a list may hold `*.a.com` with
  // its root in scope and `*.b.com` without. It stays pure sugar over the host
  // list - the bare scan-root line IS how a batch asks for it - so there is no
  // extra state to persist and the textarea keeps showing the truth. Lines are
  // compared normalised: a pasted `https://a.com/` is the same line and must go too.
  const handleGroupRootToggle = (scanRoot: string, checked: boolean) => {
    setBatchHostDraft(null)
    const withoutRoot = batchHosts.filter(h => normalizeHost(h) !== scanRoot)
    updateField('domainBatchHosts', checked ? [...withoutRoot, scanRoot] : withoutRoot)
  }

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Target size={16} />
          Target Configuration
          <WikiInfoButton target="Target" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Define the primary target for your security assessment. Choose between domain-based
            or IP-based targeting mode.
          </p>

          {/* Targeting mode: a full-width, two-card segmented selector. This is
              the first and most consequential decision on the form (it decides
              which half of the pipeline runs), so it reads as a pair of distinct
              coloured modes rather than a small on/off toggle. Blue = Domain,
              purple = IP/Local, mirroring the recon-preset classification chips.
              Locked after creation - ipMode cannot change on an existing project. */}
          <div className={styles.fieldGroup}>
            <div className={styles.modeCards}>
              {([
                {
                  mode: 'domain' as TargetMode,
                  icon: <Globe size={20} />,
                  title: 'Single Domain',
                  subtitle: 'One domain or hostname, public or internal (incl. AD)',
                },
                {
                  mode: 'ip' as TargetMode,
                  icon: <Network size={20} />,
                  title: 'IP / CIDR',
                  subtitle: 'IP addresses or ranges, public or internal',
                },
                {
                  mode: 'batch' as TargetMode,
                  icon: <Layers size={20} />,
                  title: 'Domain batch',
                  subtitle: 'A list of hostnames, grouped into scope groups and scanned in turn',
                },
              ]).map((opt) => {
                const active = opt.mode === targetMode
                return (
                  <button
                    key={opt.title}
                    type="button"
                    data-mode={opt.mode}
                    className={`${styles.modeCard} ${active ? styles.modeCardActive : ''}`}
                    disabled={isLocked}
                    aria-pressed={active}
                    onClick={() => !isLocked && handleTargetModeChange(opt.mode)}
                  >
                    <span className={styles.modeCardHead}>
                      {opt.icon}
                      <span className={styles.modeCardTitle}>{opt.title}</span>
                      {active && !isLocked && <Check size={16} className={styles.modeCardMark} />}
                      {isLocked && active && <Lock size={14} className={styles.modeCardMark} />}
                    </span>
                    <span className={styles.modeCardSubtitle}>{opt.subtitle}</span>
                  </button>
                )
              })}
            </div>

            <p className={styles.toggleDescription} style={{ marginTop: 'var(--space-3)' }}>
              {batchMode ? (
                <>
                  Paste or upload a list of hostnames. Each belongs to its{' '}
                  <strong>registrable domain</strong>, read from the Public Suffix List (so
                  a.b.example.com belongs to example.com and www.acme.co.uk to acme.co.uk),
                  and the list is split into <strong>scope groups</strong> that a{' '}
                  <strong>single</strong> recon run scans in turn, writing to the graph as it
                  finishes each one. A plain line is scanned exactly as written &mdash;{' '}
                  <strong>except under a wildcard</strong>. Write <code>*.example.com</code>{' '}
                  (or <code>*example.com</code>) to run the full subdomain enumeration under
                  that name, exactly as a Single Domain project does
                  {NESTED_WILDCARDS_ENABLED
                    ? <>, at any depth (<code>*.api.example.com</code> works too)</>
                    : <>; for now a wildcard names a registrable domain</>}
                  . A plain line under a wildcard is seeded into its group. Tick{' '}
                  <strong>Root</strong> on a wildcard row to also scan the wildcard&apos;s own name.
                </>
              ) : ipMode ? (
                <>
                  Targets are IP addresses or CIDR ranges, <strong>public or private</strong>.
                  The pipeline runs reverse DNS to recover hostnames. For a private/internal
                  range or Active Directory, pick the{' '}
                  <strong>Internal Network &amp; Active Directory</strong> recon preset, which
                  turns off the public-only tools (OSINT, subdomain enumeration, WHOIS) that
                  cannot see a LAN.
                </>
              ) : (
                <>
                  Targets are a domain or hostname, <strong>public or internal</strong>. A
                  public domain gets full OSINT and subdomain discovery; for an internal
                  hostname (e.g. myinternal.com) turn Subdomain Discovery off and
                  make sure this host can resolve the name. Choose <strong>IP / CIDR</strong>{' '}
                  instead when you only have addresses.
                </>
              )}
              {isLocked && (
                <>
                  {' '}
                  <strong>The targeting mode is locked after project creation.</strong> Create
                  a new project to change it.
                </>
              )}
            </p>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Project Name
              </label>
              <input
                type="text"
                className="textInput"
                value={data.name}
                onChange={(e) => updateField('name', e.target.value)}
                placeholder="My Security Project"
              />
            </div>

            {targetMode === 'domain' && (
              <div className={styles.fieldGroup}>
                <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                  Target domain or hostname
                </label>
                <input
                  type="text"
                  className="textInput"
                  value={data.targetDomain}
                  onChange={(e) => updateField('targetDomain', e.target.value)}
                  placeholder="example.com or api.example.com"
                  disabled={isLocked}
                  title={isLocked ? 'Target domain cannot be changed after creation. Create a new project instead.' : undefined}
                />
                {targetInvalid ? (
                  <span className={styles.fieldHint}>
                    {targetInvalid.entry}: {INVALID_REASON_TEXT[targetInvalid.reason]}
                  </span>
                ) : singleGroup && (
                  <span className={styles.fieldHint}>
                    {GRAPH_DOMAIN_IS_ORG ? 'Graph domain' : 'Registrable domain'}: {singleGroup.orgDomain}
                    {' '}&middot; scan root: {singleGroup.scanRoot}
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Hard guardrail warning for government/public domains */}
          {hardBlockResult && (
            <div className={`${styles.callout} ${styles.calloutDanger}`}>
              <ShieldAlert size={16} />
              <span>
                <strong>Target permanently blocked: {hardBlockResult.name}.</strong> Government, military, educational, and international
                organization websites (.gov, .mil, .edu, .int, etc.) are always blocked and cannot be used as targets,
                regardless of guardrail settings. This restriction cannot be disabled.
              </span>
            </div>
          )}

          {/* Domain batch: the hostname list plus a live preview of the groups it
              produces. The preview is the ONLY place the grouping rule is visible,
              and it is generated by the same helper the server persists with, so
              what the operator approves here is what the pipeline runs. */}
          {batchMode && (
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Hostnames
              </label>
              <div className={styles.fileImportWrap}>
                <textarea
                  className="textarea"
                  rows={6}
                  value={displayBatchHosts}
                  onChange={(e) => handleBatchHostsChange(e.target.value)}
                  placeholder={'sub1.domain1.com\nsub2.domain2.it\n*.domain3.com\nsuba.sub3.domain4.com'}
                  title={'The next scan rebuilds the graph against this list.'}
                />
                <FileImportButton
                  onImport={(values) => { setBatchHostDraft(null); updateField('domainBatchHosts', values) }}
                  variant="textarea"
                  fieldName="hostnames"
                />
              </div>
              <p className={styles.fieldHint}>
                One per line, or comma separated. {batchHosts.length} hostname
                {batchHosts.length === 1 ? '' : 's'} (max {MAX_BATCH_HOSTS}), grouped into{' '}
                {batchResult?.groups.length ?? 0} scope group
                {(batchResult?.groups.length ?? 0) === 1 ? '' : 's'} across {batchOrgCount} domain
                {batchOrgCount === 1 ? '' : 's'} (max {MAX_BATCH_GROUPS} groups).
              </p>

              {batchResult && batchResult.groups.length > 0 && (
                <>
                  <div className={styles.previewTableWrap}>
                    <table className={styles.previewTable} style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ textAlign: 'left' }}>
                          <th style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>#</th>
                          <th style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>Scan root</th>
                          <th style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>Domain (org)</th>
                          <th style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>Mode</th>
                          <th style={{ padding: '6px 8px' }}>Hosts</th>
                          <th style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>Root</th>
                          {data.verifyDomainOwnership && (
                            <th style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>Ownership TXT</th>
                          )}
                        </tr>
                      </thead>
                      <tbody>
                        {batchResult.groups.map((g, i) => {
                          const firstOfOrg = batchResult.groups.findIndex(o => o.orgDomain === g.orgDomain)
                          return (
                          <tr key={g.scanRoot}>
                            <td className={styles.previewTableMuted} style={{ padding: '6px 8px' }}>{i + 1}</td>
                            <td style={{ padding: '6px 8px', fontWeight: 600, whiteSpace: 'nowrap' }}>
                              {g.mode === 'enumerate' ? `*.${g.scanRoot}` : g.scanRoot}
                            </td>
                            <td
                              className={firstOfOrg < i ? styles.previewTableMuted : undefined}
                              style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}
                            >
                              {g.orgDomain}{firstOfOrg < i && ` (shared with #${firstOfOrg + 1})`}
                            </td>
                            <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                              {g.mode === 'enumerate'
                                ? <span className={styles.enumBadge}>FULL ENUMERATION</span>
                                : <span className={styles.previewTableMuted}>EXACT</span>}
                            </td>
                            <td className={styles.previewTableMuted} style={{ padding: '6px 8px' }}>
                              {g.mode === 'enumerate' ? (
                                <>
                                  everything found under {g.scanRoot}
                                  {g.exactHosts.map(h => <div key={h}>{h} seeded</div>)}
                                  {g.notes.map(n => (
                                    <div key={n.entry}><code>{n.entry}</code> covered by <code>{n.coveredBy}</code></div>
                                  ))}
                                </>
                              ) : g.entries.join(', ')}
                            </td>
                            <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                              {g.mode === 'enumerate' ? (
                                <label style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}>
                                  <input
                                    type="checkbox"
                                    checked={g.includeRoot}
                                    onChange={(e) => handleGroupRootToggle(g.scanRoot, e.target.checked)}
                                    aria-label={`Also scan ${g.scanRoot} itself`}
                                  />
                                </label>
                              ) : (
                                <span className={styles.previewTableMuted}>&ndash;</span>
                              )}
                            </td>
                            {data.verifyDomainOwnership && (
                              <td className={styles.previewTableMuted} style={{ padding: '6px 8px' }}>
                                {ownershipRecordNames(g, ownershipPrefix).map((name, k) => (
                                  <div key={name}>{k > 0 && 'or '}<code>{name}</code></div>
                                ))}
                              </td>
                            )}
                          </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                  <p className={styles.fieldHint}>
                    Groups run top to bottom, one at a time, in a single scan.
                  </p>
                  {wildcardGroupCount > 0 && (
                    <div className={`${styles.callout} ${styles.calloutWarning}`}>
                      <AlertTriangle size={16} />
                      <span>
                        <strong>
                          {wildcardGroupCount} scope group{wildcardGroupCount === 1 ? '' : 's'} will be
                          fully enumerated.
                        </strong>{' '}
                        Subdomain discovery runs for {wildcardGroupCount === 1 ? 'it' : 'each of them'}{' '}
                        (crt.sh, Subfinder, Amass, Knockpy, puredns) and the whole pipeline then runs
                        over everything found, so this scan may take <strong>many hours</strong> and
                        will grow the graph substantially. The hostname and scope-group limits count
                        the list you typed, not what enumeration discovers.
                      </span>
                    </div>
                  )}
                </>
              )}

              {batchResult && batchResult.invalid.length > 0 && (
                <div className={`${styles.callout} ${styles.calloutDanger}`}>
                  <AlertTriangle size={16} />
                  <span>
                    <strong>Not accepted:</strong>
                    <ul style={{ margin: '4px 0', paddingLeft: '18px' }}>
                      {batchResult.invalid.map(i => (
                        <li key={i.entry}><code>{i.entry}</code>: {INVALID_REASON_TEXT[i.reason]}</li>
                      ))}
                    </ul>
                    Remove or correct {batchResult.invalid.length === 1 ? 'it' : 'them'} to continue.
                  </span>
                </div>
              )}

              {batchBlocked && (
                <div className={`${styles.callout} ${styles.calloutDanger}`}>
                  <ShieldAlert size={16} />
                  <span>
                    <strong>Target permanently blocked: {batchBlocked.domain}.</strong> Government,
                    military, educational and international organization domains are always
                    blocked and cannot be scanned, regardless of guardrail settings. Remove that
                    entry to continue.
                  </span>
                </div>
              )}
            </div>
          )}

          {/* IP Mode: Target IPs textarea */}
          {ipMode && (
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Target IPs / CIDRs
              </label>
              <div className={styles.fileImportWrap}>
                <textarea
                  className="textarea"
                  value={displayIps}
                  onChange={(e) => handleIpsChange(e.target.value)}
                  placeholder={"192.168.1.1\n10.0.0.0/24\n2001:db8::1"}
                  rows={4}
                  disabled={isLocked}
                  title={isLocked ? 'Target IPs cannot be changed after creation.' : undefined}
                />
                {!isLocked && (
                  <FileImportButton
                    variant="textarea"
                    fieldName="target IPs / CIDRs"
                    onImport={(values) => updateField('targetIps', values)}
                  />
                )}
              </div>
              <span className={styles.fieldHint}>
                {isLocked
                  ? 'Target IPs are locked after project creation. Create a new project to change them.'
                  : 'Enter one IP or CIDR per line, or comma-separated. IPv4, IPv6, and CIDR ranges supported. Max /24 (256 hosts).'}
              </span>

              {/* Private/local target detected: public OSINT + subdomain enumeration
                  cannot see RFC1918 space, so warn and point at the internal preset. */}
              {hasLocalIps && (
                <div className={`${styles.callout} ${styles.calloutWarning}`}>
                  <AlertTriangle size={16} />
                  <span>
                    <strong>
                      {ipTargetClass === 'mixed'
                        ? 'Some targets are on a private / local network.'
                        : 'These targets are on a private / local network.'}
                    </strong>{' '}
                    Public lookups (Shodan, Censys, crt.sh, WHOIS, subdomain enumeration)
                    return nothing for private / RFC1918 addresses, so leaving them on just
                    wastes time. For local network or Active Directory testing, select the
                    {' '}<strong>Internal Network &amp; Active Directory</strong> recon preset,
                    which turns those off and focuses the scan on internal services
                    (SMB, LDAP, Kerberos, RDP, WinRM, databases).
                  </span>
                </div>
              )}

              {/* Always-on note for IP mode: the domain-only phases don't apply. */}
              <div className={`${styles.callout} ${styles.calloutInfo}`}>
                <Info size={16} />
                <span>
                  <strong>IP mode:</strong> domain-only steps are skipped. Subdomain
                  discovery, WHOIS, DNS/email security and subdomain-takeover checks need a
                  registered domain and do not run against bare IPs. Port scanning, service
                  and version detection, HTTP probing, CVE lookup and the security checks
                  work normally.
                </span>
              </div>
            </div>
          )}

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Description</label>
            <textarea
              className="textarea"
              value={data.description || ''}
              onChange={(e) => updateField('description', e.target.value)}
              placeholder="Project description (optional)"
              rows={2}
            />
          </div>

          {widensScheduledScope && (
            <div className={`${styles.callout} ${styles.calloutWarning}`} role="status">
              <AlertTriangle size={16} />
              <span>
                <strong>
                  {enabledSchedules} scheduled scan{enabledSchedules === 1 ? '' : 's'} will run the
                  wider scope.
                </strong>{' '}
                This change adds hosts the saved scope did not cover, and every enabled schedule
                scans them from its next run. Pause a schedule in the Scans tab if that is not
                intended.
              </span>
            </div>
          )}

          {/* Domain-mode only fields */}
          {/* Domain and batch modes share the AI + ownership settings below, but
              Subdomain Prefixes and Include Root Domain belong to a SINGLE target:
              a batch derives per-group prefixes from its host list, and subdomain
              discovery is forced off for it, so showing these would be a lie. */}
          {targetMode === 'domain' && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Subdomain Prefixes</label>
                <div className={styles.fileImportWrap}>
                  <input
                    type="text"
                    className="textInput"
                    value={displayPrefixes}
                    onChange={(e) => handlePrefixesChange(e.target.value)}
                    placeholder="www, api, eu.api (comma-separated)"
                    disabled={isLocked}
                    title={isLocked ? 'Subdomain list cannot be changed after creation. Create a new project instead.' : undefined}
                  />
                  {!isLocked && (
                    <FileImportButton
                      fieldName="subdomain prefixes"
                      onImport={(values) => handlePrefixesChange(values.join(', '))}
                    />
                  )}
                </div>
                <span className={styles.fieldHint}>
                  {isLocked
                    ? 'Target domain and subdomains are locked after project creation to keep graph data consistent. To change them, create a new project.'
                    : `Leave empty to discover every subdomain of ${targetName}. Enter each prefix without ${targetName}; it may have several labels (e.g., "www, api, eu.api").`}
                </span>
                {prefixInvalid.length > 0 && (
                  <div className={`${styles.callout} ${styles.calloutDanger}`}>
                    <AlertTriangle size={16} />
                    <span>
                      <strong>Not accepted:</strong>{' '}
                      {prefixInvalid.map(i => `${i.entry.replace(/\.$/, '')} (${INVALID_REASON_TEXT[i.reason]})`).join('; ')}
                    </span>
                  </div>
                )}
                {!isLocked && displayPrefixes.trim().length === 0 && (
                  <div className={`${styles.callout} ${styles.calloutWarning}`}>
                    <AlertTriangle size={16} />
                    <span>
                      <strong>Heads up:</strong> Leaving Subdomain Prefixes empty starts full
                      subdomain enumeration of everything under {targetName}. This will take
                      <strong> much, much longer </strong>
                      than scanning a specific set of prefixes.
                    </span>
                  </div>
                )}
                {prefixesPresent && (
                  <div className={`${styles.callout} ${styles.calloutInfo}`}>
                    <Info size={16} />
                    <span>
                      <strong>Filtered mode:</strong> with explicit prefixes the pipeline scans
                      only the subdomains you listed. <strong>Subdomain Discovery has been
                      automatically turned off</strong> and locked (Subfinder, Amass, crt.sh,
                      HackerTarget, Knockpy, puredns will not run). Clear the prefixes if you
                      want full enumeration.
                    </span>
                  </div>
                )}
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Include Root Domain</span>
                  <p className={styles.toggleDescription}>
                    Also scan {targetName} itself, not only the names under it.
                    {forceIncludeRootDomain && (
                      <>
                        {' '}
                        <strong>Locked ON: Subdomain Discovery is disabled and no prefixes are set, so {targetName} is the only valid target.</strong>
                      </>
                    )}
                  </p>
                </div>
                <Toggle
                  checked={includesRootDomain}
                  onChange={handleRootDomainToggle}
                  disabled={isLocked || forceIncludeRootDomain}
                />
              </div>
            </>
          )}

          {/* AI in Pipeline renders in every target mode: IP and batch scans run the
              same AI-hooked tools as domain scans, so it must stay outside the gate below. */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)', alignItems: 'center' }}>
              <AiToggleLabel
                label="Enable AI in Pipeline"
                tooltip={
                  'Master switch that unlocks every per-tool AI toggle below. ' +
                  'When OFF, all per-tool AI flags are forced OFF and disabled, ' +
                  'no LLM calls are made by the recon pipeline. When ON, each ' +
                  'per-tool toggle becomes editable and individual AI hooks can ' +
                  'be turned on or off independently. Pick the model used by ' +
                  'every hook just below.'
                }
              />
              <Toggle
                checked={data.aiInPipeline}
                onChange={(checked) => {
                  updateField('aiInPipeline', checked)
                  // When master flips, cascade to every per-tool flag so the
                  // form state matches the backend defense-in-depth contract.
                  updateField('ffufAiExtensions', checked)
                  updateField('nucleiAiTags', checked)
                  updateField('wafAiClassifier', checked)
                  updateField('nucleiAiResponseFilter', checked)
                  updateField('takeoverAiClassifier', checked)
                }}
              />
            </div>
            {data.aiInPipeline && (
              <>
                <div className={aiStyles.modelRow}>
                  <div className={aiStyles.column}>
                    <label className={styles.fieldLabel}>AI Model</label>
                    <ModelPicker
                      userId={userId}
                      value={data.aiPipelineModel}
                      onChange={(id) => updateField('aiPipelineModel', id)}
                      filter={excludeLoop}
                    />
                    <span className={styles.fieldHint}>
                      Model used by every AI hook in recon. Independent of the
                      agent&apos;s own model selection. Pick a cheaper model here
                      if cost matters more than peak quality. Applies to hooks on
                      the LLM engine.
                    </span>
                  </div>
                  <div className={aiStyles.column}>
                    <span className={styles.fieldLabel}>Jev engine</span>
                    <JevTokenPanel userId={userId} />
                  </div>
                </div>

                {/* Per-tool AI toggles. Each one mirrors the toggle in its tool
                    section, sharing the same form field, so flipping either
                    place updates both. The list lives inside a fixed-height
                    scroll container so adding more hooks doesn't push the
                    rest of the form down. Descriptions are rendered as
                    native title-attribute tooltips on the info icon to
                    keep each row compact. Add new entries to the
                    `aiPipelineHooks` array below as more tools gain AI
                    hooks -- no JSX changes needed. */}
                {(() => {
                  const aiPipelineHooks: Array<{
                    field: 'ffufAiExtensions' | 'nucleiAiTags' | 'wafAiClassifier' | 'nucleiAiResponseFilter' | 'takeoverAiClassifier'
                    /** The LLM | Jev engine switch. Absent where Jev must not decide: the
                        Nuclei false-positive filter deletes findings from target-controlled bytes. */
                    engineField?: 'ffufAiUseJev' | 'nucleiTagsAiUseJev' | 'wafAiUseJev' | 'takeoverAiUseJev'
                    label: string
                    /** One line under the label; the full text stays in the info tooltip. */
                    summary: string
                    description: string
                  }> = [
                    {
                      field: 'ffufAiExtensions',
                      engineField: 'ffufAiUseJev',
                      label: 'FFuf: Use AI for Extensions',
                      summary: 'Picks file extensions per target from its response headers.',
                      description: 'For each fuzz target, FFuf first sends a single HEAD request and asks the configured model to suggest the most likely file extensions based on the response headers (Server, X-Powered-By, X-AspNet-Version). The static FFuf extensions list in the FFuf module is ignored when this is on. Same toggle as in the FFuf module: flipping it here flips it there. A per-fingerprint cache means N hosts behind the same stack collapse to one LLM call.',
                    },
                    {
                      field: 'nucleiAiTags',
                      engineField: 'nucleiTagsAiUseJev',
                      label: 'Nuclei: Use AI for Tag Selection',
                      summary: 'Prunes the tag list to the detected tech stack, once per scan.',
                      description: 'Once per scan, Nuclei aggregates the detected tech stack from http_probe (Wappalyzer + Server headers) and asks the configured model to prune its include-tags list to ones matching the stack. Drops irrelevant tags like wordpress on Node sites, adds tech-specific ones like apache or wp-plugin when detected. The static Include Tags list in the Nuclei module is ignored when this is on. Same toggle as in the Nuclei module: flipping it here flips it there. Candidate tag pool is built from the live nuclei-templates volume (count >= 50, ~125 broad-category tags).',
                    },
                    {
                      field: 'wafAiClassifier',
                      engineField: 'wafAiUseJev',
                      label: 'Security Checks: Use AI for WAF Classification',
                      summary: 'Scores WAF/CDN presence when the header check misses it.',
                      description: 'Augments the static WAF/CDN header-token check used by the Direct IP and WAF Bypass checks. When the static list misses (modern WAFs strip or rebrand their headers), the response gets a second pass through the configured model, which scores WAF presence 0-100 from headers, body fingerprints, cookies, and latency. Same toggle as in the Security Checks module: flipping it here flips it there. A per-response fingerprint cache collapses identical responses to one LLM call.',
                    },
                    {
                      field: 'nucleiAiResponseFilter',
                      label: 'Nuclei: Use AI to Filter False-Positive Block Pages',
                      summary: 'Tells a WAF block page from a real hit on suspicious findings.',
                      description: "Augments the keyword-based WAF/rate-limit detection inside Nuclei's false-positive filter. When the static list misses (rebranded WAF blocks, AWS WAF JSON errors, custom Fortinet pages) but the response still looks like a block (suspicious status code on an injection finding), the LLM classifies the body as block-page or real hit. Suppresses fake findings and exposes real ones the keyword filter wrongly hides. Same toggle as in the Nuclei module: flipping it here flips it there. Per-response fingerprint cache keeps cost bounded.",
                    },
                    {
                      field: 'takeoverAiClassifier',
                      engineField: 'takeoverAiUseJev',
                      label: 'Takeover: Use AI to Disambiguate WAF "No-Host" Pages',
                      summary: 'Tells a real unclaimed-service page from a WAF block page.',
                      description: "Subjack/Nuclei takeover fingerprints can collide with WAF block pages that say \"not found\" for a hostname the WAF doesn't recognize. When AI is on, each takeover candidate is probed; if the response carries no third-party vendor token (Heroku-Request-Id, x-amz-bucket-region, etc.), the LLM classifies the body as a real unclaimed-service page or a WAF block. AI-flagged collisions get a -40 score penalty so they land in manual_review instead of being shipped as criticals. Same toggle as in the Subdomain Takeover module: flipping it here flips it there.",
                    },
                  ]
                  // Jev-only hooks: no LLM twin and no per-hook AI flag, so the card
                  // has one Off | Jev control. Never part of the master cascade above:
                  // aiInPipeline does not set or reset them.
                  const jevOnlyHooks: Array<{
                    field: 'ffufJevBasePaths' | 'httpxJevPageType' | 'resourceEnumJevToolHealth' | 'hakrawlerJevSeedOrder'
                      | 'serializedScanJevRank' | 'routeExposureJevRank' | 'routeExposureJevWallCheck'
                      | 'routeExposureJevAssess'
                    label: string
                    summary: string
                    description: string
                  }> = [
                    {
                      field: 'httpxJevPageType',
                      label: 'HTTP Probe: Label Page Types with Jev',
                      summary: 'Labels each probed page: app, login wall, parked, default, placeholder or error.',
                      description: 'After httpx probes each URL, Jev labels every page with one yes/no question per class. A deterministic pre-filter (default install titles, parking CNAMEs, error statuses, login paths) supplies the label only where Jev gives no answer. An unsure answer is "app", so nothing is hidden. The label is written onto the Endpoint in the graph (page_class) and kept in the recon output; what gets scanned does not change. At most 300 distinct pages per scan, within 60 seconds. Same switch as in the httpx module.',
                    },
                    {
                      field: 'ffufJevBasePaths',
                      label: 'FFuf: Rank Smart-Fuzz Directories with Jev',
                      summary: 'Picks which discovered directories FFuf smart-fuzzes under its cap.',
                      description: 'When smart fuzz has more discovered base directories than its cap, Jev is asked, per directory, whether it is likely to hold sensitive, administrative or application content, and its best ones fill the cap. The same number of directories is fuzzed either way, and the random pick is the fallback when Jev is unavailable. Same switch as in the FFuf module.',
                    },
                    {
                      field: 'hakrawlerJevSeedOrder',
                      label: 'Hakrawler: Order Seeds with Jev',
                      summary: 'Orders hosts so a capped crawl reaches the promising ones first.',
                      description: 'Hakrawler crawls its seeds in list order and stops once its URL cap is reached, so with a tight cap hosts late in the alphabet are never crawled. Jev is asked, per probed host, whether it has a rich web application surface, and Hakrawler crawls host by host in that order (alphabetical when Jev is unavailable). Ordering only: every seed stays in the list. Partial recon keeps the alphabetical order. Same switch as in the Hakrawler module.',
                    },
                    {
                      field: 'resourceEnumJevToolHealth',
                      label: 'Resource Enum: Read Tool Errors with Jev',
                      summary: 'Asks whether an empty result with odd error output was a transient failure.',
                      description: 'Every empty result from a crawler or collector is classified from its exit code and error output, and one that looks like a failure is recorded as a coverage gap, with or without this switch. When the error output fits neither a routine line nor a known failure, Jev is asked whether it describes a transient failure a second run could fix. At most 20 questions per run, header values redacted. The verdict is kept in the recon output next to the coverage gap; no tool is re-run. Same switch as in the Resource Enum AI module.',
                    },
                    {
                      field: 'serializedScanJevRank',
                      label: 'Serialized Objects: Rank Candidates with Jev',
                      summary: 'Asks which format each flagged blob is and how likely it is to be a reachable sink.',
                      description: 'When the Serialized Object Scan flags candidates, Jev is asked, per distinct blob, which serialization format it is (one of the scanner\'s 13, or none) and whether it is likely to be an attacker-reachable deserialization sink. Jev is not told which format the signatures matched, so its answer is a second opinion. Both answers are written onto the candidate, and the agent\'s deserialization skill confirms the most reachable first. It never drops a candidate and never changes the matched format; without a Jev token, or for a blob Jev cannot answer, the candidates stay exactly as the signatures flagged them. Needs the Serialized Object Scan on. At most 200 distinct blobs per scan, within a 60-second budget. Same switch as in the Serialized Object Scan module.',
                    },
                    {
                      field: 'routeExposureJevRank',
                      label: 'Route Exposure: Rank Routes with Jev',
                      summary: 'Requests the routes Jev reads as logged-in, internal or admin only first.',
                      description: 'Jev is asked, per route, whether it is meant only for logged-in, internal or administrative callers, from its path, method, category and four flags. Its answer fills the request budget after the always-requested routes, so the routes it reads as private are requested first, and it is saved on each lead (route_jev_privacy). It never cuts an always-requested route; without a Jev token, or when Jev cannot answer, the order is the built-in one. Needs Route Exposure on. At most 400 routes per scan. Same switch as in the Route Exposure module.',
                    },
                    {
                      field: 'routeExposureJevWallCheck',
                      label: 'Route Exposure: Spot Disguised Login Walls with Jev',
                      summary: 'Moves an HTML lead that is really a login form or error page to the end.',
                      description: 'For the HTML pages the deterministic page check kept as leads, Jev is asked which page class each is. The body reaches Jev masked and capped. The page class is saved on the lead in the graph (anon_page_class), and a lead Jev places as a login wall, error page or placeholder at confidence 70 or more moves to the end of the list the agent confirms. No lead is ever dropped. Needs Route Exposure on. At most 100 pages per scan, within a 60-second budget. Same switch as in the Route Exposure module.',
                    },
                    {
                      field: 'routeExposureJevAssess',
                      label: 'Route Exposure: Assess Leads with Jev',
                      summary: 'Orders the leads the agent confirms by how sensitive Jev reads each one.',
                      description: 'Jev is asked, per lead, which kind of route it is and how sensitive what it returns is, from the evidence alone: statuses, content class, masked key names and closed hints. It is never told the route class or a value. Both answers are saved on the lead in the graph (route_jev_kind, route_jev_sensitivity), and the agent confirms the most sensitive leads first; a lead Jev reads as public content at confidence 70 or more goes last. No lead is ever dropped and the route class is never rewritten. Needs Route Exposure on. At most 200 leads per scan, within a 60-second budget. Same switch as in the Route Exposure module.',
                    },
                  ]
                  return (
                    <div className={aiStyles.hookList} data-testid="ai-hook-list">
                      {aiPipelineHooks.map((hook) => {
                        const on = data[hook.field]
                        return (
                          <div
                            key={hook.field}
                            className={`${aiStyles.hookCard} ${on ? aiStyles.hookCardOn : ''}`}
                            data-testid={`ai-hook-${hook.field}`}
                          >
                            <div className={aiStyles.hookHead}>
                              <div className={aiStyles.hookText}>
                                <AiToggleLabel label={hook.label} tooltip={hook.description} />
                                <span className={aiStyles.hookSummary}>{hook.summary}</span>
                              </div>
                              <Toggle
                                checked={on}
                                onChange={(checked) => updateField(hook.field, checked)}
                              />
                            </div>
                            <div className={aiStyles.hookEngine}>
                              <span className={aiStyles.engineLabel}>Engine</span>
                              {hook.engineField ? (
                                <JevEngineControl
                                  value={data[hook.engineField]}
                                  enabled={data.aiInPipeline && on}
                                  disabledHint="Turn this hook on to choose its engine."
                                  jevStatus={jevStatus}
                                  onSelect={(useJev) => updateField(hook.engineField!, useJev)}
                                />
                              ) : (
                                <span
                                  className={aiStyles.llmOnly}
                                  title="This hook can drop a finding based on bytes the target controls, so it is not offered on Jev."
                                >
                                  LLM only
                                </span>
                              )}
                            </div>
                          </div>
                        )
                      })}
                      {jevOnlyHooks.map((hook) => (
                        <div
                          key={hook.field}
                          className={`${aiStyles.hookCard} ${data[hook.field] ? aiStyles.hookCardOn : ''}`}
                          data-testid={`ai-hook-${hook.field}`}
                        >
                          <div className={aiStyles.hookHead}>
                            <div className={aiStyles.hookText}>
                              <AiToggleLabel label={hook.label} tooltip={hook.description} />
                              <span className={aiStyles.hookSummary}>{hook.summary}</span>
                            </div>
                          </div>
                          <div className={aiStyles.hookEngine}>
                            <span className={aiStyles.engineLabel}>Jev only</span>
                            <JevEngineControl
                              variant="jevOnly"
                              value={data[hook.field]}
                              enabled={data.aiInPipeline}
                              jevStatus={jevStatus}
                              onSelect={(on) => updateField(hook.field, on)}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                })()}
              </>
            )}
          </div>

          {/* Domain ownership is a DNS TXT check, which a bare IP target cannot satisfy. */}
          {!ipMode && (
            <div className={styles.subSection}>
              <h3 className={styles.subSectionTitle}>Domain Verification</h3>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Verify Domain Ownership</span>
                  <p className={styles.toggleDescription}>
                    Require a DNS TXT record <code>redamon-verify=&lt;token&gt;</code> before
                    scanning. Each scan root accepts it at <code>{ownershipPrefix}.&lt;scan root&gt;</code>{' '}
                    or at <code>{ownershipPrefix}.&lt;registrable domain&gt;</code>
                    {!batchMode && singleGroup && (
                      <>
                        {' '}(here{' '}
                        {ownershipRecordNames(singleGroup, ownershipPrefix).map((name, k) => (
                          <span key={name}>{k > 0 && ' or '}<code>{name}</code></span>
                        ))}
                        )
                      </>
                    )}
                    .
                  </p>
                </div>
                <Toggle
                  checked={data.verifyDomainOwnership}
                  onChange={(checked) => updateField('verifyDomainOwnership', checked)}
                />
              </div>

              {data.verifyDomainOwnership && (
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Ownership Token</label>
                    <input
                      type="text"
                      className="textInput"
                      value={data.ownershipToken}
                      onChange={(e) => updateField('ownershipToken', e.target.value)}
                    />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>TXT Record Prefix</label>
                    <input
                      type="text"
                      className="textInput"
                      value={data.ownershipTxtPrefix}
                      onChange={(e) => updateField('ownershipTxtPrefix', e.target.value)}
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* --- Engagement limits ------------------------------------------------
              The eight limits that configure no single module: they cap every
              tool, filter every phase, or gate the whole run. That is the rule
              that puts them here and keeps everything else out - a tool's own
              setting belongs beside that tool, not in a shared drawer.

              There is no master switch, deliberately. It used to be one
              (`roeEnabled`), and a switch whose only function is to disable
              other safety fields is a bypass by design: one write of false and
              the ceiling, the exclusions and the window all stopped applying at
              once, with every field still showing its configured value. The
              status line below reports the DERIVED answer instead, and it is
              never part of the form's data, so it cannot make the form dirty. */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>
              <Gauge size={14} />
              Engagement limits
            </h3>
            <p className={styles.sectionDescription}>
              Enforced at scan start whatever any tool&apos;s own setting says, and reachable
              from the API in exactly the same way. Changing one applies to the NEXT scan.
            </p>

            <div className={`${styles.statusLine} ${limitsActive ? styles.statusLineActive : ''}`}>
              {limitsActive
                ? `Limits are ACTIVE because ${activeLimits.join(' and ')} ${activeLimits.length === 1 ? 'is' : 'are'} set.`
                : 'No limits are active: set a rate ceiling, exclude a host, or restrict the ' +
                  'scanning window. Every tool runs at whatever rate its own setting says.'}
              {/* A third-party engagement is REFUSED without a ceiling rather
                  than merely unconstrained, so the generic line above
                  understates it by exactly the amount that matters. */}
              {data.engagementKind === 'third_party' && !(data.roeGlobalMaxRps > 0) && (
                <strong className={styles.statusLineAlert}>
                  This is a third-party engagement, so a scan will be REFUSED until a
                  request-rate ceiling is set here.
                </strong>
              )}
            </div>

            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel} htmlFor="engagement-max-rps">
                  Global max requests/sec
                </label>
                <input
                  id="engagement-max-rps"
                  className="textInput"
                  type="number"
                  min={0}
                  max={10000}
                  value={data.roeGlobalMaxRps}
                  onChange={(e) => updateField('roeGlobalMaxRps', parseInt(e.target.value) || 0)}
                />
                <span className={styles.fieldHint}>
                  Caps every tool&apos;s rate at scan start, including the ones whose own value
                  means &ldquo;unlimited&rdquo;. <strong>0 means NO ceiling</strong>, not a slow
                  one.
                </span>
              </div>
            </div>

            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Never-touch hosts</label>
              <span className={styles.fieldHint}>
                IPs or domains that must NEVER be scanned, even though they fall inside the
                target scope. Dropped from expanded IPs, from discovered subdomains, and from
                the target domain itself.
              </span>
              {(data.roeExcludedHosts || []).map((host, i) => (
                <div key={i} className={styles.excludedHostRow}>
                  <input
                    className="textInput"
                    value={host}
                    onChange={(e) => updateExcludedHost(i, e.target.value)}
                    placeholder="IP or domain"
                    aria-label={`Excluded host ${i + 1}`}
                  />
                  <input
                    className="textInput"
                    value={(data.roeExcludedHostReasons || [])[i] || ''}
                    onChange={(e) => updateExcludedReason(i, e.target.value)}
                    placeholder="Why excluded"
                    aria-label={`Exclusion reason ${i + 1}`}
                  />
                  <button type="button" className="secondaryButton" onClick={() => removeExcludedHost(i)}
                    aria-label={`Remove excluded host ${i + 1}`}>
                    <Minus size={14} />
                  </button>
                </div>
              ))}
              <button type="button" className="secondaryButton" onClick={addExcludedHost}
                style={{ width: 'fit-content', marginTop: 'var(--space-2)' }}>
                <Plus size={14} /> Add excluded host
              </button>
            </div>

            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Restrict scanning to a time window</span>
                <p className={styles.toggleDescription}>
                  Outside the window the orchestrator refuses a scan start outright, so a
                  nightly job scheduled outside it will not run.
                </p>
              </div>
              <Toggle
                checked={data.roeTimeWindowEnabled}
                onChange={(checked) => updateField('roeTimeWindowEnabled', checked)}
              />
            </div>

            {data.roeTimeWindowEnabled && (
              <>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel} htmlFor="engagement-window-tz">
                      Timezone
                    </label>
                    <input id="engagement-window-tz" className="textInput"
                      value={data.roeTimeWindowTimezone}
                      onChange={(e) => updateField('roeTimeWindowTimezone', e.target.value)}
                      placeholder="e.g. Europe/Rome, America/New_York" />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel} htmlFor="engagement-window-start">
                      Start time
                    </label>
                    <input id="engagement-window-start" className="textInput" type="time"
                      value={data.roeTimeWindowStartTime}
                      onChange={(e) => updateField('roeTimeWindowStartTime', e.target.value)} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel} htmlFor="engagement-window-end">
                      End time
                    </label>
                    <input id="engagement-window-end" className="textInput" type="time"
                      value={data.roeTimeWindowEndTime}
                      onChange={(e) => updateField('roeTimeWindowEndTime', e.target.value)} />
                  </div>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Allowed days</label>
                  <div className={styles.dayPicker}>
                    {WEEKDAYS.map(day => {
                      const on = (data.roeTimeWindowDays || []).includes(day)
                      return (
                        <label key={day} className={`${styles.dayChip} ${on ? styles.dayChipOn : ''}`}>
                          <input type="checkbox" checked={on} onChange={() => toggleDay(day)} />
                          {day.charAt(0).toUpperCase() + day.slice(1, 3)}
                        </label>
                      )
                    })}
                  </div>
                </div>
              </>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Stealth Mode</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Stealth Mode</span>
                <p className={styles.toggleDescription}>
                  Force the entire pipeline to use only passive and low-noise techniques.
                  Active scanners (Kiterunner, banner grabbing, OpenAPI import) are disabled. Port scanning
                  switches to passive mode. Nuclei disables DAST and interactsh. The AI agent
                  uses only stealthy methods and will stop if stealth is impossible for a
                  requested action.
                </p>
              </div>
              <Toggle
                checked={data.stealthMode}
                onChange={(checked) => updateField('stealthMode', checked)}
              />
            </div>
          </div>

          {/* Target Guardrail */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Target Guardrail</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Target Guardrail</span>
                <p className={styles.toggleDescription}>
                  Block well-known public targets (major tech companies,
                  cloud providers, financial institutions, etc.) when saving the project.
                  Prevents accidental scanning of unauthorized domains.
                  Government, military, educational, and international organization domains
                  (.gov, .mil, .edu, .int) are always blocked regardless of this setting.
                </p>
              </div>
              <Toggle
                checked={data.targetGuardrailEnabled ?? true}
                onChange={(checked) => updateField('targetGuardrailEnabled', checked)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
