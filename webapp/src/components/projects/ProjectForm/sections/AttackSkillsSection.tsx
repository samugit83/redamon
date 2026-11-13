'use client'

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import Link from 'next/link'
import { SETTINGS_SKILLS_HREF } from '@/lib/settingsLinks'
import { ChevronDown, Bug, KeyRound, Mail, Swords, Loader2, Settings, Zap, Database, Code2, Globe, Terminal, FolderTree, Download, ShieldAlert, FileCode2, Binary, Split, Search, GitBranch, ShieldOff, AlertTriangle, Upload, Files } from 'lucide-react'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import { useAlertModal } from '@/components/ui/AlertModal'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import { HydraSection } from './BruteForceSection'
import { PhishingSection } from './PhishingSection'
import { DosSection } from './DosSection'
import { SqliSection } from './SqliSection'
import { SsrfSection } from './SsrfSection'
import { RceSection } from './RceSection'
import { PathTraversalSection } from './PathTraversalSection'
import { DeserializationSection } from './DeserializationSection'
import { PluginSkillRow } from '@/components/plugins/skills/PluginSkillRow'
import { usePluginSkillOverrides } from '@/components/plugins/skills/usePluginSkillOverrides'
import { SkillVersionsModal } from '@/components/plugins/review/SkillVersionsModal'
import { OverrideReviewModal } from '@/components/plugins/review/OverrideReviewModal'
import { importSummary } from '@/components/settings/AgentSkillsTab'
import { useSkillUpload } from '@/components/userSkills/useSkillUpload'
import { MAX_ENABLED_USER_SKILLS_PER_PROJECT, MAX_SKILLS_PER_USER, USER_SKILL_LIMIT_TEXT } from '@/lib/userSkills'
import { postUserSkillsChanged, useUserSkillsChanged } from '@/lib/userSkillsChannel'
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'
import styles from '../ProjectForm.module.css'

const LOAD_FAILED = 'Your skills could not be loaded'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AttackSkillsSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  /**
   * The saved project's id. Plugin version controls render only when it is set: the section
   * also renders in create mode (no project yet) and inside the chat SettingsModal, whose
   * debounced whole-row PUT swallows errors, so Reset/Delete are their own API calls (X23).
   * The upload dialog saves skills, and with a saved project their toggles, through its own
   * API call; only create-mode toggles go through `updateField`.
   */
  projectId?: string | null
  /** Opens the RoE tab; absent in the chat SettingsModal, which has no tabs. */
  onOpenRoe?: () => void
}

interface BuiltInSkillDef {
  id: string
  name: string
  description: string
  icon: React.ReactNode
}

interface UserSkillDef {
  id: string
  name: string
  description?: string | null
  createdAt: string
  version?: number | null
  lineageRootId?: string | null
  derivedFromName?: string | null
  quarantinedAt?: string | null
}

const LIMIT_TOOLTIP = `A project can use at most ${MAX_ENABLED_USER_SKILLS_PER_PROJECT} of your skills; turn one off first`

const BUILT_IN_SKILLS: BuiltInSkillDef[] = [
  {
    id: 'cve_exploit',
    name: 'CVE (MSF)',
    description: 'Exploit known CVEs using Metasploit Framework modules against target services',
    icon: <Bug size={16} />,
  },
  {
    id: 'sql_injection',
    name: 'SQL Injection',
    description: 'SQL injection testing with SQLMap, WAF bypass, blind injection, and OOB DNS exfiltration',
    icon: <Database size={16} />,
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    description: 'Reflected, stored, DOM-based, and blind XSS testing with dalfox, kxss, Playwright, and CSP-bypass guidance',
    icon: <Code2 size={16} />,
  },
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    description: 'SSRF detection, internal-network probing, cloud-metadata pivots, protocol smuggling, DNS rebinding, and Redis/FastCGI/Docker RCE chains',
    icon: <Globe size={16} />,
  },
  {
    id: 'rce',
    name: 'Remote Code Execution',
    description: 'RCE / command injection across six primitives: shell-metachar injection (commix), SSTI (sstimap), Java/PHP/Python deserialization (ysoserial), eval / OGNL / SpEL, media-pipeline RCE, and SSRF-to-RCE chains',
    icon: <Terminal size={16} />,
  },
  {
    id: 'deserialization',
    name: 'Insecure Deserialization',
    description: 'Confirms recon serialized-object candidates (Java, PHP, Python, .NET, Ruby, polymorphic JSON/XML/YAML, Hessian) with a non-destructive oracle (out-of-band callback, timing or error differential), then escalates to a gated gadget chain (ysoserial / phpggc). Reuses recon candidates first; exec gadgets off by default.',
    icon: <Binary size={16} />,
  },
  {
    id: 'path_traversal',
    name: 'Path Traversal / LFI / RFI',
    description: 'Arbitrary file read via path traversal, Local File Inclusion, Remote File Inclusion, PHP wrapper chains (php://filter, data://, expect://), log poisoning, and Zip Slip archive-extraction tests',
    icon: <FolderTree size={16} />,
  },
  {
    id: 'access_control',
    name: 'Broken Access Control',
    description: 'Authorization bypass: forced browsing, IDOR / BOLA, vertical/horizontal privilege escalation, HTTP verb tampering, 401/403 path-normalization and trust-header bypass, hidden-field / role tampering, JWT attacks, and CORS/GraphQL authz flaws',
    icon: <ShieldAlert size={16} />,
  },
  {
    id: 'http_request_smuggling',
    name: 'HTTP Request Smuggling / Desync',
    description: 'Desync a front proxy / load balancer / CDN / cache from the back-end app via CL.TE / TE.CL / TE.TE, obfuscated Transfer-Encoding, and CL.0 framing disagreements to bypass front-enforced access controls, poison another user\'s request, or reach internal-only hosts. Raw-socket byte-exact probing.',
    icon: <Split size={16} />,
  },
  {
    id: 'xxe',
    name: 'XML External Entity',
    description: 'XXE testing against XML parsers: in-band file read, php-filter source read, error-based and out-of-band exfiltration via external/local DTD, SSRF via entities, XInclude, content-type switching, and XXE in SVG/DOCX/SAML uploads',
    icon: <FileCode2 size={16} />,
  },
  {
    id: 'crypto_attack',
    name: 'Cryptographic Attacks',
    description: 'Break trusted crypto: CBC padding oracles and bit-flipping, ECB analysis, stream/nonce reuse (two-time pad), JWT signature attacks (alg:none, HS/RS confusion, weak-secret cracking, kid/jwk/jku), hash length extension, RSA weaknesses, and predictable-token/PRNG reconstruction',
    icon: <Binary size={16} />,
  },
  {
    id: 'brute_force_credential_guess',
    name: 'Credential Testing',
    description: 'Credential policy validation using Hydra against login services',
    icon: <KeyRound size={16} />,
  },
  {
    id: 'phishing_social_engineering',
    name: 'Social Engineering Simulation',
    description: 'Payload generation, document crafting, and email delivery for authorized awareness testing',
    icon: <Mail size={16} />,
  },
  {
    id: 'denial_of_service',
    name: 'Availability Testing',
    description: 'Assess service resilience using flooding, resource exhaustion, and crash vectors',
    icon: <Zap size={16} />,
  },
]

type AttackSkillConfig = {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
}

const DEFAULT_CONFIG: AttackSkillConfig = {
  builtIn: {
    cve_exploit: true,
    sql_injection: true,
    xss: true,
    ssrf: true,
    rce: true,
    deserialization: false,
    path_traversal: true,
    access_control: true,
    http_request_smuggling: false,
    xxe: true,
    crypto_attack: true,
    brute_force_credential_guess: false,
    phishing_social_engineering: false,
    denial_of_service: false,
  },
  user: {},
}

function getConfig(data: FormData): AttackSkillConfig {
  const raw = data.attackSkillConfig as unknown
  if (raw && typeof raw === 'object' && 'builtIn' in (raw as Record<string, unknown>)) {
    const config = raw as Partial<AttackSkillConfig> & { builtIn: Record<string, boolean> }
    // A stored config may lack `user`; every reader below indexes it.
    return config.user && typeof config.user === 'object' ? (config as AttackSkillConfig) : { ...config, user: {} }
  }
  return DEFAULT_CONFIG
}

export function AttackSkillsSection({ data, updateField, projectId, onOpenRoe }: AttackSkillsSectionProps) {
  const { userId } = useProject()
  const { alertError, alert: showAlert } = useAlertModal()
  // A collaborator's form (step 5.7): the toggles pick among the project OWNER's skills, listed by
  // name from the owner's catalog; turning one on or off needs Manage, and only the owner uploads.
  const owner = useOwnerCatalogSource()
  const ownerForm = owner !== null
  const skillRefusal = owner?.pickRefusal ?? null
  const ownerCatalog = owner?.catalog ?? null
  const ownerSkills = useMemo<UserSkillDef[]>(() => (ownerCatalog?.attackSkills ?? []).map(s => ({
    id: s.id, name: s.name, createdAt: '', quarantinedAt: s.quarantined ? 'quarantined' : null,
  })), [ownerCatalog])
  const [builtInOpen, setBuiltInOpen] = useState(true)
  const [userOpen, setUserOpen] = useState(true)
  const [ownSkills, setUserSkills] = useState<UserSkillDef[]>([])
  const userSkills = ownerForm ? ownerSkills : ownSkills
  const [ownLoading, setLoading] = useState(true)
  const loading = ownerForm ? owner.status === 'loading' : ownLoading
  // The failed read's " (code · HTTP n)"; null while the list is good.
  const [loadError, setLoadError] = useState<string | null>(null)
  // Whose list is loaded: until it is the current user's, the cap and the free slots would be
  // counted from an empty list, so the upload buttons wait.
  const loadedFor = useRef<string | null>(null)
  const [importing, setImporting] = useState(false)
  const [skillQuery, setSkillQuery] = useState('')
  const [enabledOnly, setEnabledOnly] = useState(false)

  // Plugin skill-version controls, only for a saved project (X23).
  const savedProjectId = projectId ?? null
  const { bySkill, rowActions, reload: reloadOverrides, error: pluginOverridesError } = usePluginSkillOverrides(savedProjectId)
  const [versionsSkill, setVersionsSkill] = useState<string | null>(null)
  const [reviewChangeSetId, setReviewChangeSetId] = useState<string | null>(null)

  const config = getConfig(data)
  // Create mode switches the new skills on from the toggles of the moment, not of a render ago.
  const configRef = useRef(config)
  configRef.current = config
  const userSkillsRef = useRef(userSkills)
  userSkillsRef.current = userSkills

  const fetchUserSkills = useCallback(async () => {
    if (!userId || ownerForm) return
    if (loadedFor.current !== userId) setLoading(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`)
      if (resp.ok) {
        setUserSkills(await resp.json())
        setLoadError(null)
        loadedFor.current = userId
      } else {
        setLoadError(formatApiError({ ...(await readApiError(resp, LOAD_FAILED)), reason: '' }))
      }
    } catch (err) {
      console.error('Failed to fetch user attack skills:', err)
      setLoadError(formatApiError({ ...toApiError(err, LOAD_FAILED), reason: '' }))
    } finally {
      setLoading(false)
    }
  }, [userId, ownerForm])

  useEffect(() => { fetchUserSkills() }, [fetchUserSkills])
  // A version saved in another window (a review in the chat drawer) appears here at once;
  // the form's own copy of the toggles is refreshed by ProjectForm.
  useUserSkillsChanged(() => { fetchUserSkills() })

  const isBuiltInEnabled = (skillId: string) => {
    if (skillId in config.builtIn) {
      return config.builtIn[skillId] !== false
    }
    // Key missing from the saved config (a project older than the skill): show
    // the shipped default. The agent's get_enabled_builtin_skills is a strict
    // has-key check, so a missing key is OFF there. The two agree for a skill
    // that is false in DEFAULT_CONFIG; a skill that is true in it shows ON here
    // while the agent treats it as OFF, until it is toggled and saved.
    return DEFAULT_CONFIG.builtIn[skillId] ?? false
  }

  const isUserEnabled = (skillId: string) => {
    return config.user[skillId] === true
  }

  // Only the owner's existing skills count, as on the server: a stale id in the map does not.
  const enabledCount = userSkills.filter(s => isUserEnabled(s.id)).length
  const atEnabledLimit = enabledCount >= MAX_ENABLED_USER_SKILLS_PER_PROJECT

  /** Create mode only: the new project does not exist yet, so its toggles are form state. */
  const enableInForm = useCallback((ids: string[]) => {
    const current = configRef.current
    let room = Math.max(0, MAX_ENABLED_USER_SKILLS_PER_PROJECT - userSkillsRef.current.filter(s => current.user[s.id] === true).length)
    const user = { ...current.user }
    let enabled = 0
    let leftOff = 0
    for (const id of ids) {
      if (room > 0) { user[id] = true; room--; enabled++ } else { leftOff++ }
    }
    if (enabled) updateField('attackSkillConfig', { ...current, user } as unknown as FormData['attackSkillConfig'])
    return { enabled, leftOff }
  }, [updateField])

  const upload = useSkillUpload({
    userId,
    existingCount: userSkills.length,
    project: {
      id: savedProjectId,
      freeSlots: Math.max(0, MAX_ENABLED_USER_SKILLS_PER_PROJECT - enabledCount),
      enableLocally: savedProjectId ? undefined : enableInForm,
    },
    onUploaded: () => { fetchUserSkills() },
  })
  const uploadTitle = loading
    ? 'Loading your skills…'
    : loadError !== null ? `${LOAD_FAILED}${loadError}. Reload the page to upload.`
      : loadedFor.current !== userId ? 'Loading your skills…'
        : userSkills.length >= MAX_SKILLS_PER_USER ? USER_SKILL_LIMIT_TEXT : undefined
  const uploadDisabled = !userId || !!uploadTitle
  // Two members of one family on at once: the agent sees two versions of the same skill.
  const familyOn = new Map<string, UserSkillDef[]>()
  for (const s of userSkills) {
    if (s.lineageRootId && isUserEnabled(s.id)) familyOn.set(s.lineageRootId, [...(familyOn.get(s.lineageRootId) ?? []), s])
  }
  const q = skillQuery.trim().toLowerCase()
  const shownUserSkills = userSkills.filter(s =>
    (!enabledOnly || isUserEnabled(s.id)) &&
    (!q || s.name.toLowerCase().includes(q) || (s.description ?? '').toLowerCase().includes(q)))

  const toggleBuiltIn = (skillId: string, enabled: boolean) => {
    const newConfig: AttackSkillConfig = {
      ...config,
      builtIn: { ...config.builtIn, [skillId]: enabled },
    }
    // Sync hydraEnabled with brute force master toggle
    if (skillId === 'brute_force_credential_guess') {
      updateField('hydraEnabled', enabled)
    }
    updateField('attackSkillConfig', newConfig as unknown as FormData['attackSkillConfig'])
  }

  const toggleUser = (skillId: string, enabled: boolean) => {
    if (enabled && !isUserEnabled(skillId) && atEnabledLimit) return
    const newConfig: AttackSkillConfig = {
      ...config,
      user: { ...config.user, [skillId]: enabled },
    }
    updateField('attackSkillConfig', newConfig as unknown as FormData['attackSkillConfig'])
  }

  const downloadSkill = useCallback(async (skillId: string, skillName: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (!resp.ok) {
        alertError((await readApiError(resp, 'Failed to download the skill')).message)
        return
      }
      const skill = await resp.json()
      const blob = new Blob([skill.content], { type: 'text/markdown' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${skillName}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to download skill:', err)
      alertError(toApiError(err, 'Failed to download the skill').message)
    }
  }, [userId, alertError])

  const importCommunityAgentSkills = useCallback(async () => {
    if (!userId || importing) return
    setImporting(true)
    try {
      const previousIds = new Set(userSkills.map(s => s.id))

      const resp = await fetch(`/api/users/${userId}/attack-skills/import-community`, { method: 'POST' })
      if (!resp.ok) {
        alertError((await readApiError(resp, 'Failed to import community skills')).message)
        return
      }
      const result = await resp.json().catch(() => null)
      if (!result) {
        // Skills may have landed even when the answer cannot be read.
        postUserSkillsChanged({})
        alertError(`Failed to read the import's answer (invalid_json · HTTP ${resp.status}). Check your skills list.`)
        return
      }

      const refreshResp = await fetch(`/api/users/${userId}/attack-skills`)
      if (!refreshResp.ok) {
        showAlert(result.message || `Imported ${result.imported ?? 0} community skill(s).`)
        return
      }
      const fresh: UserSkillDef[] = await refreshResp.json()
      setUserSkills(fresh)
      // Global Settings and other project windows list the new skills.
      postUserSkillsChanged({})

      // Enable newly imported skills in THIS project's config (existing ones untouched),
      // up to the per-project limit.
      const newlyImported = fresh.filter(s => !previousIds.has(s.id))
      let room = MAX_ENABLED_USER_SKILLS_PER_PROJECT - fresh.filter(s => config.user[s.id] === true).length
      let leftOff = 0
      if (newlyImported.length > 0) {
        const updatedUser = { ...config.user }
        for (const s of newlyImported) {
          if (room > 0) { updatedUser[s.id] = true; room-- } else { leftOff++ }
        }
        const newConfig: AttackSkillConfig = { ...config, user: updatedUser }
        updateField('attackSkillConfig', newConfig as unknown as FormData['attackSkillConfig'])
      }

      showAlert(
        importSummary(result) +
        (newlyImported.length - leftOff > 0 ? ` ${newlyImported.length - leftOff} new skill(s) are enabled for this project.` : '') +
        (leftOff ? ` ${leftOff} were left off: a project can use at most ${MAX_ENABLED_USER_SKILLS_PER_PROJECT} of your skills.` : '')
      )
    } catch (err) {
      console.error('Failed to import community skills:', err)
      alertError(toApiError(err, 'Failed to import community skills').message)
    } finally {
      setImporting(false)
    }
  }, [userId, importing, userSkills, config, updateField, alertError, showAlert])

  return (
    <>
      {/* Built-in Agent Skills */}
      <div className={`${styles.section} ${styles.formSkin}`}>
        <div className={styles.sectionHeader} onClick={() => setBuiltInOpen(!builtInOpen)}>
          <h2 className={styles.sectionTitle}>
            <Bug size={16} />
            Built-in Agent Skills
            <WikiInfoButton target="AttackSkills" />
            <span className={styles.badgeActive}>Active</span>
          </h2>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${builtInOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>

        {builtInOpen && (
          <div className={styles.sectionContent}>
            <p className={styles.sectionDescription}>
              Core agent skills with specialized workflows. Disable a skill to prevent the agent
              from classifying requests into that skill type and using its prompts.
            </p>

            <div className={styles.skillList}>
              {BUILT_IN_SKILLS.map(skill => {
                const enabled = isBuiltInEnabled(skill.id)
                return (
                  <div key={skill.id} className={`${styles.skillPanel} ${enabled ? '' : styles.skillPanelOff}`}>
                    <div className={styles.skillHead}>
                      <Toggle
                        checked={enabled}
                        onChange={(v) => toggleBuiltIn(skill.id, v)}
                        size="large"
                        aria-label={skill.name}
                      />
                      <div className={styles.skillInfo}>
                        <div className={styles.skillName}>
                          <span className={styles.skillIcon}>{skill.icon}</span>
                          {skill.name}
                          <span className={styles.badgeActive}>Active</span>
                        </div>
                        <div className={styles.skillDetail}>{skill.description}</div>
                      </div>
                    </div>

                    {/* Sub-settings rendered when skill is ON */}
                    {enabled && skill.id === 'brute_force_credential_guess' && (
                      <HydraSection data={data} updateField={updateField} />
                    )}
                    {enabled && skill.id === 'phishing_social_engineering' && (
                      <PhishingSection data={data} updateField={updateField} />
                    )}
                    {enabled && skill.id === 'denial_of_service' && (
                      <DosSection data={data} updateField={updateField} />
                    )}
                    {enabled && skill.id === 'sql_injection' && (
                      <SqliSection data={data} updateField={updateField} />
                    )}
                    {enabled && skill.id === 'ssrf' && (
                      <SsrfSection data={data} updateField={updateField} />
                    )}
                    {enabled && skill.id === 'rce' && (
                      <RceSection data={data} updateField={updateField} onOpenRoe={onOpenRoe} />
                    )}
                    {enabled && skill.id === 'path_traversal' && (
                      <PathTraversalSection data={data} updateField={updateField} onOpenRoe={onOpenRoe} />
                    )}
                    {enabled && skill.id === 'deserialization' && (
                      <DeserializationSection data={data} updateField={updateField} />
                    )}

                    {savedProjectId && (
                      <PluginSkillRow
                        skillId={skill.id}
                        projectId={savedProjectId}
                        scopeOwnerId={userId}
                        summary={bySkill.get(skill.id)}
                        rowActions={rowActions}
                        onVersions={setVersionsSkill}
                        onPending={setVersionsSkill}
                        onReset={reloadOverrides}
                      />
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* User Agent Skills */}
      <div className={`${styles.section} ${styles.formSkin}`}>
        <div className={`${styles.sectionHeader} ${styles.userSkillsHeader}`} onClick={() => setUserOpen(!userOpen)}>
          <div className={styles.userSkillsHeaderTitle}>
            <h2 className={styles.sectionTitle}>
              <Swords size={16} />
              User Agent Skills
              <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills#community-skills" title="Open Community Agent Skills wiki section" />
            </h2>
            <ChevronDown
              size={16}
              className={`${styles.sectionIcon} ${userOpen ? styles.sectionIconOpen : ''}`}
            />
          </div>
          {!ownerForm && <div className={styles.userSkillsHeaderActions}>
            <button
              type="button"
              className={`${styles.sectionHeaderButton} ${styles.sectionHeaderButtonPrimary}`}
              onClick={(e) => { e.stopPropagation(); upload.openSingle() }}
              disabled={uploadDisabled}
              title={uploadTitle ?? 'Upload one .md skill file'}
            >
              <Upload size={12} /> Upload Skill
            </button>
            <button
              type="button"
              className={styles.sectionHeaderButton}
              onClick={(e) => { e.stopPropagation(); upload.openBatch() }}
              disabled={uploadDisabled}
              title={uploadTitle ?? 'Upload several .md skill files at once'}
            >
              <Files size={12} /> Upload Batch
            </button>
            <button
              type="button"
              className={styles.sectionHeaderButton}
              onClick={(e) => { e.stopPropagation(); importCommunityAgentSkills() }}
              disabled={importing || !userId}
              title="Import all community attack skills into your library and enable them for this project"
            >
              {importing
                ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
                : <Download size={12} />}
              Import from Community
            </button>
          </div>}
        </div>

        {userOpen && (
          <div className={styles.sectionContent}>
            {ownerForm ? (
              <p className={styles.sectionDescription}>
                The project owner&apos;s agent skills, by name. A skill is off until it is turned on here;
                {skillRefusal ? ' turning one on or off needs Manage.' : ' only the owner uploads or edits them.'}
              </p>
            ) : (
              <p className={styles.sectionDescription}>
                Your own agent skills. Upload .md files here, one at a time or in a batch, or manage them
                in Global Settings. A skill is off until you turn it on here; uploads and community imports
                from this section can turn the new skills on for this project.
              </p>
            )}

            {userSkills.length > 0 && (
              <div className={styles.skillFilterBar}>
                <label className={styles.skillSearch}>
                  <Search size={14} aria-hidden />
                  <input
                    className="textInput"
                    type="search"
                    placeholder={ownerForm ? "Search the owner's skills" : 'Search your skills'}
                    aria-label={ownerForm ? "Search the owner's skills" : 'Search your skills'}
                    value={skillQuery}
                    onChange={e => setSkillQuery(e.target.value)}
                    style={{ flex: 1, minWidth: 0 }}
                  />
                </label>
                <label className={styles.skillFilterCheck}>
                  <input type="checkbox" checked={enabledOnly} onChange={e => setEnabledOnly(e.target.checked)} />
                  Enabled only
                </label>
                <span
                  data-testid="user-skill-enabled-count"
                  className={`${styles.fieldHint} ${atEnabledLimit ? styles.fieldHintCaution : ''}`}
                >
                  {enabledCount} of {MAX_ENABLED_USER_SKILLS_PER_PROJECT} enabled
                </span>
              </div>
            )}

            {pluginOverridesError && (
              <div className={styles.skillListNote} role="alert">
                {pluginOverridesError}{' '}
                <button type="button" className="secondaryButton" onClick={reloadOverrides}>Retry</button>
              </div>
            )}

            {loading ? (
              <div className={styles.skillListNote}>
                <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Loading...
              </div>
            ) : ownerForm && owner.status === 'error' ? (
              <div className={styles.skillListNote} role="alert">
                {owner.error}{' '}
                <button type="button" className="secondaryButton" onClick={owner.retry}>Retry</button>
              </div>
            ) : ownerForm && userSkills.length === 0 ? (
              <div className={styles.skillListNote}>The project owner has no agent skills.</div>
            ) : userSkills.length === 0 && loadError !== null ? (
              <div className={styles.skillListNote} role="alert">
                {LOAD_FAILED}{loadError}. Reload the page.
              </div>
            ) : userSkills.length === 0 ? (
              <div className={styles.skillEmptyState}>
                <p>
                  No user skills uploaded yet. Upload <code>.md</code> skill files above, or manage them in Global Settings.
                </p>
                <Link href={SETTINGS_SKILLS_HREF} className={styles.skillEmptyLink}>
                  <Settings size={13} />
                  Go to Global Settings
                </Link>
              </div>
            ) : shownUserSkills.length === 0 ? (
              <div className={styles.skillListNote}>
                No skill matches.
              </div>
            ) : (
              <div className={styles.skillList}>
                {shownUserSkills.map(skill => {
                  const enabled = isUserEnabled(skill.id)
                  const quarantined = !!skill.quarantinedAt
                  const blockedByLimit = !enabled && atEnabledLimit
                  const sibling = enabled && skill.lineageRootId
                    ? (familyOn.get(skill.lineageRootId) ?? []).find(o => o.id !== skill.id)
                    : undefined
                  return (
                    <div key={skill.id} className={`${styles.skillPanel} ${enabled ? '' : styles.skillPanelOff}`}>
                      <div className={styles.skillHead}>
                        <span
                          title={skillRefusal ?? (quarantined ? 'Quarantined: release it in Global Settings to turn it on' : blockedByLimit ? LIMIT_TOOLTIP : undefined)}
                          data-testid={`user-skill-toggle-${skill.id}`}
                        >
                          <Toggle
                            checked={enabled}
                            onChange={(v) => toggleUser(skill.id, v)}
                            size="large"
                            disabled={(quarantined && !enabled) || blockedByLimit || skillRefusal !== null}
                            aria-label={skill.name}
                          />
                        </span>
                        <div className={styles.skillInfo}>
                          <div className={styles.skillName}>
                            <span className={styles.skillIcon}><Swords size={14} /></span>
                            <span style={{ overflowWrap: 'anywhere' }}>{skill.name}</span>
                            {skill.version != null && (
                              <span className={styles.skillVersionBadge}>
                                <GitBranch size={10} aria-hidden /> v{skill.version}{skill.derivedFromName ? ` · from ${skill.derivedFromName}` : ''}
                              </span>
                            )}
                            {quarantined && (
                              <span className={styles.skillFlagDanger}>
                                <ShieldOff size={11} aria-hidden /> Quarantined
                              </span>
                            )}
                          </div>
                          {sibling && (
                            <div className={`${styles.fieldHint} ${styles.fieldHintCaution} ${styles.skillDetail} ${styles.skillWarning}`}>
                              <AlertTriangle size={11} aria-hidden /> {sibling.name} is also on: the agent sees two versions of the same skill.
                            </div>
                          )}
                          {!ownerForm && (
                            <>
                              <div className={styles.skillDetail}>
                                {skill.description || (
                                  <span className={styles.skillDetailEmpty}>No description</span>
                                )}
                              </div>
                              <div className={styles.skillDetail}>
                                Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                              </div>
                            </>
                          )}
                        </div>
                        {!ownerForm && (
                          <button
                            type="button"
                            className={`iconButton ${styles.skillIconButton}`}
                            title="Download .md"
                            onClick={() => downloadSkill(skill.id, skill.name)}
                          >
                            <Download size={14} />
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Outside the header: events from the portalled dialog bubble along the React tree,
          and a click there would collapse the section. */}
      {upload.dialogs}

      {savedProjectId && versionsSkill && (
        <SkillVersionsModal
          projectId={savedProjectId}
          initialSkill={versionsSkill}
          scopeOwnerId={userId}
          onClose={() => { setVersionsSkill(null); reloadOverrides() }}
          onOpenReview={(changeSetId) => { setVersionsSkill(null); setReviewChangeSetId(changeSetId) }}
          onReviewAgain={(changeSetId) => { setVersionsSkill(null); setReviewChangeSetId(changeSetId) }}
        />
      )}

      {savedProjectId && reviewChangeSetId && (
        <OverrideReviewModal
          changeSetId={reviewChangeSetId}
          scopeOwnerId={userId}
          projectId={savedProjectId}
          onClose={() => setReviewChangeSetId(null)}
          onDecided={() => { setReviewChangeSetId(null); reloadOverrides(); fetchUserSkills() }}
        />
      )}
    </>
  )
}
