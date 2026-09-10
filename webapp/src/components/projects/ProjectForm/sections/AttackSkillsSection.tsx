'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { SETTINGS_SKILLS_HREF } from '@/lib/settingsLinks'
import { ChevronDown, Bug, KeyRound, Mail, Swords, Loader2, Settings, Zap, Database, Code2, Globe, Terminal, FolderTree, Download, ShieldAlert, FileCode2, Binary } from 'lucide-react'
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
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AttackSkillsSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
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
}

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
    path_traversal: true,
    access_control: true,
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
    return raw as AttackSkillConfig
  }
  return DEFAULT_CONFIG
}

export function AttackSkillsSection({ data, updateField }: AttackSkillsSectionProps) {
  const { userId } = useProject()
  const { alertError, alert: showAlert } = useAlertModal()
  const [builtInOpen, setBuiltInOpen] = useState(true)
  const [userOpen, setUserOpen] = useState(true)
  const [userSkills, setUserSkills] = useState<UserSkillDef[]>([])
  const [loading, setLoading] = useState(true)
  const [importing, setImporting] = useState(false)

  const config = getConfig(data)

  // Fetch available user skills
  const fetchUserSkills = useCallback(async () => {
    if (!userId) { setLoading(false); return }
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`)
      if (resp.ok) setUserSkills(await resp.json())
    } catch (err) {
      console.error('Failed to fetch user attack skills:', err)
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { fetchUserSkills() }, [fetchUserSkills])

  const isBuiltInEnabled = (skillId: string) => {
    if (skillId in config.builtIn) {
      return config.builtIn[skillId] !== false
    }
    // Key missing from saved config: fall back to the shipped default so the
    // UI matches what the Python agent does (get_enabled_builtin_skills is a
    // strict has-key check; missing key = disabled). Without this fallback,
    // legacy projects show new skills as ON in the UI while the agent treats
    // them as OFF, and toggling does not persist until the user explicitly
    // clicks. Default-OFF skills like ssrf are the obvious victim.
    return DEFAULT_CONFIG.builtIn[skillId] ?? false
  }

  const isUserEnabled = (skillId: string) => {
    return config.user[skillId] === true
  }

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
      if (!resp.ok) return
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
    }
  }, [userId])

  const importCommunityAgentSkills = useCallback(async () => {
    if (!userId || importing) return
    setImporting(true)
    try {
      const previousIds = new Set(userSkills.map(s => s.id))

      const resp = await fetch(`/api/users/${userId}/attack-skills/import-community`, { method: 'POST' })
      const result = await resp.json()
      if (!resp.ok) {
        alertError(result.error || 'Failed to import community skills')
        return
      }

      const refreshResp = await fetch(`/api/users/${userId}/attack-skills`)
      if (!refreshResp.ok) {
        showAlert(result.message || `Imported ${result.imported ?? 0} community skill(s).`)
        return
      }
      const fresh: UserSkillDef[] = await refreshResp.json()
      setUserSkills(fresh)

      // Enable newly imported skills in THIS project's config (existing ones untouched).
      const newlyImported = fresh.filter(s => !previousIds.has(s.id))
      if (newlyImported.length > 0) {
        const updatedUser = { ...config.user }
        for (const s of newlyImported) updatedUser[s.id] = true
        const newConfig: AttackSkillConfig = { ...config, user: updatedUser }
        updateField('attackSkillConfig', newConfig as unknown as FormData['attackSkillConfig'])
      }

      showAlert(
        `Imported ${result.imported ?? 0} community skill(s)` +
        (result.skipped ? `, skipped ${result.skipped} duplicate(s)` : '') +
        '. New skills are enabled for this project.'
      )
    } catch (err) {
      console.error('Failed to import community skills:', err)
      alertError('Failed to import community skills')
    } finally {
      setImporting(false)
    }
  }, [userId, importing, userSkills, config, updateField, alertError, showAlert])

  return (
    <>
      {/* Built-in Agent Skills */}
      <div className={styles.section}>
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

            {BUILT_IN_SKILLS.map(skill => {
              const enabled = isBuiltInEnabled(skill.id)
              return (
                <div
                  key={skill.id}
                  style={{
                    marginBottom: 'var(--space-4)',
                    opacity: enabled ? 1 : 0.5,
                    transition: 'opacity 0.2s ease',
                  }}
                >
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-3)',
                    marginBottom: enabled ? 'var(--space-3)' : 0,
                    padding: 'var(--space-3)',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-default)',
                  }}>
                    <Toggle
                      checked={enabled}
                      onChange={(v) => toggleBuiltIn(skill.id, v)}
                      size="large"
                    />
                    <div style={{ flex: 1 }}>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-1-5)',
                        fontSize: 'var(--text-sm)',
                        fontWeight: 'var(--font-semibold)',
                        color: 'var(--text-primary)',
                      }}>
                        {skill.icon}
                        {skill.name}
                        <span className={styles.badgeActive}>Active</span>
                      </div>
                      <div style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--text-tertiary)',
                        marginTop: '2px',
                      }}>
                        {skill.description}
                      </div>
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
                    <RceSection data={data} updateField={updateField} />
                  )}
                  {enabled && skill.id === 'path_traversal' && (
                    <PathTraversalSection data={data} updateField={updateField} />
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* User Agent Skills */}
      <div className={styles.section}>
        <div className={styles.sectionHeader} onClick={() => setUserOpen(!userOpen)}>
          <h2 className={styles.sectionTitle}>
            <Swords size={16} />
            User Agent Skills
            <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills#community-skills" title="Open Community Agent Skills wiki section" />
          </h2>
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <button
              type="button"
              className="secondaryButton"
              onClick={(e) => { e.stopPropagation(); importCommunityAgentSkills() }}
              disabled={importing || !userId}
              title="Import all community attack skills into your library and enable them for this project"
            >
              {importing
                ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
                : <Download size={14} />}
              Import from Community
            </button>
            <ChevronDown
              size={16}
              className={`${styles.sectionIcon} ${userOpen ? styles.sectionIconOpen : ''}`}
            />
          </div>
        </div>

        {userOpen && (
          <div className={styles.sectionContent}>
            <p className={styles.sectionDescription}>
              Custom agent skills uploaded from Global Settings. Enable a skill to let the agent
              classify requests into it and use its workflow. Newly imported skills default to off
              for new projects; use the Import shortcut above to bulk-import community templates and
              auto-enable them for this project.
            </p>

            {loading ? (
              <div style={{ textAlign: 'center', padding: 'var(--space-4)', color: 'var(--text-tertiary)' }}>
                <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Loading...
              </div>
            ) : userSkills.length === 0 ? (
              <div style={{
                textAlign: 'center',
                padding: 'var(--space-6) var(--space-4)',
                color: 'var(--text-tertiary)',
                fontSize: 'var(--text-sm)',
              }}>
                <p style={{ marginBottom: 'var(--space-3)' }}>
                  No user skills uploaded yet. Upload <code>.md</code> skill files from Global Settings to create custom attack workflows.
                </p>
                <Link
                  href={SETTINGS_SKILLS_HREF}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 'var(--space-1-5)',
                    padding: 'var(--space-2) var(--space-3)',
                    fontSize: 'var(--text-xs)',
                    fontWeight: 'var(--font-medium)',
                    color: 'var(--text-primary)',
                    background: 'var(--bg-hover)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-default)',
                    textDecoration: 'none',
                    transition: 'var(--transition-all)',
                  }}
                >
                  <Settings size={13} />
                  Go to Global Settings
                </Link>
              </div>
            ) : (
              userSkills.map(skill => {
                const enabled = isUserEnabled(skill.id)
                return (
                  <div
                    key={skill.id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--space-3)',
                      marginBottom: 'var(--space-2)',
                      padding: 'var(--space-3)',
                      background: 'var(--bg-primary)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 'var(--radius-default)',
                      opacity: enabled ? 1 : 0.5,
                      transition: 'opacity 0.2s ease',
                    }}
                  >
                    <Toggle
                      checked={enabled}
                      onChange={(v) => toggleUser(skill.id, v)}
                      size="large"
                    />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-1-5)',
                        fontSize: 'var(--text-sm)',
                        fontWeight: 'var(--font-semibold)',
                        color: 'var(--text-primary)',
                      }}>
                        <Swords size={14} />
                        {skill.name}
                      </div>
                      <div style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--text-tertiary)',
                        marginTop: '2px',
                      }}>
                        {skill.description || (
                          <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>
                        )}
                      </div>
                      <div style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--text-tertiary)',
                        marginTop: '2px',
                      }}>
                        Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="iconButton"
                      title="Download .md"
                      onClick={() => downloadSkill(skill.id, skill.name)}
                    >
                      <Download size={14} />
                    </button>
                  </div>
                )
              })
            )}
          </div>
        )}
      </div>
    </>
  )
}
