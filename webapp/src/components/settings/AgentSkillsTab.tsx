'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, Download, Files, GitBranch, Inbox, Loader2, Pencil, Search, ShieldOff, Sparkles, Swords, Trash2, Upload } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { OverrideReviewModal } from '@/components/plugins/review/OverrideReviewModal'
import { FeatureModelLine, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { AI_FAILED_TEXT, CREDENTIALS_TEXT } from '@/components/userSkills/SkillUploadReviewModal'
import { useSkillUpload } from '@/components/userSkills/useSkillUpload'
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'
import { formatApiError, readApiError, toApiError, type ApiError } from '@/lib/apiError'
import { tidySkillName } from '@/lib/skillMetadata'
import { CREDENTIALS_ERROR } from '@/lib/skillUploadDraft'
import { DESCRIPTION_MAX_CHARS, MAX_SKILLS_PER_USER, NAME_MAX_CHARS, USER_SKILL_LIMIT_TEXT } from '@/lib/userSkills'
import { postUserSkillsChanged, useUserSkillsChanged } from '@/lib/userSkillsChannel'
import { nameCheckMessage, useSkillNameCheck } from './useSkillNameCheck'
import { offerCommunityUpdates } from './communitySkillUpdates'
import styles from './Settings.module.css'
import own from './AgentSkillsTab.module.css'

/** A row of GET /api/users/[id]/attack-skills. */
export interface UserSkillRow {
  id: string
  name: string
  description?: string | null
  createdAt: string
  version?: number | null
  lineageRootId?: string | null
  derivedFromName?: string | null
  originPluginId?: string | null
  quarantinedAt?: string | null
  quarantineReason?: string | null
  pendingChangeSetIds?: string[]
  duplicateName?: boolean
}

const QUARANTINE_TEXT: Record<string, string> = {
  plugin_version_revoked:
    'The plugin version that proposed this skill was revoked by the plugin catalog, so it was turned off in every project.',
  derived_from_revoked:
    'It was saved from a skill whose plugin version the plugin catalog revoked, so it carries that text on and was turned off in every project.',
}

const LOAD_FAILED = 'Your skills could not be loaded'

/** " (code · HTTP n)", the part of a failure's message after its reason. */
function causeOf(err: ApiError): string {
  return formatApiError({ ...err, reason: '' })
}

function downloadText(name: string, content: string) {
  const blob = new Blob([content], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${name}.md`
  a.click()
  URL.revokeObjectURL(url)
}

/**
 * Global Settings → Agent Skills: the user's own skills (upload, rename, describe,
 * download, delete, community import), the versions saved from a plugin's proposals with
 * their lineage, the proposals waiting for review, and the quarantine a revoked plugin
 * version puts on what it proposed.
 */
export function AgentSkillsTab({ userId }: { userId: string | null | undefined }) {
  const { alertError, alert: showAlert, confirm: showConfirm, dangerConfirm } = useAlertModal()
  const toast = useToast()
  const { ensureFeatureModel, fetchWithFeatureModel } = useFeatureModelGate()
  const [skills, setSkills] = useState<UserSkillRow[]>([])
  const [loading, setLoading] = useState(true)
  // The failed read's code and status, e.g. " (P1001 · HTTP 500)"; null while the list is good.
  const [loadError, setLoadError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [importing, setImporting] = useState(false)
  const [edit, setEdit] = useState<{ id: string; name: string; description: string } | null>(null)
  const [editSaving, setEditSaving] = useState(false)
  const [editError, setEditError] = useState<string | null>(null)
  // The skill whose Generate runs: per skill, so a run left behind by a closed dialog neither
  // blocks the next skill's button nor writes into its dialog.
  const [editGenerating, setEditGenerating] = useState<string | null>(null)
  const editGeneratingRef = useRef<string | null>(null)
  const editRef = useRef(edit)
  editRef.current = edit
  const [editAiError, setEditAiError] = useState<string | null>(null)
  const [reviewChangeSetId, setReviewChangeSetId] = useState<string | null>(null)

  // A failed read keeps the list it had, and says so: the cap is counted from this list.
  const fetchSkills = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`)
      if (resp.ok) {
        setSkills(await resp.json())
        setLoadError(null)
      } else {
        setLoadError(causeOf(await readApiError(resp, LOAD_FAILED)))
      }
    } catch (err) {
      console.error('Failed to fetch attack skills:', err)
      setLoadError(causeOf(toApiError(err, LOAD_FAILED)))
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { fetchSkills() }, [fetchSkills])
  useUserSkillsChanged(() => { fetchSkills() })

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return skills
    return skills.filter((s) => s.name.toLowerCase().includes(q) || (s.description ?? '').toLowerCase().includes(q))
  }, [skills, query])

  const editCheck = useSkillNameCheck(userId, edit?.name ?? '', { exceptId: edit?.id, enabled: !!edit && !!edit.name.trim() })

  const download = useCallback(async (skill: UserSkillRow) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skill.id}`)
      if (!resp.ok) {
        toast.error((await readApiError(resp, 'Failed to download the skill')).message)
        return
      }
      downloadText(skill.name, (await resp.json()).content)
    } catch (err) {
      console.error('Failed to download skill:', err)
      toast.error(toApiError(err, 'Failed to download the skill').message)
    }
  }, [userId, toast])

  const remove = useCallback(async (skill: UserSkillRow) => {
    if (!userId) return
    const waiting = skill.pendingChangeSetIds?.length ?? 0
    const message = 'Delete this skill? It will be removed from all projects.' +
      (waiting ? ` Its ${waiting} proposal${waiting === 1 ? '' : 's'} waiting for review ${waiting === 1 ? 'is' : 'are'} deleted too.` : '')
    if (!(await showConfirm(message))) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skill.id}`, { method: 'DELETE' })
      if (!resp.ok) {
        alertError((await readApiError(resp, 'Failed to delete skill')).message)
        return
      }
      postUserSkillsChanged({})
      toast.success('Attack skill deleted')
    } catch (err) {
      console.error('Failed to delete skill:', err)
      toast.error(toApiError(err, 'Failed to delete skill').message)
    }
  }, [userId, fetchSkills, showConfirm, alertError, toast])

  const release = useCallback(async (skill: UserSkillRow) => {
    if (!userId) return
    const ok = await dangerConfirm(
      `Release "${skill.name}"? Read its text first (Download): a plugin version the catalog revoked proposed it. ` +
      'Once released it can be turned on in your projects again.',
      'Release a quarantined skill',
      { confirmLabel: 'I have read it, release' },
    )
    if (!ok) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skill.id}/release`, { method: 'POST' })
      if (!resp.ok) {
        alertError((await readApiError(resp, 'Failed to release the skill')).message)
        return
      }
      postUserSkillsChanged({})
      toast.success('Skill released; turn it on in a project to use it')
    } catch (err) {
      toast.error(toApiError(err, 'Failed to release the skill').message)
    }
  }, [userId, dangerConfirm, alertError, fetchSkills, toast])

  const openEdit = useCallback((skill: UserSkillRow) => {
    setEditError(null)
    setEditAiError(null)
    setEdit({ id: skill.id, name: skill.name, description: skill.description ?? '' })
  }, [])

  /** Fills only an empty name or description of the skill being edited; Save is still the only write. */
  const generateEdit = useCallback(async () => {
    if (!userId || !edit) return
    const fields = [...(edit.name.trim() ? [] : ['name']), ...(edit.description.trim() ? [] : ['description'])]
    if (!fields.length) return
    const skillId = edit.id
    // Set before the first await: a double click must not start a second run.
    if (editGeneratingRef.current === skillId) return
    editGeneratingRef.current = skillId
    setEditGenerating(skillId)
    setEditAiError(null)
    const stillOpen = () => editRef.current?.id === skillId
    try {
      const model = await ensureFeatureModel('skill_metadata')
      if (!model) return
      const text = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (!text.ok) {
        const err = await readApiError(text, 'The skill text could not be read')
        if (stillOpen()) setEditAiError(`${formatApiError({ ...err, reason: 'The skill text could not be read' })}.`)
        return
      }
      const { content } = await text.json()
      // The name is only context here; one stored before the 100-character limit is cut, or
      // the route refuses the whole request.
      const contextName = tidySkillName(edit.name).value
      const res = await fetchWithFeatureModel('skill_metadata', () => fetch(`/api/users/${userId}/attack-skills/generate-metadata`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items: [{ key: skillId, fileName: '', content, name: contextName, fields }] }),
      }))
      if (!res.ok) {
        const err = await readApiError(res, AI_FAILED_TEXT)
        if (!stillOpen()) return
        const code = readFeatureModelCode(err.body)
        setEditAiError(code ? featureModelMessage(code, model) : err.message)
        return
      }
      const body = await res.json().catch(() => ({}))
      if (!stillOpen()) return
      const item = Array.isArray(body.items) ? body.items[0] : null
      if (item?.error === CREDENTIALS_ERROR) setEditAiError(CREDENTIALS_TEXT)
      else if (!item?.name && !item?.description) setEditAiError(AI_FAILED_TEXT)
      // Read at the moment of filling: a field typed while the model ran is kept.
      setEdit((x) => (x && x.id === skillId ? {
        ...x,
        name: !x.name.trim() && typeof item?.name === 'string' ? item.name : x.name,
        description: !x.description.trim() && typeof item?.description === 'string' ? item.description : x.description,
      } : x))
    } catch (err) {
      console.error('Failed to generate the skill metadata:', err)
      if (stillOpen()) setEditAiError(toApiError(err, AI_FAILED_TEXT).message)
    } finally {
      if (editGeneratingRef.current === skillId) editGeneratingRef.current = null
      setEditGenerating((g) => (g === skillId ? null : g))
    }
  }, [userId, edit, ensureFeatureModel, fetchWithFeatureModel])

  const saveEdit = useCallback(async () => {
    if (!userId || !edit) return
    setEditSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${edit.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: edit.name, description: edit.description.trim() || null }),
      })
      if (resp.ok) {
        setEdit(null)
        postUserSkillsChanged({})
        toast.success('Skill updated')
        return
      }
      const err = await readApiError(resp, 'Failed to update the skill')
      if (err.code === 'name_taken' || err.code === 'name_invalid' || err.code === 'name_too_long') {
        setEditError(err.reason)
      } else {
        alertError(err.message)
      }
    } catch (err) {
      console.error('Failed to update skill:', err)
      toast.error(toApiError(err, 'Failed to update the skill').message)
    } finally {
      setEditSaving(false)
    }
  }, [userId, edit, fetchSkills, toast, alertError])

  const importCommunity = useCallback(async () => {
    if (!userId) return
    setImporting(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/import-community`, { method: 'POST' })
      if (!resp.ok) {
        alertError((await readApiError(resp, 'Failed to import community skills')).message)
        return
      }
      // Skills may have landed even when the answer cannot be read.
      postUserSkillsChanged({})
      const data = await resp.json().catch(() => null)
      if (!data) {
        alertError(`Failed to read the import's answer (invalid_json · HTTP ${resp.status}). Check your skills list.`)
        return
      }
      const update = await offerCommunityUpdates(userId, data, showConfirm)
      if (update) {
        postUserSkillsChanged({})
        if (!update.ok) {
          alertError((await readApiError(update, 'Failed to update community skills')).message)
          return
        }
        showAlert(importSummary(data) + updatedSummary(await update.json().catch(() => null)))
        return
      }
      showAlert(importSummary(data))
    } catch (err) {
      console.error('Failed to import community skills:', err)
      alertError(toApiError(err, 'Failed to import community skills').message)
    } finally {
      setImporting(false)
    }
  }, [userId, fetchSkills, showAlert, alertError, showConfirm])

  const atLimit = skills.length >= MAX_SKILLS_PER_USER
  const upload = useSkillUpload({ userId, existingCount: skills.length })
  const uploadTitle = loading
    ? 'Loading your skills…'
    : loadError !== null ? `${LOAD_FAILED}${loadError}. Reload the page to upload.` : atLimit ? USER_SKILL_LIMIT_TEXT : undefined
  const uploadDisabled = !userId || loading || loadError !== null || atLimit
  const editEmptyField = !!edit && (!edit.name.trim() || !edit.description.trim())

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
          <Swords size={16} /> Agent Skills
          <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills" title="Open Agent Skills wiki page" />
        </h2>
        <div className={own.headerActions}>
          <button className="secondaryButton" onClick={importCommunity} disabled={importing || atLimit}>
            {importing ? <Loader2 size={14} className={styles.spin} /> : <Download size={14} />}
            Import from Community
          </button>
          <button type="button" className="secondaryButton" onClick={upload.openBatch} disabled={uploadDisabled} title={uploadTitle}>
            <Files size={14} /> Upload Batch
          </button>
          <button type="button" className="primaryButton" onClick={upload.openSingle} disabled={uploadDisabled} title={uploadTitle}>
            <Upload size={14} /> Upload Skill
          </button>
        </div>
      </div>
      <p className={styles.sectionHint}>
        Upload .md files defining custom attack skill workflows, one at a time or in a batch. A file can declare
        its name and description in a frontmatter block; the upload dialog fills in what it finds and can write
        the rest with AI. Skills become available as toggles in all project settings.
        {' '}Browse <a href="https://github.com/samugit83/redamon/wiki/Agent-Skills#community-skills" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)', textDecoration: 'underline' }}>community skills</a> for ready-to-use templates.
      </p>

      <div className={own.toolbar}>
        <label className={own.search}>
          <Search size={14} aria-hidden />
          <input
            className="textInput"
            type="search"
            placeholder="Search by name or description"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search your skills"
          />
        </label>
        <span className={own.count} data-testid="skill-count">{skills.length} of {MAX_SKILLS_PER_USER}</span>
      </div>

      {loading ? (
        <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
      ) : skills.length === 0 && loadError !== null ? (
        <div className={styles.emptyState} role="alert">{LOAD_FAILED}{loadError}. Reload the page.</div>
      ) : skills.length === 0 ? (
        <div className={styles.emptyState}>No custom skills uploaded yet. Upload a .md file, or a batch of them, to get started.</div>
      ) : visible.length === 0 ? (
        <div className={styles.emptyState}>No skill matches “{query}”.</div>
      ) : (
        <div className={styles.providerList}>
          {visible.map((skill) => {
            const waiting = skill.pendingChangeSetIds?.length ?? 0
            return (
              <div key={skill.id} className={`${styles.providerCard} ${own.card}`} data-testid={`user-skill-${skill.id}`}>
                <span className={styles.providerIcon}><Swords size={16} /></span>
                <div className={styles.providerInfo}>
                  <div className={`${styles.providerName} ${own.nameRow}`}>
                    <span className={own.name}>{skill.name}</span>
                    {skill.version != null && (
                      <span className={own.badge} title={skill.derivedFromName ? `Saved as a new version of ${skill.derivedFromName}` : undefined}>
                        <GitBranch size={11} aria-hidden /> v{skill.version}{skill.derivedFromName ? ` · from ${skill.derivedFromName}` : ''}
                      </span>
                    )}
                    {waiting > 0 && (
                      <button type="button" className={own.chip} onClick={() => setReviewChangeSetId(skill.pendingChangeSetIds![0])}>
                        <Inbox size={11} aria-hidden /> {waiting} proposal{waiting === 1 ? '' : 's'}
                      </button>
                    )}
                    {skill.duplicateName && (
                      <span className={own.warn}><AlertTriangle size={11} aria-hidden /> Same name as another skill — rename one</span>
                    )}
                  </div>
                  <div className={styles.providerMeta}>
                    {skill.description || <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>}
                  </div>
                  <div className={styles.providerMeta}>
                    Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                  </div>
                  {skill.quarantinedAt && (
                    <div className={own.quarantine} role="status">
                      <ShieldOff size={14} aria-hidden />
                      <div>
                        <strong>Quarantined.</strong>{' '}
                        {QUARANTINE_TEXT[skill.quarantineReason ?? ''] ?? 'It was turned off in every project.'}
                        {' '}Read it before you release it.
                        <div className={own.quarantineActions}>
                          <button type="button" className="secondaryButton" onClick={() => download(skill)}><Download size={13} /> Read (download)</button>
                          <button type="button" className="secondaryButton" onClick={() => release(skill)}>Release</button>
                          <button type="button" className="secondaryButton" onClick={() => remove(skill)}><Trash2 size={13} /> Delete</button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                <div className={styles.providerActions}>
                  <button className="iconButton" title="Edit name and description" onClick={() => openEdit(skill)}>
                    <Pencil size={14} />
                  </button>
                  <button className="iconButton" title="Download" onClick={() => download(skill)}>
                    <Download size={14} />
                  </button>
                  <button className="iconButton" title="Delete" onClick={() => remove(skill)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      <Modal
        isOpen={!!edit}
        onClose={() => setEdit(null)}
        title="Edit Skill"
        size="default"
        footer={
          <>
            <button className="secondaryButton" onClick={() => setEdit(null)}>Cancel</button>
            <button
              className="primaryButton"
              disabled={editSaving || !edit?.name.trim() || editCheck.state === 'taken' || editCheck.state === 'invalid'}
              onClick={saveEdit}
            >
              {editSaving ? <Loader2 size={14} className={styles.spin} /> : <Pencil size={14} />}
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel" htmlFor="skill-edit-name">Name</label>
          <input
            id="skill-edit-name"
            className="textInput"
            type="text"
            value={edit?.name ?? ''}
            onChange={(e) => { setEditError(null); setEdit((x) => (x ? { ...x, name: e.target.value } : x)) }}
            maxLength={NAME_MAX_CHARS}
            autoFocus
          />
          <span className="formHint" role={editError || nameCheckMessage(editCheck) ? 'alert' : undefined}>
            {editError || nameCheckMessage(editCheck) || 'Names are unique among your skills, ignoring case and spacing.'}
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel" htmlFor="skill-edit-description">Description</label>
          <textarea
            id="skill-edit-description"
            className="textInput"
            rows={3}
            value={edit?.description ?? ''}
            onChange={(e) => setEdit((x) => (x ? { ...x, description: e.target.value } : x))}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={DESCRIPTION_MAX_CHARS}
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead - a good description improves classification accuracy.
          </span>
        </div>
        <div className={own.generate}>
          <button
            type="button"
            className="secondaryButton aiGenerateButton"
            onClick={() => void generateEdit()}
            disabled={!editEmptyField || editSaving || editGenerating === edit?.id}
            title={editEmptyField ? 'Write the empty name or description with AI' : 'The name and description are both filled'}
          >
            {editGenerating === edit?.id ? <Loader2 size={14} className={styles.spin} /> : <Sparkles size={14} />}
            Generate with AI
          </button>
          <FeatureModelLine featureId="skill_metadata" />
        </div>
        {editAiError && <span className="formHint" role="alert">{editAiError}</span>}
      </Modal>

      {upload.dialogs}

      {reviewChangeSetId && userId && (
        <OverrideReviewModal
          changeSetId={reviewChangeSetId}
          scopeOwnerId={userId}
          onClose={() => { setReviewChangeSetId(null); fetchSkills() }}
          onDecided={() => { setReviewChangeSetId(null); fetchSkills() }}
        />
      )}
    </div>
  )
}

/** The community import's answer, with each reason a skill was skipped said apart. */
/** What the second call of an update said, appended to the import's summary. */
export function updatedSummary(answer: unknown): string {
  const n = answer && typeof answer === 'object' ? (answer as { updated?: unknown }).updated : undefined
  return typeof n === 'number' ? ` Updated ${n} to the catalog's version.` : ' The update\'s answer could not be read: check your skills list.'
}

export function importSummary(data: {
  imported?: number
  skippedBy?: Partial<Record<'duplicate' | 'outdated' | 'limit' | 'fetchFailed' | 'tooLarge' | 'invalid' | 'saveFailed', number>>
  skipped?: number
  message?: string
}): string {
  if (data.message) return data.message
  const by = data.skippedBy ?? {}
  const parts = [
    by.duplicate ? `${by.duplicate} already in your skills` : '',
    by.outdated ? `${by.outdated} older than the catalog's version (kept as you have them)` : '',
    by.limit ? `${by.limit} over your ${MAX_SKILLS_PER_USER}-skill limit` : '',
    by.tooLarge ? `${by.tooLarge} too large` : '',
    by.fetchFailed ? `${by.fetchFailed} could not be fetched` : '',
    by.invalid ? `${by.invalid} not valid` : '',
    by.saveFailed ? `${by.saveFailed} could not be saved` : '',
  ].filter(Boolean)
  return `Imported ${data.imported ?? 0} community skill(s)` + (parts.length ? `; skipped ${parts.join(', ')}.` : '.')
}
