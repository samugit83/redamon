'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { ChevronDown, Plus, Search, Trash2, AlertTriangle, List, X, Check } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { numericDefault } from '../formDefaults'
import Link from 'next/link'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys, type CredentialKeysApi } from '@/hooks/useCredentialKeys'
import { SCAN_TARGET_FOLDERS } from '@/lib/trufflehogSources'
import { copyText } from '@/lib/copyText'
import { readApiError, toApiError } from '@/lib/apiError'
import {
  TRUFFLEHOG_DETECTOR_COUNT,
  filterDetectors,
  parseDetectorList,
  unknownDetectors,
} from '@/lib/trufflehogDetectors'
import {
  TRUFFLEHOG_SOURCES,
  TRUFFLEHOG_SOURCE_IDS,
  type TrufflehogField,
  validateTrufflehogConfig,
} from '@/lib/trufflehogSources'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TrufflehogProfile {
  id: string
  source: string
  label: string
  config: Record<string, unknown>
  validationErrors?: string[]
  missingCredentials?: { settingsKey: string; label: string }[]
}

interface TrufflehogSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  /** Profiles are per-project rows, so they can only be managed once the project
   *  exists. In create mode the section shows the shared options only. */
  projectId?: string | null
  mode?: 'create' | 'edit'
  /** Update Settings / Start to Scan for this scan, rendered in the header. */
  actions?: React.ReactNode
}

const RESULT_TYPES = [
  { value: 'verified', label: 'Verified (confirmed live)' },
  { value: 'unverified', label: 'Unverified (detected, not confirmed)' },
  { value: 'unknown', label: 'Unknown (the verify call failed)' },
  { value: 'filtered_unverified', label: 'Filtered unverified' },
]

// `min`/`max` on a number input only bind the steppers and native validation;
// typed digits sail straight past them, so the bound is enforced here too.
const CONCURRENCY_MIN = 1
const CONCURRENCY_MAX = 32
const clampConcurrency = (n: number) =>
  Math.min(CONCURRENCY_MAX, Math.max(CONCURRENCY_MIN, Math.trunc(n)))

const get = (data: FormData, key: string) => (data as unknown as Record<string, unknown>)[key]
const setField = (
  updateField: TrufflehogSectionProps['updateField'],
  key: string,
  value: unknown,
) => updateField(key as keyof FormData, value as FormData[keyof FormData])

export function TrufflehogSection({ data, updateField, projectId, mode = 'edit', actions }: TrufflehogSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [profiles, setProfiles] = useState<TrufflehogProfile[]>([])
  const [addingSource, setAddingSource] = useState('')
  const [error, setError] = useState('')
  // Kept apart from `error`: a failed list must read as a failure, not as "no
  // sources configured", and must not be cleared by the next add or save.
  const [listError, setListError] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  // The raw text of the concurrency box while it is being edited. The stored
  // setting is an Int, so it cannot hold the empty string the user must pass
  // through to replace the current value; without this the field snaps back on
  // every clear and can only be appended to. null = not editing, show the value.
  const [concurrencyText, setConcurrencyText] = useState<string | null>(null)
  const keys = useCredentialKeys()
  const [picker, setPicker] = useState<'include' | 'exclude' | null>(null)

  const canManageProfiles = mode === 'edit' && Boolean(projectId)

  const loadProfiles = useCallback(async () => {
    if (!canManageProfiles) return
    // A failed list must not break the whole project form, only say why.
    try {
      const res = await fetch(`/api/trufflehog/${projectId}/profiles`)
      if (!res.ok) throw await readApiError(res, 'Could not load the sources')
      const body = await res.json()
      setProfiles(body.profiles ?? [])
      setListError('')
    } catch (e) {
      setListError(toApiError(e, 'Could not load the sources').message)
    }
  }, [canManageProfiles, projectId])

  useEffect(() => { void loadProfiles() }, [loadProfiles])

  // Verification is the headline control: it makes RedAmon send found
  // credentials to their owning services to test whether they are live. Default
  // ON (it is TruffleHog's whole value), but the badge has to tell the truth.
  const skipVerification = (get(data, 'trufflehogNoVerification') as boolean) ?? false
  const verifies = !skipVerification

  const resultTypes = String((get(data, 'trufflehogResultTypes') as string) ?? 'verified,unverified,unknown')
    .split(',').map(s => s.trim()).filter(Boolean)

  const includeRaw = (get(data, 'trufflehogIncludeDetectors') as string) ?? ''
  const excludeRaw = (get(data, 'trufflehogExcludeDetectors') as string) ?? ''
  const includeSelected = parseDetectorList(includeRaw)
  const excludeSelected = parseDetectorList(excludeRaw)
  // A name TruffleHog does not know is not ignored: the engine refuses to
  // initialise, so the scan dies at once with an error nobody sees in the UI.
  const unknownInclude = unknownDetectors(includeRaw)
  const unknownExclude = unknownDetectors(excludeRaw)

  const toggleDetector = (name: string) => {
    const field = picker === 'exclude' ? 'trufflehogExcludeDetectors' : 'trufflehogIncludeDetectors'
    const current = picker === 'exclude' ? excludeSelected : includeSelected
    const next = current.includes(name) ? current.filter(d => d !== name) : [...current, name]
    setField(updateField, field, next.join(','))
  }

  const toggleResultType = (value: string) => {
    const next = resultTypes.includes(value)
      ? resultTypes.filter(v => v !== value)
      : [...resultTypes, value]
    setField(updateField, 'trufflehogResultTypes', next.join(','))
  }

  const addProfile = async () => {
    if (!addingSource || !projectId) return
    setError('')
    let body: { profile?: { id?: string } }
    try {
      const res = await fetch(`/api/trufflehog/${projectId}/profiles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: addingSource, config: {} }),
      })
      if (!res.ok) { setError((await readApiError(res, 'Could not add the source')).message); return }
      body = await res.json().catch(() => ({}))
    } catch (e) {
      setError(toApiError(e, 'Could not add the source').message)
      return
    }
    setAddingSource('')
    setExpanded(body.profile?.id ?? null)
    await loadProfiles()
  }

  const saveProfile = async (profile: TrufflehogProfile, config: Record<string, unknown>) => {
    if (!projectId) return
    setError('')
    setProfiles(prev => prev.map(p => (p.id === profile.id ? { ...p, config } : p)))
    let failure = ''
    try {
      const res = await fetch(`/api/trufflehog/${projectId}/profiles/${profile.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config }),
      })
      if (!res.ok) failure = (await readApiError(res, 'Could not save the source')).message
    } catch (e) {
      failure = toApiError(e, 'Could not save the source').message
    }
    if (failure) {
      // The card keeps what was typed (it owns its edits), so the list goes back
      // to what the server holds and the message says the edit is not saved.
      setProfiles(prev => prev.map(p => (p.id === profile.id ? { ...p, config: profile.config } : p)))
      setError(`${failure}. The last change to ${TRUFFLEHOG_SOURCES[profile.source]?.label ?? profile.source} is not saved.`)
    }
  }

  const deleteProfile = async (profile: TrufflehogProfile) => {
    if (!projectId) return
    setError('')
    try {
      const res = await fetch(`/api/trufflehog/${projectId}/profiles/${profile.id}`, { method: 'DELETE' })
      if (!res.ok) setError((await readApiError(res, 'Could not remove the source')).message)
    } catch (e) {
      setError(toApiError(e, 'Could not remove the source').message)
    }
    await loadProfiles()
  }

  const unconfigured = TRUFFLEHOG_SOURCE_IDS.filter(id => !profiles.some(p => p.source === id))

  return (
    // id: scroll target for the Other Scans card's settings link. Keep it in
    // sync with PROJECT_SECTION_ANCHORS in lib/projectSettingsLinks.ts.
    <div className={`${styles.section} ${styles.formSkin}`} id="trufflehog-scanner">
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          Secret Multiscanner
          <WikiInfoButton target="Trufflehog" />
          {/* Dynamic, not a fixed "Passive": with verification on, the scanner
              authenticates to third-party services with credentials it found. */}
          <span className={verifies ? styles.badgeActive : styles.badgePassive}>
            {verifies ? 'Active' : 'Passive'}
          </span>
        </h2>
        {actions}
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Deep secret scanning with 700+ detectors across 14 sources — git hosts, container
            registries, Hugging Face, object storage, CI systems and more. Each configured source
            runs as its own scan, and several can run at the same time.
          </p>

          {/* ---- Per-source profiles. First: the sources ARE the scan, and
                  the options below only modulate them. ---- */}
          <h3 className={styles.subSectionTitle ?? styles.fieldLabel}>Sources</h3>

          {!canManageProfiles ? (
            <p className={styles.sectionRequirement}>
              Save the project first, then add the sources to scan here.
            </p>
          ) : (
            <>
              {error && (
                <div className={`${styles.callout} ${styles.calloutDanger}`} role="alert">
                  <AlertTriangle size={16} />
                  <span>{error}</span>
                </div>
              )}

              {listError && (
                <div className={`${styles.callout} ${styles.calloutDanger}`} role="alert">
                  <AlertTriangle size={16} />
                  <span>{listError}</span>
                </div>
              )}

              {!listError && profiles.length === 0 && (
                <p className={styles.fieldHint}>
                  No sources configured yet. Add one below to make it startable from Other Scans.
                </p>
              )}

              {profiles.map(profile => (
                <ProfileEditor
                  key={profile.id}
                  profile={profile}
                  expanded={expanded === profile.id}
                  onToggle={() => setExpanded(expanded === profile.id ? null : profile.id)}
                  onSave={config => saveProfile(profile, config)}
                  onDelete={() => deleteProfile(profile)}
                  keys={keys}
                />
              ))}

              {unconfigured.length > 0 && (
                <div className={styles.addSourceRow}>
                  <select
                    className="select"
                    value={addingSource}
                    onChange={(e) => setAddingSource(e.target.value)}
                    aria-label="Add a source"
                  >
                    <option value="">Add a source…</option>
                    {unconfigured.map(id => (
                      <option key={id} value={id}>{TRUFFLEHOG_SOURCES[id].label}</option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className={styles.actionButton}
                    onClick={addProfile}
                    disabled={!addingSource}
                  >
                    <Plus size={14} /> Add source
                  </button>
                </div>
              )}
            </>
          )}

          <div className={styles.groupHeader}>
            <h3 className={styles.subSectionTitle ?? styles.fieldLabel}>Shared options</h3>
            <p className={styles.fieldHint}>Applied to every source above.</p>
          </div>

          {/* ---- The verification switch: always visible, never gated behind a
                  configured target. Hiding it is why the control could not be
                  found at all. ---- */}
          <div className={styles.toggleBlock}>
            <div className={styles.toggleBlockHead}>
              <span className={styles.toggleLabel}>Verify secrets against live APIs</span>
              <Toggle
                checked={verifies}
                onChange={(checked) => setField(updateField, 'trufflehogNoVerification', !checked)}
              />
            </div>
            {/* Below the switch, not beside it: this is the one control here
                whose consequence needs reading, and squeezed into the label
                column it wrapped into a wall against the toggle. */}
            <p className={`${styles.toggleDescription} ${styles.toggleDescriptionBelow}`}>
              When on, RedAmon sends found credentials to their owning services to test whether
              they are live. This is the highest-value result in an authorised engagement, but it
              is an ACTIVE behaviour. Use the detector exclude list below to skip services you do
              not want contacted.
            </p>
          </div>

          {/* Result types and Concurrency share a row: both are small, and the
              detector lists below need the full width for pasted names. */}
          <div className={styles.optionRow}>
            <div className={styles.fieldGroup} style={{ flex: 1, minWidth: 0 }}>
              <label className={styles.fieldLabel}>Result types</label>
              <div className={styles.checkboxGroup}>
                {RESULT_TYPES.map(rt => (
                  <label
                    key={rt.value}
                    className={`checkboxLabel ${verifies ? '' : styles.checkboxLabelOff}`}
                  >
                    <input
                      type="checkbox"
                      className="checkbox"
                      checked={resultTypes.includes(rt.value)}
                      disabled={!verifies}
                      onChange={() => toggleResultType(rt.value)}
                    />
                    {rt.label}
                  </label>
                ))}
              </div>
              <span className={styles.fieldHint}>
                {verifies
                  ? 'Which statuses to report. Orthogonal to the switch above.'
                  : 'Disabled while verification is off — nothing is checked, so every finding is unverified.'}
              </span>
            </div>

            <div className={styles.fieldGroup} style={{ width: '110px', flexShrink: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-concurrency">Concurrency</label>
              <input
                id="trufflehog-concurrency"
                type="number"
                className="textInput"
                value={concurrencyText ?? String((get(data, 'trufflehogConcurrency') as number) ?? 8)}
                onChange={(e) => {
                  setConcurrencyText(e.target.value)
                  const n = parseInt(e.target.value, 10)
                  // An empty or half-typed box keeps the last valid number stored,
                  // so leaving the form mid-edit can never save a NaN.
                  if (Number.isFinite(n)) {
                    setField(updateField, 'trufflehogConcurrency', clampConcurrency(n))
                  }
                }}
                onBlur={() => setConcurrencyText(null)}
                min={CONCURRENCY_MIN}
                max={CONCURRENCY_MAX}
              />
              <span className={styles.fieldHint}>{CONCURRENCY_MIN}-{CONCURRENCY_MAX}</span>
            </div>
          </div>

          <div className={styles.optionRow}>
            <div className={styles.fieldGroup} style={{ flex: 1, minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-include-detectors">
                Include detectors
              </label>
              <input
                id="trufflehog-include-detectors"
                type="text"
                className="textInput"
                value={includeRaw}
                onChange={(e) => setField(updateField, 'trufflehogIncludeDetectors', e.target.value)}
                placeholder="AWS,Github,Slack"
              />
              <div className={styles.detectorHintRow}>
                <span className={styles.fieldHint}>Comma-separated. Leave empty for all.</span>
                <button
                  type="button"
                  className={styles.browseButton}
                  onClick={() => setPicker(picker === 'include' ? null : 'include')}
                  aria-expanded={picker === 'include'}
                >
                  <List size={12} /> Browse all {TRUFFLEHOG_DETECTOR_COUNT}
                </button>
              </div>
              {unknownInclude.length > 0 && (
                <span className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
                  Secret Multiscanner does not know {unknownInclude.join(', ')} and refuses to start. Check the
                  spelling in the list; names are case-sensitive.
                </span>
              )}
            </div>

            <div className={styles.fieldGroup} style={{ flex: 1, minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-exclude-detectors">
                Exclude detectors
              </label>
              <input
                id="trufflehog-exclude-detectors"
                type="text"
                className="textInput"
                value={excludeRaw}
                onChange={(e) => setField(updateField, 'trufflehogExcludeDetectors', e.target.value)}
                placeholder="DetectorName1,DetectorName2"
              />
              <div className={styles.detectorHintRow}>
                <span className={styles.fieldHint}>
                  Takes precedence over include. An excluded detector is never contacted.
                </span>
                <button
                  type="button"
                  className={styles.browseButton}
                  onClick={() => setPicker(picker === 'exclude' ? null : 'exclude')}
                  aria-expanded={picker === 'exclude'}
                >
                  <List size={12} /> Browse all {TRUFFLEHOG_DETECTOR_COUNT}
                </button>
              </div>
              {unknownExclude.length > 0 && (
                <span className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
                  Secret Multiscanner does not know {unknownExclude.join(', ')} and refuses to start. Check the
                  spelling in the list; names are case-sensitive.
                </span>
              )}
            </div>
          </div>

          {picker && (
            <DetectorPicker
              target={picker}
              selected={picker === 'include' ? includeSelected : excludeSelected}
              onToggle={toggleDetector}
              onClose={() => setPicker(null)}
            />
          )}

          {/* ---- The rest of the shared options ----------------------------------
                  These are project-level TruffleHog settings that have always
                  been writable over the API and had no input anywhere: the
                  per-source targets moved to the scan-profile rows above, and
                  the shared ones stayed on Project and were forgotten. They
                  stack rather than scroll, so they stay usable at phone width. */}
          <div className={styles.toggleBlock}>
            <div className={styles.toggleBlockHead}>
              <span className={styles.toggleLabel}>Run the secret multiscanner</span>
              <Toggle
                checked={Boolean(get(data, 'trufflehogEnabled'))}
                onChange={(checked) => setField(updateField, 'trufflehogEnabled', checked)}
              />
            </div>
            <p className={`${styles.toggleDescription} ${styles.toggleDescriptionBelow}`}>
              Off, the profiles above are kept and nothing runs.
            </p>
          </div>

          <div className={styles.optionRow}>
            <div className={styles.fieldGroup} style={{ flex: '1 1 240px', minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-archive-depth">
                Archive depth
              </label>
              <input
                id="trufflehog-archive-depth"
                type="number"
                className="textInput"
                min={0}
                max={50}
                value={Number(get(data, 'trufflehogArchiveMaxDepth') ?? 0)}
                onChange={(e) => setField(
                  updateField, 'trufflehogArchiveMaxDepth', parseInt(e.target.value) || 0
                )}
              />
              <span className={styles.fieldHint}>
                How many nested archives to open. 0 opens none.
              </span>
            </div>
            <div className={styles.fieldGroup} style={{ flex: '1 1 240px', minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-decode-depth">
                Decode depth
              </label>
              <input
                id="trufflehog-decode-depth"
                type="number"
                className="textInput"
                min={0}
                max={50}
                value={Number(get(data, 'trufflehogMaxDecodeDepth') ?? 5)}
                onChange={(e) => {
                  // Not `||`: a typed 0 is a real depth (decode nothing).
                  const n = parseInt(e.target.value, 10)
                  setField(
                    updateField, 'trufflehogMaxDecodeDepth',
                    Number.isNaN(n) ? numericDefault('trufflehogMaxDecodeDepth') : n
                  )
                }}
              />
              <span className={styles.fieldHint}>
                How many layers of base64 and friends to unwrap.
              </span>
            </div>
          </div>

          <div className={styles.optionRow}>
            <div className={styles.fieldGroup} style={{ flex: '1 1 240px', minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-archive-size">
                Archive max size
              </label>
              <input
                id="trufflehog-archive-size"
                type="text"
                className="textInput"
                value={String(get(data, 'trufflehogArchiveMaxSize') ?? '')}
                onChange={(e) => setField(updateField, 'trufflehogArchiveMaxSize', e.target.value)}
                placeholder="e.g. 250MB"
              />
              <span className={styles.fieldHint}>Empty uses the tool&apos;s own default.</span>
            </div>
            <div className={styles.fieldGroup} style={{ flex: '1 1 240px', minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-archive-timeout">
                Archive timeout
              </label>
              <input
                id="trufflehog-archive-timeout"
                type="text"
                className="textInput"
                value={String(get(data, 'trufflehogArchiveTimeout') ?? '')}
                onChange={(e) => setField(updateField, 'trufflehogArchiveTimeout', e.target.value)}
                placeholder="e.g. 30s"
              />
              <span className={styles.fieldHint}>Empty uses the tool&apos;s own default.</span>
            </div>
          </div>

          <div className={styles.optionRow}>
            <div className={styles.fieldGroup} style={{ flex: '1 1 240px', minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-detector-timeout">
                Detector timeout
              </label>
              <input
                id="trufflehog-detector-timeout"
                type="text"
                className="textInput"
                value={String(get(data, 'trufflehogDetectorTimeout') ?? '')}
                onChange={(e) => setField(updateField, 'trufflehogDetectorTimeout', e.target.value)}
                placeholder="e.g. 10s"
              />
              <span className={styles.fieldHint}>
                How long one detector may spend verifying a candidate.
              </span>
            </div>
            <div className={styles.fieldGroup} style={{ flex: '1 1 240px', minWidth: 0 }}>
              <label className={styles.fieldLabel} htmlFor="trufflehog-filter-entropy">
                Entropy filter
              </label>
              <input
                id="trufflehog-filter-entropy"
                type="text"
                className="textInput"
                value={String(get(data, 'trufflehogFilterEntropy') ?? '')}
                onChange={(e) => setField(updateField, 'trufflehogFilterEntropy', e.target.value)}
                placeholder="e.g. 3.0"
              />
              <span className={styles.fieldHint}>
                Drop candidates below this Shannon entropy. Empty keeps them all.
              </span>
            </div>
          </div>

          <div className={styles.toggleBlock}>
            <div className={styles.toggleBlockHead}>
              <span className={styles.toggleLabel}>Skip archives</span>
              <Toggle
                checked={Boolean(get(data, 'trufflehogForceSkipArchives'))}
                onChange={(checked) => setField(updateField, 'trufflehogForceSkipArchives', checked)}
              />
            </div>
          </div>
          <div className={styles.toggleBlock}>
            <div className={styles.toggleBlockHead}>
              <span className={styles.toggleLabel}>Skip binaries</span>
              <Toggle
                checked={Boolean(get(data, 'trufflehogForceSkipBinaries'))}
                onChange={(checked) => setField(updateField, 'trufflehogForceSkipBinaries', checked)}
              />
            </div>
          </div>
          <div className={styles.toggleBlock}>
            <div className={styles.toggleBlockHead}>
              <span className={styles.toggleLabel}>Drop unverified JWTs</span>
              <Toggle
                checked={Boolean(get(data, 'trufflehogDropUnverifiedJwt'))}
                onChange={(checked) => setField(updateField, 'trufflehogDropUnverifiedJwt', checked)}
              />
            </div>
            <p className={`${styles.toggleDescription} ${styles.toggleDescriptionBelow}`}>
              A JWT nobody could verify is usually an expired token in a test fixture.
            </p>
          </div>
          <div className={styles.toggleBlock}>
            <div className={styles.toggleBlockHead}>
              <span className={styles.toggleLabel}>Allow overlapping verification</span>
              <Toggle
                checked={Boolean(get(data, 'trufflehogAllowVerificationOverlap'))}
                onChange={(checked) => setField(
                  updateField, 'trufflehogAllowVerificationOverlap', checked
                )}
              />
            </div>
            <p className={`${styles.toggleDescription} ${styles.toggleDescriptionBelow}`}>
              Let more than one detector verify the same candidate. Louder, and occasionally the
              only way a shared-format key is attributed to the right service.
            </p>
          </div>

        </div>
      )}
    </div>
  )
}

/**
 * The full detector catalogue, scrollable and filterable.
 *
 * It exists because the two detector fields are free text whose only valid
 * values are 1060 exact, case-sensitive names that appear nowhere in the UI: an
 * operator had to guess, and a guess makes TruffleHog refuse to start. Clicking
 * a name writes it into the field, so the names never have to be typed at all.
 */
function DetectorPicker({
  target, selected, onToggle, onClose,
}: {
  target: 'include' | 'exclude'
  selected: string[]
  onToggle: (name: string) => void
  onClose: () => void
}) {
  const [query, setQuery] = useState('')
  const [copied, setCopied] = useState(false)
  const shown = filterDetectors(query)
  const selectedSet = new Set(selected)

  const copyAll = async () => {
    try {
      await copyText(shown.join(','))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // copyText already falls back for plain http, so this only fires when no
      // copy path works; the names are selectable text either way, so a failure
      // needs no error of its own.
    }
  }

  return (
    <div className={styles.detectorPicker}>
      <div className={styles.detectorPickerHead}>
        <strong className={styles.detectorPickerTitle}>
          Detectors to {target}
        </strong>
        <input
          type="text"
          className="textInput"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Filter, e.g. aws"
          style={{ flex: 1, minWidth: '120px' }}
          aria-label="Filter detectors"
        />
        <span className={styles.fieldHint} style={{ whiteSpace: 'nowrap' }}>
          {shown.length} of {TRUFFLEHOG_DETECTOR_COUNT}
        </span>
        <button type="button" className={styles.browseButton} onClick={copyAll}>
          {copied ? <Check size={12} /> : null} {copied ? 'Copied' : 'Copy shown'}
        </button>
        <button
          type="button"
          className={styles.browseButton}
          onClick={onClose}
          aria-label="Close the detector list"
        >
          <X size={12} />
        </button>
      </div>

      <div className={styles.detectorGrid}>
        {shown.map(name => {
          const on = selectedSet.has(name)
          return (
            <button
              key={name}
              type="button"
              className={`${styles.detectorChip} ${on ? styles.detectorChipOn : ''}`}
              onClick={() => onToggle(name)}
              title={on ? `Remove ${name}` : `Add ${name}`}
            >
              {name}
            </button>
          )
        })}
        {shown.length === 0 && (
          <span className={styles.fieldHint}>No detector matches that filter.</span>
        )}
      </div>

      <span className={styles.fieldHint}>
        Click a name to add or remove it. Names are case-sensitive, exactly as shown.
      </span>
    </div>
  )
}

function ProfileEditor({
  profile, expanded, onToggle, onSave, onDelete, keys,
}: {
  profile: TrufflehogProfile
  expanded: boolean
  onToggle: () => void
  onSave: (config: Record<string, unknown>) => void
  onDelete: () => void
  keys: CredentialKeysApi
}) {
  const src = TRUFFLEHOG_SOURCES[profile.source]
  const [config, setConfig] = useState<Record<string, unknown>>(profile.config ?? {})

  // Keyed on the profile IDENTITY, not on `profile.config`.
  //
  // The card owns the operator's in-progress edits, and the parent already
  // mirrors every save back into its own list, so there is nothing to pull in
  // while the same profile stays open. Reacting to `profile.config` instead
  // meant a `loadProfiles()` response that had been issued BEFORE an edit could
  // land after it, carrying the config as the server knew it a moment earlier,
  // and silently revert the field just typed. The next edit then merged onto
  // that reverted object and the earlier field never reached the PATCH at all.
  // Confirmed from a network trace: two edits produced
  // `{"groupIds":[...]}` then `{"excludeRepos":[...]}`, losing the target.
  // On gitlab that is invisible, because a profile with no target is still
  // valid and means "scan every project this token can reach".
  useEffect(() => { setConfig(profile.config ?? {}) }, [profile.id])

  if (!src) return null

  const errors = validateTrufflehogConfig(profile.source, config)
  const localFolder = (SCAN_TARGET_FOLDERS as Record<string, string>)[profile.source]
  // The server computed this when the profiles were listed, so it still names a
  // key that has since been set from the shortcut below. Re-filter against live
  // state or the card keeps saying "missing" until the whole form reloads.
  const missing = (profile.missingCredentials ?? []).filter(m => !keys.isSet(m.settingsKey))
  const sweepMode = String(config.mode ?? 'assets') === 'sweep'

  const update = (key: string, value: unknown) => {
    const next = { ...config, [key]: value }
    setConfig(next)
    onSave(next)
  }

  const isDisabled = (field: TrufflehogField) => {
    if (!field.requires) return false
    // 'sweep' names the Hugging Face mode; anything else names another field
    // that must be non-empty (the org-only GitHub options).
    if (field.requires === 'sweep') return !sweepMode
    const other = config[field.requires]
    return !(Array.isArray(other) ? other.length : String(other ?? '').length)
  }

  return (
    // The id is the only stable handle on one source's card. Several sources
    // share a field label ('Endpoint', 'Include paths', ...), so a selector
    // scoped to the whole section resolves to two inputs the moment a project
    // holds more than one profile, which is the normal state, not an edge case.
    <div id={`trufflehog-source-${src.id}`} className={styles.subSection}>
      <div className={styles.sourceCardHead} onClick={onToggle}>
        <div className={styles.sourceCardHeading}>
          <strong className={styles.sourceCardTitle}>{src.label}</strong>
          {errors.length > 0 && (
            <span className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
              needs configuration
            </span>
          )}
          {missing.length > 0 && (
            <span className={styles.inlineError}>
              missing {missing.map(m => m.label).join(', ')}
            </span>
          )}
        </div>
        <button
          type="button"
          className={styles.removeButton}
          onClick={(e) => { e.stopPropagation(); onDelete() }}
          aria-label={`Remove the ${src.label} source`}
        >
          <Trash2 size={14} />
        </button>
      </div>

      {expanded && (
        <div className={styles.sourceCardBody}>
          <p className={styles.fieldHint}>{src.description}</p>

          {/* The one thing an operator cannot discover from the fields: WHICH
              folder on the host these local targets are read from. */}
          {localFolder && (
            <p className={styles.localTargetNote}>
              Local target, no network needed. Put the files in{' '}
              <code>{localFolder}</code> on the machine running RedAmon, then name
              them below. The folder is mounted read-only into the scan; a name
              with a slash or <code>..</code> in it is refused.
            </p>
          )}

          {missing.length > 0 && (
            <p className={styles.sectionRequirement}>
              {src.label} requires {missing.map(m => m.label).join(', ')}. Set it below, or in{' '}
              <Link href={`${SETTINGS_KEYS_HREF}#trufflehog-keys`}>
                Global Settings &gt; API Keys &gt; Secret Multiscanner
              </Link>
              . Until then this source cannot start.
            </p>
          )}

          {/* Every credential the source declares, mandatory and optional alike,
              so a key can be replaced here and not only supplied. They are USER
              settings shared by every project, which each card's badge says. */}
          {src.credentials.length > 0 && (
            <div className={styles.credentialStack}>
              {src.credentials.map(cred => (
                <CredentialShortcut
                  key={cred.settingsKey}
                  settingsKey={cred.settingsKey}
                  keys={keys}
                  optional={cred.optional}
                  compact
                />
              ))}
            </div>
          )}

          <div className={styles.sourceFieldGrid}>
            {src.fields.map(field => (
              <FieldInput
                key={field.key}
                field={field}
                value={config[field.key]}
                disabled={isDisabled(field)}
                onChange={value => update(field.key, value)}
              />
            ))}
          </div>

          {errors.map(e => (
            <p key={e} className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>{e}</p>
          ))}
        </div>
      )}
    </div>
  )
}

/** Renders one registry field. The control follows `field.type`, which is the
 *  same value the Python side uses to build argv — so what the operator types
 *  and what TruffleHog receives cannot diverge in shape. */
function FieldInput({
  field, value, disabled, onChange,
}: {
  field: TrufflehogField
  value: unknown
  disabled: boolean
  onChange: (value: unknown) => void
}) {
  // Without this the label is a bare sibling of its control: unreachable for a
  // screen reader, and for anything that addresses a field by its name.
  const inputId = useId()
  const asText = String(value ?? '')
  const asCsv = Array.isArray(value) ? value.join(', ') : asText

  if (field.type === 'toggle') {
    return (
      <div className={styles.toggleRow} style={{ opacity: disabled ? 0.5 : 1 }}>
        <div>
          <span className={styles.toggleLabel}>{field.label}</span>
          {field.hint && <p className={styles.toggleDescription}>{field.hint}</p>}
        </div>
        {/* The label is a sibling span, not a <label>, so without this the
            switch has no accessible name: a screen reader announces "switch,
            off" for every one of the 23 toggles across the 14 sources. */}
        <Toggle
          checked={Boolean(value)}
          onChange={onChange}
          disabled={disabled}
          aria-label={field.label}
        />
      </div>
    )
  }

  return (
    <div className={styles.fieldGroup} style={{ opacity: disabled ? 0.5 : 1 }}>
      <label className={styles.fieldLabel} htmlFor={inputId}>
        {field.label}{field.required ? ' *' : ''}
      </label>

      {field.type === 'select' ? (
        <select
          id={inputId}
          className="select"
          value={asText}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">Select…</option>
          {(field.options ?? []).map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      ) : field.type === 'pathfile' || field.type === 'textarea' ? (
        <textarea
          id={inputId}
          className="textarea"
          rows={3}
          value={asText}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : field.type === 'number' ? (
        <input
          id={inputId}
          type="number"
          className="textInput"
          value={asText}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === '' ? '' : Number(e.target.value))}
        />
      ) : (
        <input
          id={inputId}
          type="text"
          className="textInput"
          value={asCsv}
          disabled={disabled}
          // multi/csv fields are typed comma-separated and stored as a list, so
          // the registry's `multi` type reaches Python as repeated flags.
          onChange={(e) => onChange(
            field.type === 'multi'
              ? e.target.value.split(',').map(s => s.trim()).filter(Boolean)
              : e.target.value,
          )}
        />
      )}

      {field.hint && <span className={styles.fieldHint}>{field.hint}</span>}
    </div>
  )
}
