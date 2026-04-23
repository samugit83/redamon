'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'next/navigation'
import { Plus, Pencil, Trash2, Loader2, Eye, EyeOff, Upload, Download, Swords, RotateCw, Copy, Check, ExternalLink, ChevronDown, ChevronRight, Info, BookOpen } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useVersionCheck } from '@/hooks/useVersionCheck'
import { LlmProviderForm } from '@/components/settings/LlmProviderForm'
import type { ProviderData } from '@/components/settings/LlmProviderForm'
import { PROVIDER_TYPES } from '@/lib/llmProviderPresets'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import styles from '@/components/settings/Settings.module.css'
import { buildTemplate, templateToJson, validateAndParse, isValidationError } from '@/lib/apiKeysTemplate'
import type { ParsedImport } from '@/lib/apiKeysTemplate'

interface UserSettings {
  githubAccessToken: string
  tavilyApiKey: string
  shodanApiKey: string
  serpApiKey: string
  nvdApiKey: string
  vulnersApiKey: string
  urlscanApiKey: string
  censysApiToken: string
  censysOrgId: string
  fofaApiKey: string
  otxApiKey: string
  netlasApiKey: string
  virusTotalApiKey: string
  zoomEyeApiKey: string
  criminalIpApiKey: string
  quakeApiKey: string
  hunterApiKey: string
  publicWwwApiKey: string
  hunterHowApiKey: string
  googleApiKey: string
  googleApiCx: string
  onypheApiKey: string
  driftnetApiKey: string
  wpscanApiToken: string
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
}

const EMPTY_SETTINGS: UserSettings = {
  githubAccessToken: '',
  tavilyApiKey: '',
  shodanApiKey: '',
  serpApiKey: '',
  nvdApiKey: '',
  vulnersApiKey: '',
  urlscanApiKey: '',
  censysApiToken: '',
  censysOrgId: '',
  fofaApiKey: '',
  otxApiKey: '',
  netlasApiKey: '',
  virusTotalApiKey: '',
  zoomEyeApiKey: '',
  criminalIpApiKey: '',
  quakeApiKey: '',
  hunterApiKey: '',
  publicWwwApiKey: '',
  hunterHowApiKey: '',
  googleApiKey: '',
  googleApiCx: '',
  onypheApiKey: '',
  driftnetApiKey: '',
  wpscanApiToken: '',
  ngrokAuthtoken: '',
  chiselServerUrl: '',
  chiselAuth: '',
}

interface RotationInfo {
  extraKeyCount: number
  rotateEveryN: number
}

/** Maps settings field name → rotation tool name */
const TOOL_NAME_MAP: Record<string, string> = {
  tavilyApiKey: 'tavily',
  shodanApiKey: 'shodan',
  serpApiKey: 'serp',
  nvdApiKey: 'nvd',
  vulnersApiKey: 'vulners',
  urlscanApiKey: 'urlscan',
  fofaApiKey: 'fofa',
  otxApiKey: 'otx',
  netlasApiKey: 'netlas',
  virusTotalApiKey: 'virustotal',
  zoomEyeApiKey: 'zoomeye',
  criminalIpApiKey: 'criminalip',
  quakeApiKey: 'quake',
  hunterApiKey: 'hunter',
  publicWwwApiKey: 'publicwww',
  hunterHowApiKey: 'hunterhow',
  onypheApiKey: 'onyphe',
  driftnetApiKey: 'driftnet',
  wpscanApiToken: 'wpscan',
}

function getProviderIcon(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.icon || '⚙️'
}

function getProviderLabel(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.name || providerType
}

export default function SettingsPage() {
  const { userId } = useProject()
  const { alertError, alert: showAlert, confirm: showConfirm } = useAlertModal()
  const toast = useToast()

  // LLM Providers
  const [providers, setProviders] = useState<ProviderData[]>([])
  const [providersLoading, setProvidersLoading] = useState(true)
  const [showProviderForm, setShowProviderForm] = useState(false)
  const [editingProvider, setEditingProvider] = useState<ProviderData | null>(null)

  // User Settings
  const [settings, setSettings] = useState<UserSettings>(EMPTY_SETTINGS)
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsDirty, setSettingsDirty] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [visibleFields, setVisibleFields] = useState<Record<string, boolean>>({})

  // Key Rotation
  const [rotationConfigs, setRotationConfigs] = useState<Record<string, RotationInfo>>({})
  const [rotationModal, setRotationModal] = useState<string | null>(null) // toolName or null
  const [rotationDraft, setRotationDraft] = useState({ extraKeys: '', rotateEveryN: 10 })
  const [rotationDraftDirty, setRotationDraftDirty] = useState(false) // true = user typed new keys

  // API Keys Import
  const [pendingImport, setPendingImport] = useState<ParsedImport | null>(null)
  const importFileRef = useRef<HTMLInputElement>(null)

  // Attack Skills
  const [attackSkills, setAttackSkills] = useState<{ id: string; name: string; description?: string | null; createdAt: string }[]>([])
  const [skillsLoading, setSkillsLoading] = useState(true)
  const [skillNameModal, setSkillNameModal] = useState(false)
  const [pendingSkillContent, setPendingSkillContent] = useState('')
  const [pendingSkillName, setPendingSkillName] = useState('')
  const [pendingSkillDescription, setPendingSkillDescription] = useState('')
  const [skillUploading, setSkillUploading] = useState(false)
  // Edit description modal
  const [editDescModal, setEditDescModal] = useState(false)
  const [editingSkillId, setEditingSkillId] = useState('')
  const [editingSkillDescription, setEditingSkillDescription] = useState('')
  const [editDescSaving, setEditDescSaving] = useState(false)
  // Import from Community (Agent Skills)
  const [importingAgentSkills, setImportingAgentSkills] = useState(false)

  // Chat Skills
  const [chatSkills, setChatSkills] = useState<{ id: string; name: string; description?: string | null; category?: string | null; createdAt: string }[]>([])
  const [chatSkillsLoading, setChatSkillsLoading] = useState(true)
  const [chatSkillNameModal, setChatSkillNameModal] = useState(false)
  const [pendingChatSkillContent, setPendingChatSkillContent] = useState('')
  const [pendingChatSkillName, setPendingChatSkillName] = useState('')
  const [pendingChatSkillDescription, setPendingChatSkillDescription] = useState('')
  const [pendingChatSkillCategory, setPendingChatSkillCategory] = useState('general')
  const [chatSkillUploading, setChatSkillUploading] = useState(false)
  // Chat skill edit description modal
  const [editChatDescModal, setEditChatDescModal] = useState(false)
  const [editingChatSkillId, setEditingChatSkillId] = useState('')
  const [editingChatSkillDescription, setEditingChatSkillDescription] = useState('')
  const [editChatDescSaving, setEditChatDescSaving] = useState(false)
  // Import from Community (Chat Skills)
  const [importingChatSkills, setImportingChatSkills] = useState(false)
  // Fetch attack skills
  const fetchSkills = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`)
      if (resp.ok) setAttackSkills(await resp.json())
    } catch (err) {
      console.error('Failed to fetch attack skills:', err)
    } finally {
      setSkillsLoading(false)
    }
  }, [userId])

  // Upload skill from .md file — read file then open name modal
  const handleSkillUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !userId) return

    const reader = new FileReader()
    reader.onload = () => {
      setPendingSkillContent(reader.result as string)
      setPendingSkillName(file.name.replace(/\.md$/i, ''))
      setSkillNameModal(true)
    }
    reader.readAsText(file)
    e.target.value = '' // Reset input
  }, [userId])

  // Confirm skill upload from modal
  const confirmSkillUpload = useCallback(async () => {
    if (!userId || !pendingSkillName.trim()) return
    setSkillUploading(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: pendingSkillName.trim(), description: pendingSkillDescription.trim() || null, content: pendingSkillContent }),
      })
      if (resp.ok) {
        fetchSkills()
        setSkillNameModal(false)
        setPendingSkillContent('')
        setPendingSkillName('')
        setPendingSkillDescription('')
        toast.success('Attack skill uploaded')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to upload skill')
      }
    } catch (err) {
      console.error('Failed to upload skill:', err)
      toast.error('Failed to upload skill')
    } finally {
      setSkillUploading(false)
    }
  }, [userId, pendingSkillName, pendingSkillDescription, pendingSkillContent, fetchSkills])

  // Download skill as .md
  const downloadSkill = useCallback(async (skillId: string, skillName: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        const blob = new Blob([skill.content], { type: 'text/markdown' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${skillName}.md`
        a.click()
        URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Failed to download skill:', err)
    }
  }, [userId])

  // Delete skill
  const deleteSkill = useCallback(async (skillId: string) => {
    if (!userId || !(await showConfirm('Delete this skill? It will be removed from all projects.'))) return
    try {
      await fetch(`/api/users/${userId}/attack-skills/${skillId}`, { method: 'DELETE' })
      fetchSkills()
      toast.success('Attack skill deleted')
    } catch (err) {
      console.error('Failed to delete skill:', err)
      toast.error('Failed to delete skill')
    }
  }, [userId, fetchSkills])

  // Open edit description modal
  const openEditDescription = useCallback(async (skillId: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        setEditingSkillId(skillId)
        setEditingSkillDescription(skill.description || '')
        setEditDescModal(true)
      }
    } catch (err) {
      console.error('Failed to fetch skill:', err)
    }
  }, [userId])

  // Save edited description
  const saveEditDescription = useCallback(async () => {
    if (!userId || !editingSkillId) return
    setEditDescSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${editingSkillId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: editingSkillDescription.trim() || null }),
      })
      if (resp.ok) {
        fetchSkills()
        setEditDescModal(false)
        setEditingSkillId('')
        setEditingSkillDescription('')
        toast.success('Skill description updated')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to update description')
      }
    } catch (err) {
      console.error('Failed to update skill description:', err)
      toast.error('Failed to update description')
    } finally {
      setEditDescSaving(false)
    }
  }, [userId, editingSkillId, editingSkillDescription, fetchSkills])

  // Import community agent skills
  const importCommunityAgentSkills = useCallback(async () => {
    if (!userId) return
    setImportingAgentSkills(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/import-community`, { method: 'POST' })
      const data = await resp.json()
      if (resp.ok) {
        fetchSkills()
        showAlert(data.message || `Imported ${data.imported ?? 0} community skill(s).`)
      } else {
        alertError(data.error || 'Failed to import community skills')
      }
    } catch (err) {
      console.error('Failed to import community skills:', err)
    } finally {
      setImportingAgentSkills(false)
    }
  }, [userId, fetchSkills])

  // Fetch chat skills
  const fetchChatSkills = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills`)
      if (resp.ok) setChatSkills(await resp.json())
    } catch (err) {
      console.error('Failed to fetch chat skills:', err)
    } finally {
      setChatSkillsLoading(false)
    }
  }, [userId])

  // Upload chat skill from .md file
  const handleChatSkillUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !userId) return
    const reader = new FileReader()
    reader.onload = () => {
      setPendingChatSkillContent(reader.result as string)
      setPendingChatSkillName(file.name.replace(/\.md$/i, ''))
      setPendingChatSkillCategory('general')
      setChatSkillNameModal(true)
    }
    reader.readAsText(file)
    e.target.value = ''
  }, [userId])

  // Confirm chat skill upload
  const confirmChatSkillUpload = useCallback(async () => {
    if (!userId || !pendingChatSkillName.trim()) return
    setChatSkillUploading(true)
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: pendingChatSkillName.trim(),
          description: pendingChatSkillDescription.trim() || null,
          category: pendingChatSkillCategory,
          content: pendingChatSkillContent,
        }),
      })
      if (resp.ok) {
        fetchChatSkills()
        setChatSkillNameModal(false)
        setPendingChatSkillContent('')
        setPendingChatSkillName('')
        setPendingChatSkillDescription('')
        setPendingChatSkillCategory('general')
        toast.success('Chat skill uploaded')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to upload chat skill')
      }
    } catch (err) {
      console.error('Failed to upload chat skill:', err)
      toast.error('Failed to upload chat skill')
    } finally {
      setChatSkillUploading(false)
    }
  }, [userId, pendingChatSkillName, pendingChatSkillDescription, pendingChatSkillCategory, pendingChatSkillContent, fetchChatSkills])

  // Download chat skill as .md
  const downloadChatSkill = useCallback(async (skillId: string, skillName: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        const blob = new Blob([skill.content], { type: 'text/markdown' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${skillName}.md`
        a.click()
        URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Failed to download chat skill:', err)
    }
  }, [userId])

  // Delete chat skill
  const deleteChatSkill = useCallback(async (skillId: string) => {
    if (!userId || !(await showConfirm('Delete this chat skill?'))) return
    try {
      await fetch(`/api/users/${userId}/chat-skills/${skillId}`, { method: 'DELETE' })
      fetchChatSkills()
      toast.success('Chat skill deleted')
    } catch (err) {
      console.error('Failed to delete chat skill:', err)
      toast.error('Failed to delete chat skill')
    }
  }, [userId, fetchChatSkills])

  // Open chat skill edit description modal
  const openEditChatDescription = useCallback(async (skillId: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        setEditingChatSkillId(skillId)
        setEditingChatSkillDescription(skill.description || '')
        setEditChatDescModal(true)
      }
    } catch (err) {
      console.error('Failed to fetch chat skill:', err)
    }
  }, [userId])

  // Save edited chat skill description
  const saveEditChatDescription = useCallback(async () => {
    if (!userId || !editingChatSkillId) return
    setEditChatDescSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/${editingChatSkillId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: editingChatSkillDescription.trim() || null }),
      })
      if (resp.ok) {
        fetchChatSkills()
        setEditChatDescModal(false)
        setEditingChatSkillId('')
        setEditingChatSkillDescription('')
        toast.success('Chat skill description updated')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to update description')
      }
    } catch (err) {
      console.error('Failed to update chat skill description:', err)
      toast.error('Failed to update description')
    } finally {
      setEditChatDescSaving(false)
    }
  }, [userId, editingChatSkillId, editingChatSkillDescription, fetchChatSkills])

  // Import community chat skills
  const importCommunityChatSkills = useCallback(async () => {
    if (!userId) return
    setImportingChatSkills(true)
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/import-community`, { method: 'POST' })
      const data = await resp.json()
      if (resp.ok) {
        fetchChatSkills()
        showAlert(data.message || `Imported ${data.imported ?? 0} community chat skill(s).`)
      } else {
        alertError(data.error || 'Failed to import community chat skills')
      }
    } catch (err) {
      console.error('Failed to import community chat skills:', err)
    } finally {
      setImportingChatSkills(false)
    }
  }, [userId, fetchChatSkills])

  // Fetch providers
  const fetchProviders = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/llm-providers`)
      if (resp.ok) setProviders(await resp.json())
    } catch (err) {
      console.error('Failed to fetch providers:', err)
    } finally {
      setProvidersLoading(false)
    }
  }, [userId])

  // Fetch user settings
  const fetchSettings = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/settings`)
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          githubAccessToken: data.githubAccessToken || '',
          tavilyApiKey: data.tavilyApiKey || '',
          shodanApiKey: data.shodanApiKey || '',
          serpApiKey: data.serpApiKey || '',
          nvdApiKey: data.nvdApiKey || '',
          vulnersApiKey: data.vulnersApiKey || '',
          urlscanApiKey: data.urlscanApiKey || '',
          censysApiToken: data.censysApiToken || '',
          censysOrgId: data.censysOrgId || '',
          fofaApiKey: data.fofaApiKey || '',
          otxApiKey: data.otxApiKey || '',
          netlasApiKey: data.netlasApiKey || '',
          virusTotalApiKey: data.virusTotalApiKey || '',
          zoomEyeApiKey: data.zoomEyeApiKey || '',
          criminalIpApiKey: data.criminalIpApiKey || '',
          quakeApiKey: data.quakeApiKey || '',
          hunterApiKey: data.hunterApiKey || '',
          publicWwwApiKey: data.publicWwwApiKey || '',
          hunterHowApiKey: data.hunterHowApiKey || '',
          googleApiKey: data.googleApiKey || '',
          googleApiCx: data.googleApiCx || '',
          onypheApiKey: data.onypheApiKey || '',
          driftnetApiKey: data.driftnetApiKey || '',
          wpscanApiToken: data.wpscanApiToken || '',
          ngrokAuthtoken: data.ngrokAuthtoken || '',
          chiselServerUrl: data.chiselServerUrl || '',
          chiselAuth: data.chiselAuth || '',
        })
        if (data.rotationConfigs) {
          setRotationConfigs(data.rotationConfigs)
        }
      }
    } catch (err) {
      console.error('Failed to fetch settings:', err)
    } finally {
      setSettingsLoading(false)
    }
  }, [userId])

  useEffect(() => {
    fetchProviders()
    fetchSettings()
    fetchSkills()
    fetchChatSkills()
  }, [fetchProviders, fetchSettings, fetchSkills, fetchChatSkills])

  // Delete provider
  const deleteProvider = useCallback(async (providerId: string) => {
    if (!userId || !(await showConfirm('Delete this provider? Models from it will no longer be available.'))) return
    try {
      await fetch(`/api/users/${userId}/llm-providers/${providerId}`, { method: 'DELETE' })
      fetchProviders()
      toast.success('Provider deleted')
    } catch (err) {
      console.error('Failed to delete provider:', err)
      toast.error('Failed to delete provider')
    }
  }, [userId, fetchProviders])

  // Save user settings
  const saveSettings = useCallback(async () => {
    if (!userId) return
    setSettingsSaving(true)
    try {
      // Build rotation configs payload from pending state
      const rotPayload: Record<string, { extraKeys: string; rotateEveryN: number }> = {}
      for (const [, toolName] of Object.entries(TOOL_NAME_MAP)) {
        const info = rotationConfigs[toolName]
        if (info && (info as RotationInfo & { _extraKeys?: string })._extraKeys !== undefined) {
          // New keys were set via the modal — send them
          rotPayload[toolName] = {
            extraKeys: (info as RotationInfo & { _extraKeys?: string })._extraKeys!,
            rotateEveryN: info.rotateEveryN,
          }
        } else if (info && info.extraKeyCount > 0) {
          // Existing keys not modified — send masked marker to preserve
          rotPayload[toolName] = {
            extraKeys: '••••',
            rotateEveryN: info.rotateEveryN,
          }
        }
      }

      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...settings, rotationConfigs: rotPayload }),
      })
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          githubAccessToken: data.githubAccessToken || '',
          tavilyApiKey: data.tavilyApiKey || '',
          shodanApiKey: data.shodanApiKey || '',
          serpApiKey: data.serpApiKey || '',
          nvdApiKey: data.nvdApiKey || '',
          vulnersApiKey: data.vulnersApiKey || '',
          urlscanApiKey: data.urlscanApiKey || '',
          censysApiToken: data.censysApiToken || '',
          censysOrgId: data.censysOrgId || '',
          fofaApiKey: data.fofaApiKey || '',
          otxApiKey: data.otxApiKey || '',
          netlasApiKey: data.netlasApiKey || '',
          virusTotalApiKey: data.virusTotalApiKey || '',
          zoomEyeApiKey: data.zoomEyeApiKey || '',
          criminalIpApiKey: data.criminalIpApiKey || '',
          quakeApiKey: data.quakeApiKey || '',
          hunterApiKey: data.hunterApiKey || '',
          publicWwwApiKey: data.publicWwwApiKey || '',
          hunterHowApiKey: data.hunterHowApiKey || '',
          googleApiKey: data.googleApiKey || '',
          googleApiCx: data.googleApiCx || '',
          onypheApiKey: data.onypheApiKey || '',
          driftnetApiKey: data.driftnetApiKey || '',
          wpscanApiToken: data.wpscanApiToken || '',
          ngrokAuthtoken: data.ngrokAuthtoken || '',
          chiselServerUrl: data.chiselServerUrl || '',
          chiselAuth: data.chiselAuth || '',
        })
        if (data.rotationConfigs) {
          setRotationConfigs(data.rotationConfigs)
        }
        setSettingsDirty(false)
        toast.success('Settings saved')
      }
    } catch (err) {
      console.error('Failed to save settings:', err)
      toast.error('Failed to save settings')
    } finally {
      setSettingsSaving(false)
    }
  }, [userId, settings, rotationConfigs])

  const updateSetting = useCallback(<K extends keyof UserSettings>(field: K, value: string) => {
    setSettings(prev => ({ ...prev, [field]: value }))
    setSettingsDirty(true)
  }, [])

  const toggleFieldVisibility = useCallback((field: string) => {
    setVisibleFields(prev => ({ ...prev, [field]: !prev[field] }))
  }, [])

  const openRotationModal = useCallback((settingsField: string) => {
    const toolName = TOOL_NAME_MAP[settingsField]
    if (!toolName) return
    const existing = rotationConfigs[toolName]
    setRotationModal(toolName)
    setRotationDraft({
      extraKeys: '',
      rotateEveryN: existing?.rotateEveryN ?? 10,
    })
    setRotationDraftDirty(false)
  }, [rotationConfigs])

  const closeRotationModal = useCallback(() => {
    setRotationModal(null)
    setRotationDraft({ extraKeys: '', rotateEveryN: 10 })
    setRotationDraftDirty(false)
  }, [])

  const saveRotationDraft = useCallback(() => {
    if (!rotationModal) return
    const existing = rotationConfigs[rotationModal]
    if (rotationDraftDirty) {
      // User typed new keys — send them (may be empty to clear)
      const keys = rotationDraft.extraKeys.split('\n').filter(k => k.trim())
      setRotationConfigs(prev => ({
        ...prev,
        [rotationModal]: {
          extraKeyCount: keys.length,
          rotateEveryN: Math.max(1, rotationDraft.rotateEveryN),
          _extraKeys: rotationDraft.extraKeys,
        } as RotationInfo & { _extraKeys: string },
      }))
    } else {
      // Only rotateEveryN changed — preserve existing keys
      setRotationConfigs(prev => ({
        ...prev,
        [rotationModal]: {
          extraKeyCount: existing?.extraKeyCount ?? 0,
          rotateEveryN: Math.max(1, rotationDraft.rotateEveryN),
        },
      }))
    }
    setSettingsDirty(true)
    closeRotationModal()
  }, [rotationModal, rotationDraft, rotationDraftDirty, rotationConfigs, closeRotationModal])

  const clearRotationConfig = useCallback(() => {
    if (!rotationModal) return
    setRotationConfigs(prev => ({
      ...prev,
      [rotationModal]: {
        extraKeyCount: 0,
        rotateEveryN: 10,
        _extraKeys: '',
      } as RotationInfo & { _extraKeys: string },
    }))
    setSettingsDirty(true)
    closeRotationModal()
  }, [rotationModal, closeRotationModal])

  // --- API Keys Import / Export ---------------------------------------------------

  const downloadKeysTemplate = useCallback(() => {
    const keyFields: Record<string, string> = {}
    const tunnelFields: Record<string, string> = {}
    for (const [k, v] of Object.entries(settings)) {
      if (['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'].includes(k)) {
        tunnelFields[k] = v
      } else {
        keyFields[k] = v
      }
    }
    const template = buildTemplate(keyFields, tunnelFields)
    const json = templateToJson(template)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'redamon-api-keys-template.json'
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Template downloaded')
  }, [settings])

  const handleKeysFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (importFileRef.current) importFileRef.current.value = ''
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const raw = reader.result as string
      const result = validateAndParse(raw, file.size)
      if (isValidationError(result)) {
        toast.error(result.message)
        return
      }
      if (result.keyCount === 0 && result.rotationCount === 0 && result.tunnelingCount === 0) {
        toast.error('No keys to import — all values are empty or masked.')
        return
      }
      setPendingImport(result)
    }
    reader.onerror = () => toast.error('Failed to read file.')
    reader.readAsText(file)
  }, [])

  const confirmImport = useCallback(() => {
    if (!pendingImport) return
    setSettings(prev => ({ ...prev, ...pendingImport.keys, ...pendingImport.tunneling }))
    for (const [tool, cfg] of Object.entries(pendingImport.rotation)) {
      setRotationConfigs(prev => ({
        ...prev,
        [tool]: {
          extraKeyCount: cfg.extraKeys.length,
          rotateEveryN: cfg.rotateEveryN,
          _extraKeys: cfg.extraKeys.join('\n'),
        } as RotationInfo & { _extraKeys: string },
      }))
    }
    setSettingsDirty(true)
    setPendingImport(null)
    toast.success('Keys imported — click "Save Settings" to persist.')
  }, [pendingImport])

  const searchParams = useSearchParams()
  const validTabs = ['providers', 'skills', 'chat-skills', 'keys', 'system']
  const initialTab = searchParams.get('tab') || 'providers'
  const [activeTab, setActiveTab] = useState(validTabs.includes(initialTab) ? initialTab : 'providers')

  if (!userId) {
    return (
      <div className={styles.page}>
        <h1 className={styles.pageTitle}>Global Settings <span style={{ fontSize: '0.55em', fontWeight: 400, opacity: 0.5 }}>(User-Scoped)</span></h1>
        <div className={styles.emptyState}>Select a user to configure settings.</div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <h1 className={styles.pageTitle}>Global Settings <span style={{ fontSize: '0.55em', fontWeight: 400, opacity: 0.5 }}>(User-Scoped)</span></h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px', margin: '0 0 var(--space-4)' }}>
        Personal configuration for the current user. These settings apply across all projects.
      </p>

      <div className={styles.tabBar}>
        <button className={`${styles.tab} ${activeTab === 'providers' ? styles.tabActive : ''}`} onClick={() => setActiveTab('providers')}>
          LLM Providers
        </button>
        <button className={`${styles.tab} ${activeTab === 'skills' ? styles.tabActive : ''}`} onClick={() => setActiveTab('skills')}>
          <Swords size={14} /> Agent Skills
        </button>
        <button className={`${styles.tab} ${activeTab === 'chat-skills' ? styles.tabActive : ''}`} onClick={() => setActiveTab('chat-skills')}>
          <BookOpen size={14} /> Chat Skills
        </button>
        <button className={`${styles.tab} ${activeTab === 'keys' ? styles.tabActive : ''}`} onClick={() => setActiveTab('keys')}>
          API Keys & Tunneling
        </button>
        <button className={`${styles.tab} ${activeTab === 'system' ? styles.tabActive : ''}`} onClick={() => setActiveTab('system')}>
          <Info size={14} /> System
        </button>
      </div>

      {/* Tab: LLM Providers */}
      {activeTab === 'providers' && <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>LLM Providers</h2>
          {!showProviderForm && !editingProvider && (
            <button className="primaryButton" onClick={() => setShowProviderForm(true)}>
              <Plus size={14} /> Add Provider
            </button>
          )}
        </div>
        <p className={styles.sectionHint}>
          Models from all providers appear in every project&apos;s LLM selector. Key-based providers auto-discover available models.
        </p>

        {/* Provider form */}
        {(showProviderForm || editingProvider) && (
          <LlmProviderForm
            userId={userId}
            provider={editingProvider}
            onSave={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
              fetchProviders()
            }}
            onCancel={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
            }}
          />
        )}

        {/* Provider list */}
        {!showProviderForm && !editingProvider && (
          providersLoading ? (
            <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
          ) : providers.length === 0 ? (
            <div className={styles.emptyState}>No providers configured. Add one to get started.</div>
          ) : (
            <div className={styles.providerList}>
              {providers.map((p: ProviderData) => (
                <div key={p.id} className={styles.providerCard}>
                  <span className={styles.providerIcon}>{getProviderIcon(p.providerType)}</span>
                  <div className={styles.providerInfo}>
                    <div className={styles.providerName}>{p.name}</div>
                    <div className={styles.providerMeta}>
                      {getProviderLabel(p.providerType)}
                      {p.providerType === 'openai_compatible' && p.modelIdentifier && ` — ${p.modelIdentifier}`}
                    </div>
                  </div>
                  <div className={styles.providerActions}>
                    <button className="iconButton" title="Edit" onClick={() => setEditingProvider(p)}>
                      <Pencil size={14} />
                    </button>
                    <button className="iconButton" title="Delete" onClick={() => deleteProvider(p.id!)}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </div>}

      {/* Tab: Agent Skills */}
      {activeTab === 'skills' && <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}><Swords size={16} /> Agent Skills</h2>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="secondaryButton"
              onClick={importCommunityAgentSkills}
              disabled={importingAgentSkills}
            >
              {importingAgentSkills ? <Loader2 size={14} className={styles.spin} /> : <Download size={14} />}
              Import from Community
            </button>
            <label className="primaryButton" style={{ cursor: 'pointer' }}>
              <Upload size={14} /> Upload Skill
              <input
                type="file"
                accept=".md"
                style={{ display: 'none' }}
                onChange={handleSkillUpload}
              />
            </label>
          </div>
        </div>
        <p className={styles.sectionHint}>
          Upload .md files defining custom attack skill workflows. Skills become available as toggles in all project settings.
          {' '}Browse <a href="https://github.com/samugit83/redamon/wiki/Agent-Skills#community-skills" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)', textDecoration: 'underline' }}>community skills</a> for ready-to-use templates.
        </p>

        {skillsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : attackSkills.length === 0 ? (
          <div className={styles.emptyState}>No custom skills uploaded yet. Upload a .md file to get started.</div>
        ) : (
          <div className={styles.providerList}>
            {attackSkills.map(skill => (
              <div key={skill.id} className={styles.providerCard}>
                <span className={styles.providerIcon}><Swords size={16} /></span>
                <div className={styles.providerInfo}>
                  <div className={styles.providerName}>{skill.name}</div>
                  <div className={styles.providerMeta}>
                    {skill.description || <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>}
                  </div>
                  <div className={styles.providerMeta}>
                    Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div className={styles.providerActions}>
                  <button className="iconButton" title="Edit description" onClick={() => openEditDescription(skill.id)}>
                    <Pencil size={14} />
                  </button>
                  <button className="iconButton" title="Download" onClick={() => downloadSkill(skill.id, skill.name)}>
                    <Download size={14} />
                  </button>
                  <button className="iconButton" title="Delete" onClick={() => deleteSkill(skill.id)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>}

      {/* Tab: Chat Skills */}
      {activeTab === 'chat-skills' && <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}><BookOpen size={16} /> Chat Skills</h2>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="secondaryButton"
              onClick={importCommunityChatSkills}
              disabled={importingChatSkills}
            >
              {importingChatSkills ? <Loader2 size={14} className={styles.spin} /> : <Download size={14} />}
              Import from Community
            </button>
            <label className="primaryButton" style={{ cursor: 'pointer' }}>
              <Upload size={14} /> Upload Skill (.md)
              <input
                type="file"
                accept=".md"
                style={{ display: 'none' }}
                onChange={handleChatSkillUpload}
              />
            </label>
          </div>
        </div>
        <p className={styles.sectionHint}>
          Upload and manage on-demand reference skills for the AI agent chat. Unlike Agent Skills (which drive attack classification and phase-aware workflows), Chat Skills are tactical reference docs that you inject into the agent&apos;s context on the fly using <code>/skill &lt;name&gt;</code> in the chat.
        </p>

        {chatSkillsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : chatSkills.length === 0 ? (
          <div className={styles.emptyState}>No Chat Skills yet. Click Import from Community to add ready-to-use reference skills, or upload your own .md files.</div>
        ) : (
          <div className={styles.providerList}>
            {chatSkills.map(skill => (
              <div key={skill.id} className={styles.providerCard}>
                <span className={styles.providerIcon}><BookOpen size={16} /></span>
                <div className={styles.providerInfo}>
                  <div className={styles.providerName}>
                    {skill.name}
                    {skill.category && (
                      <span style={{
                        marginLeft: '8px',
                        fontSize: '10px',
                        fontWeight: 500,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'var(--bg-tertiary)',
                        color: 'var(--text-secondary)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.03em',
                      }}>
                        {skill.category}
                      </span>
                    )}
                  </div>
                  <div className={styles.providerMeta}>
                    {skill.description || <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>}
                  </div>
                  <div className={styles.providerMeta}>
                    Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div className={styles.providerActions}>
                  <button className="iconButton" title="Edit description" onClick={() => openEditChatDescription(skill.id)}>
                    <Pencil size={14} />
                  </button>
                  <button className="iconButton" title="Download" onClick={() => downloadChatSkill(skill.id, skill.name)}>
                    <Download size={14} />
                  </button>
                  <button className="iconButton" title="Delete" onClick={() => deleteChatSkill(skill.id)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>}

      {/* Tab: API Keys & Tunneling */}
      {activeTab === 'keys' && <><div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>API Keys</h2>
          <div className={styles.sectionHeaderActions}>
            <button className={styles.sectionHeaderBtn} onClick={downloadKeysTemplate} title="Download a JSON template to fill in your API keys offline">
              <Download size={13} /> Download Template
            </button>
            <button className={styles.sectionHeaderBtn} onClick={() => importFileRef.current?.click()} title="Import API keys from a JSON template file">
              <Upload size={13} /> Import Keys
            </button>
            <input
              ref={importFileRef}
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={handleKeysFileSelect}
            />
          </div>
        </div>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="GitHub Access Token"
              hint="Required for GitHub Secret Hunt and TruffleHog scanners. Use repo scope for private repos, or a fine-grained token for specific repos only"
              signupUrl="https://github.com/settings/tokens"
              badges={['GitHub Secret Hunt', 'TruffleHog']}
              value={settings.githubAccessToken}
              visible={!!visibleFields.githubAccessToken}
              onToggle={() => toggleFieldVisibility('githubAccessToken')}
              onChange={v => updateSetting('githubAccessToken', v)}
            />
            <SecretField
              label="Tavily API Key"
              hint="Enables web_search tool for CVE research and exploit lookups"
              signupUrl="https://app.tavily.com/home"
              badges={['AI Agent']}
              value={settings.tavilyApiKey}
              visible={!!visibleFields.tavilyApiKey}
              onToggle={() => toggleFieldVisibility('tavilyApiKey')}
              onChange={v => updateSetting('tavilyApiKey', v)}
              onConfigureRotation={() => openRotationModal('tavilyApiKey')}
              rotationInfo={rotationConfigs.tavily || null}
            />
            <SecretField
              label="Shodan API Key"
              hint="Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)"
              signupUrl="https://account.shodan.io/"
              badges={['AI Agent', 'Recon Pipeline', 'Standalone + Uncover']}
              value={settings.shodanApiKey}
              visible={!!visibleFields.shodanApiKey}
              onToggle={() => toggleFieldVisibility('shodanApiKey')}
              onChange={v => updateSetting('shodanApiKey', v)}
              onConfigureRotation={() => openRotationModal('shodanApiKey')}
              rotationInfo={rotationConfigs.shodan || null}
            />
            <SecretField
              label="SerpAPI Key"
              hint="Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:). Free: 250 searches/month"
              signupUrl="https://serpapi.com/manage-api-key"
              badges={['AI Agent']}
              value={settings.serpApiKey}
              visible={!!visibleFields.serpApiKey}
              onToggle={() => toggleFieldVisibility('serpApiKey')}
              onChange={v => updateSetting('serpApiKey', v)}
              onConfigureRotation={() => openRotationModal('serpApiKey')}
              rotationInfo={rotationConfigs.serp || null}
            />
            <SecretField
              label="WPScan API Token"
              hint="Enriches execute_wpscan results with vulnerability data from the WPScan database. Free: 25 requests/day"
              signupUrl="https://wpscan.com/register"
              badges={['AI Agent']}
              value={settings.wpscanApiToken}
              visible={!!visibleFields.wpscanApiToken}
              onToggle={() => toggleFieldVisibility('wpscanApiToken')}
              onChange={v => updateSetting('wpscanApiToken', v)}
              onConfigureRotation={() => openRotationModal('wpscanApiToken')}
              rotationInfo={rotationConfigs.wpscan || null}
            />
            <SecretField
              label="NVD API Key"
              hint="NIST NVD API key — increases CVE lookup rate limit from 5 to 120 requests/30s"
              signupUrl="https://nvd.nist.gov/developers/request-an-api-key"
              badges={['Recon Pipeline']}
              value={settings.nvdApiKey}
              visible={!!visibleFields.nvdApiKey}
              onToggle={() => toggleFieldVisibility('nvdApiKey')}
              onChange={v => updateSetting('nvdApiKey', v)}
              onConfigureRotation={() => openRotationModal('nvdApiKey')}
              rotationInfo={rotationConfigs.nvd || null}
            />
            <SecretField
              label="Vulners API Key"
              hint="Vulners CVE database — alternative to NVD for vulnerability lookups with richer exploit data"
              signupUrl="https://vulners.com/#register"
              badges={['Recon Pipeline']}
              value={settings.vulnersApiKey}
              visible={!!visibleFields.vulnersApiKey}
              onToggle={() => toggleFieldVisibility('vulnersApiKey')}
              onChange={v => updateSetting('vulnersApiKey', v)}
              onConfigureRotation={() => openRotationModal('vulnersApiKey')}
              rotationInfo={rotationConfigs.vulners || null}
            />
            <SecretField
              label="URLScan API Key"
              hint="Optional — used by URLScan.io OSINT enrichment for higher rate limits. Works without key (public results only)"
              signupUrl="https://urlscan.io/user/signup"
              badges={['Recon Pipeline']}
              value={settings.urlscanApiKey}
              visible={!!visibleFields.urlscanApiKey}
              onToggle={() => toggleFieldVisibility('urlscanApiKey')}
              onChange={v => updateSetting('urlscanApiKey', v)}
              onConfigureRotation={() => openRotationModal('urlscanApiKey')}
              rotationInfo={rotationConfigs.urlscan || null}
            />

            <SecretField
              label="Censys API Token"
              hint="Censys Platform personal access token — used by Recon Pipeline and Uncover engine"
              signupUrl="https://accounts.censys.io/settings/personal-access-tokens"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.censysApiToken}
              visible={!!visibleFields.censysApiToken}
              onToggle={() => toggleFieldVisibility('censysApiToken')}
              onChange={v => updateSetting('censysApiToken', v)}
            />
            <SecretField
              label="Censys Organization ID"
              hint="Censys Organization ID — paired with API Token above. Found on your Censys account page"
              signupUrl="https://accounts.censys.io/settings/personal-access-tokens"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.censysOrgId}
              visible={!!visibleFields.censysOrgId}
              onToggle={() => toggleFieldVisibility('censysOrgId')}
              onChange={v => updateSetting('censysOrgId', v)}
            />
            <SecretField
              label="Censys Personal API Token"
              hint="Personal Access Token from your Censys account — alternative to API ID + Secret. Takes precedence when both are set."
              signupUrl="https://accounts.censys.io/settings/personal-access-tokens"
              badges={['Recon Pipeline']}
              value={settings.censysApiToken}
              visible={!!visibleFields.censysApiToken}
              onToggle={() => toggleFieldVisibility('censysApiToken')}
              onChange={v => updateSetting('censysApiToken', v)}
            />
            <SecretField
              label="FOFA API Key"
              hint="FOFA cyberspace search — asset discovery by banner, certificate, domain. Key format: email:key"
              signupUrl="https://en.fofa.info/"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.fofaApiKey}
              visible={!!visibleFields.fofaApiKey}
              onToggle={() => toggleFieldVisibility('fofaApiKey')}
              onChange={v => updateSetting('fofaApiKey', v)}
              onConfigureRotation={() => openRotationModal('fofaApiKey')}
              rotationInfo={rotationConfigs.fofa || null}
            />
            <SecretField
              label="AlienVault OTX Key"
              hint="Open Threat Exchange — threat intelligence pulses, malware indicators, passive DNS, reputation scoring"
              signupUrl="https://otx.alienvault.com/settings"
              badges={['Recon Pipeline']}
              value={settings.otxApiKey}
              visible={!!visibleFields.otxApiKey}
              onToggle={() => toggleFieldVisibility('otxApiKey')}
              onChange={v => updateSetting('otxApiKey', v)}
              onConfigureRotation={() => openRotationModal('otxApiKey')}
              rotationInfo={rotationConfigs.otx || null}
            />
            <SecretField
              label="Netlas API Key"
              hint="Netlas.io — internet-wide scan data with banners, certificates, and WHOIS info"
              signupUrl="https://app.netlas.io/profile/"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.netlasApiKey}
              visible={!!visibleFields.netlasApiKey}
              onToggle={() => toggleFieldVisibility('netlasApiKey')}
              onChange={v => updateSetting('netlasApiKey', v)}
              onConfigureRotation={() => openRotationModal('netlasApiKey')}
              rotationInfo={rotationConfigs.netlas || null}
            />
            <SecretField
              label="VirusTotal API Key"
              hint="Multi-engine reputation for IPs and domains. Free tier: 4 lookups/min, 500/day"
              signupUrl="https://www.virustotal.com/gui/my-apikey"
              badges={['Recon Pipeline']}
              value={settings.virusTotalApiKey}
              visible={!!visibleFields.virusTotalApiKey}
              onToggle={() => toggleFieldVisibility('virusTotalApiKey')}
              onChange={v => updateSetting('virusTotalApiKey', v)}
              onConfigureRotation={() => openRotationModal('virusTotalApiKey')}
              rotationInfo={rotationConfigs.virustotal || null}
            />
            <SecretField
              label="ZoomEye API Key"
              hint="ZoomEye cyberspace search — host/device discovery with port, banner, and geo data"
              signupUrl="https://www.zoomeye.ai/profile"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.zoomEyeApiKey}
              visible={!!visibleFields.zoomEyeApiKey}
              onToggle={() => toggleFieldVisibility('zoomEyeApiKey')}
              onChange={v => updateSetting('zoomEyeApiKey', v)}
              onConfigureRotation={() => openRotationModal('zoomEyeApiKey')}
              rotationInfo={rotationConfigs.zoomeye || null}
            />
            <SecretField
              label="Criminal IP API Key"
              hint="AI-powered threat intelligence — IP/domain risk scoring, vulnerability detection, proxy/VPN/Tor identification"
              signupUrl="https://search.criminalip.io/mypage/information"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.criminalIpApiKey}
              visible={!!visibleFields.criminalIpApiKey}
              onToggle={() => toggleFieldVisibility('criminalIpApiKey')}
              onChange={v => updateSetting('criminalIpApiKey', v)}
              onConfigureRotation={() => openRotationModal('criminalIpApiKey')}
              rotationInfo={rotationConfigs.criminalip || null}
            />

            {/* Uncover group */}
            <div style={{ borderTop: '1px solid var(--border-secondary)', marginTop: '0.75rem', paddingTop: '0.75rem' }}>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                Uncover (Multi-Engine Search)
              </p>
            </div>
            <SecretField
              label="Quake API Key"
              hint="360 Quake cyberspace search — asset discovery by service, certificate, and banner"
              signupUrl="https://quake.360.net/quake/#/index"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.quakeApiKey}
              visible={!!visibleFields.quakeApiKey}
              onToggle={() => toggleFieldVisibility('quakeApiKey')}
              onChange={v => updateSetting('quakeApiKey', v)}
              onConfigureRotation={() => openRotationModal('quakeApiKey')}
              rotationInfo={rotationConfigs.quake || null}
            />
            <SecretField
              label="Hunter API Key"
              hint="Qianxin Hunter cyberspace search — Chinese threat intelligence platform"
              signupUrl="https://hunter.qianxin.com/"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.hunterApiKey}
              visible={!!visibleFields.hunterApiKey}
              onToggle={() => toggleFieldVisibility('hunterApiKey')}
              onChange={v => updateSetting('hunterApiKey', v)}
              onConfigureRotation={() => openRotationModal('hunterApiKey')}
              rotationInfo={rotationConfigs.hunter || null}
            />
            <SecretField
              label="PublicWWW API Key"
              hint="Search engine for source code — find websites using specific technologies, scripts, or snippets"
              signupUrl="https://publicwww.com/profile/signup.html"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.publicWwwApiKey}
              visible={!!visibleFields.publicWwwApiKey}
              onToggle={() => toggleFieldVisibility('publicWwwApiKey')}
              onChange={v => updateSetting('publicWwwApiKey', v)}
              onConfigureRotation={() => openRotationModal('publicWwwApiKey')}
              rotationInfo={rotationConfigs.publicwww || null}
            />
            <SecretField
              label="HunterHow API Key"
              hint="hunter.how internet search — asset discovery and reconnaissance"
              signupUrl="https://hunter.how/"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.hunterHowApiKey}
              visible={!!visibleFields.hunterHowApiKey}
              onToggle={() => toggleFieldVisibility('hunterHowApiKey')}
              onChange={v => updateSetting('hunterHowApiKey', v)}
              onConfigureRotation={() => openRotationModal('hunterHowApiKey')}
              rotationInfo={rotationConfigs.hunterhow || null}
            />
            <SecretField
              label="Google Custom Search API Key"
              hint="Google Custom Search JSON API — for Uncover Google search engine (different from SerpAPI)"
              signupUrl="https://developers.google.com/custom-search/v1/introduction"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.googleApiKey}
              visible={!!visibleFields.googleApiKey}
              onToggle={() => toggleFieldVisibility('googleApiKey')}
              onChange={v => updateSetting('googleApiKey', v)}
            />
            <SecretField
              label="Google Custom Search CX"
              hint="Programmable Search Engine ID — paired with Google API Key above"
              signupUrl="https://programmablesearchengine.google.com/controlpanel/create"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.googleApiCx}
              visible={!!visibleFields.googleApiCx}
              onToggle={() => toggleFieldVisibility('googleApiCx')}
              onChange={v => updateSetting('googleApiCx', v)}
            />
            <SecretField
              label="Onyphe API Key"
              hint="Onyphe — cyber defense search engine for exposed assets, threat detection, and attack surface management"
              signupUrl="https://search.onyphe.io/signup"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.onypheApiKey}
              visible={!!visibleFields.onypheApiKey}
              onToggle={() => toggleFieldVisibility('onypheApiKey')}
              onChange={v => updateSetting('onypheApiKey', v)}
              onConfigureRotation={() => openRotationModal('onypheApiKey')}
              rotationInfo={rotationConfigs.onyphe || null}
            />
            <SecretField
              label="Driftnet API Key"
              hint="Driftnet — fast internet-wide port and service discovery"
              signupUrl="https://driftnet.io/auth?state=signup"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.driftnetApiKey}
              visible={!!visibleFields.driftnetApiKey}
              onToggle={() => toggleFieldVisibility('driftnetApiKey')}
              onChange={v => updateSetting('driftnetApiKey', v)}
              onConfigureRotation={() => openRotationModal('driftnetApiKey')}
              rotationInfo={rotationConfigs.driftnet || null}
            />
          </div>
        )}
      </div>

      {/* Tunneling sub-section */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>Tunneling</h2>
        </div>
        <p className={styles.sectionHint}>
          Configure reverse shell tunneling. Choose ngrok (free, single port) or chisel (multi-port, requires VPS). Changes apply immediately.
        </p>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="ngrok Auth Token"
              hint="Enables ngrok TCP tunnel for reverse shells on port 4444. Stageless payloads only."
              signupUrl="https://dashboard.ngrok.com/get-started/your-authtoken"
              value={settings.ngrokAuthtoken}
              visible={!!visibleFields.ngrokAuthtoken}
              onToggle={() => toggleFieldVisibility('ngrokAuthtoken')}
              onChange={v => updateSetting('ngrokAuthtoken', v)}
            />
            <div className="formGroup">
              <label className="formLabel">Chisel Server URL</label>
              <input
                className="textInput"
                type="text"
                value={settings.chiselServerUrl}
                onChange={e => updateSetting('chiselServerUrl', e.target.value)}
                placeholder="e.g. http://your-vps.com:9090"
              />
              <span className="formHint">
                Your VPS chisel server URL. Run on VPS: <code>chisel server -p 9090 --reverse</code>. Tunnels ports 4444 (handler) + 8080 (web delivery).
              </span>
            </div>
            <SecretField
              label="Chisel Auth"
              hint="user:pass for chisel server authentication (optional — only if your chisel server requires auth)"
              value={settings.chiselAuth}
              visible={!!visibleFields.chiselAuth}
              onToggle={() => toggleFieldVisibility('chiselAuth')}
              onChange={v => updateSetting('chiselAuth', v)}
            />
          </div>
        )}
        {settingsDirty && !settingsSaving && (
          <div className={styles.formActions} style={{ justifyContent: 'flex-end', marginTop: '12px' }}>
            <button className="primaryButton" onClick={saveSettings} disabled={settingsSaving}>
              Save Settings
            </button>
          </div>
        )}
      </div></>}

      {/* Tab: System */}
      {activeTab === 'system' && <SystemSection />}

      {/* Skill upload modal */}
      <Modal
        isOpen={skillNameModal}
        onClose={() => { setSkillNameModal(false); setPendingSkillContent(''); setPendingSkillName(''); setPendingSkillDescription('') }}
        title="Upload Attack Skill"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setSkillNameModal(false); setPendingSkillContent(''); setPendingSkillName(''); setPendingSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={!pendingSkillName.trim() || skillUploading}
              onClick={confirmSkillUpload}
            >
              {skillUploading ? <Loader2 size={14} className={styles.spin} /> : <Upload size={14} />}
              Upload
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Skill Name</label>
          <input
            className="textInput"
            type="text"
            value={pendingSkillName}
            onChange={(e) => setPendingSkillName(e.target.value)}
            placeholder="e.g. SQL Injection Workflow"
            autoFocus
          />
          <span className="formHint">
            This name appears in project settings and classification badges.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={pendingSkillDescription}
            onChange={(e) => setPendingSkillDescription(e.target.value)}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={500}
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead &mdash; a good description improves classification accuracy.
          </span>
        </div>
      </Modal>

      {/* Edit description modal */}
      <Modal
        isOpen={editDescModal}
        onClose={() => { setEditDescModal(false); setEditingSkillId(''); setEditingSkillDescription('') }}
        title="Edit Skill Description"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setEditDescModal(false); setEditingSkillId(''); setEditingSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={editDescSaving}
              onClick={saveEditDescription}
            >
              {editDescSaving ? <Loader2 size={14} className={styles.spin} /> : <Pencil size={14} />}
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={editingSkillDescription}
            onChange={(e) => setEditingSkillDescription(e.target.value)}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={500}
            autoFocus
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead &mdash; a good description improves classification accuracy.
          </span>
        </div>
      </Modal>

      {/* Chat Skill upload modal */}
      <Modal
        isOpen={chatSkillNameModal}
        onClose={() => { setChatSkillNameModal(false); setPendingChatSkillContent(''); setPendingChatSkillName(''); setPendingChatSkillDescription(''); setPendingChatSkillCategory('general') }}
        title="Upload Chat Skill"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setChatSkillNameModal(false); setPendingChatSkillContent(''); setPendingChatSkillName(''); setPendingChatSkillDescription(''); setPendingChatSkillCategory('general') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={!pendingChatSkillName.trim() || chatSkillUploading}
              onClick={confirmChatSkillUpload}
            >
              {chatSkillUploading ? <Loader2 size={14} className={styles.spin} /> : <Upload size={14} />}
              Upload
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Skill Name</label>
          <input
            className="textInput"
            type="text"
            value={pendingChatSkillName}
            onChange={(e) => setPendingChatSkillName(e.target.value)}
            placeholder="e.g. OWASP Top 10 Reference"
            autoFocus
          />
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={pendingChatSkillDescription}
            onChange={(e) => setPendingChatSkillDescription(e.target.value)}
            placeholder="e.g. Quick reference for OWASP Top 10 vulnerability categories"
            maxLength={500}
          />
          <span className="formHint">
            Optional. Helps you remember what this skill covers.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Category</label>
          <select
            className="textInput"
            value={pendingChatSkillCategory}
            onChange={(e) => setPendingChatSkillCategory(e.target.value)}
          >
            <option value="general">general</option>
            <option value="vulnerabilities">vulnerabilities</option>
            <option value="tooling">tooling</option>
            <option value="scan_modes">scan_modes</option>
            <option value="frameworks">frameworks</option>
            <option value="technologies">technologies</option>
            <option value="protocols">protocols</option>
            <option value="coordination">coordination</option>
            <option value="cloud">cloud</option>
            <option value="mobile">mobile</option>
            <option value="api_security">api_security</option>
            <option value="wireless">wireless</option>
            <option value="network">network</option>
            <option value="active_directory">active_directory</option>
            <option value="social_engineering">social_engineering</option>
            <option value="reporting">reporting</option>
          </select>
          <span className="formHint">
            Categorize this skill for easier browsing.
          </span>
        </div>
      </Modal>

      {/* Chat Skill edit description modal */}
      <Modal
        isOpen={editChatDescModal}
        onClose={() => { setEditChatDescModal(false); setEditingChatSkillId(''); setEditingChatSkillDescription('') }}
        title="Edit Chat Skill Description"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setEditChatDescModal(false); setEditingChatSkillId(''); setEditingChatSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={editChatDescSaving}
              onClick={saveEditChatDescription}
            >
              {editChatDescSaving ? <Loader2 size={14} className={styles.spin} /> : <Pencil size={14} />}
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={editingChatSkillDescription}
            onChange={(e) => setEditingChatSkillDescription(e.target.value)}
            placeholder="e.g. Quick reference for OWASP Top 10 vulnerability categories"
            maxLength={500}
            autoFocus
          />
          <span className="formHint">
            Optional description to help you remember what this skill covers.
          </span>
        </div>
      </Modal>

      {/* Key Rotation Modal */}
      <Modal
        isOpen={!!rotationModal}
        onClose={closeRotationModal}
        title={`Key Rotation — ${rotationModal || ''}`}
        size="small"
        footer={
          <>
            {rotationConfigs[rotationModal || '']?.extraKeyCount > 0 && !rotationDraftDirty && (
              <button className="secondaryButton" onClick={clearRotationConfig} style={{ marginRight: 'auto' }}>
                Clear All Extra Keys
              </button>
            )}
            <button className="secondaryButton" onClick={closeRotationModal}>Cancel</button>
            <button
              className="primaryButton"
              onClick={saveRotationDraft}
              disabled={!rotationDraftDirty && rotationDraft.rotateEveryN === (rotationConfigs[rotationModal || '']?.rotateEveryN ?? 10)}
            >
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Extra API Keys</label>
          {rotationConfigs[rotationModal || '']?.extraKeyCount > 0 && !rotationDraftDirty ? (
            <>
              <div style={{
                padding: '10px 12px',
                background: 'var(--accent-secondary-subtle)',
                borderRadius: '6px',
                fontSize: '12px',
                color: 'var(--accent-secondary)',
                marginBottom: '8px',
              }}>
                {rotationConfigs[rotationModal || '']?.extraKeyCount} extra key(s) configured. Paste new keys below to replace them.
              </div>
              <textarea
                className="textInput"
                rows={5}
                value={rotationDraft.extraKeys}
                onChange={e => {
                  setRotationDraft(prev => ({ ...prev, extraKeys: e.target.value }))
                  setRotationDraftDirty(true)
                }}
                placeholder="Paste API keys here, one per line..."
                style={{ fontFamily: 'monospace', fontSize: '12px' }}
              />
            </>
          ) : (
            <textarea
              className="textInput"
              rows={5}
              value={rotationDraft.extraKeys}
              onChange={e => {
                setRotationDraft(prev => ({ ...prev, extraKeys: e.target.value }))
                setRotationDraftDirty(true)
              }}
              placeholder="Paste API keys here, one per line..."
              style={{ fontFamily: 'monospace', fontSize: '12px' }}
              autoFocus
            />
          )}
          <span className="formHint">
            These keys plus the main key above form the rotation pool. All keys are treated equally.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Rotate Every N Calls</label>
          <input
            className="textInput"
            type="number"
            min={1}
            value={rotationDraft.rotateEveryN}
            onChange={e => setRotationDraft(prev => ({ ...prev, rotateEveryN: parseInt(e.target.value, 10) || 10 }))}
            style={{ width: '120px' }}
          />
          <span className="formHint">
            After this many API calls, switch to the next key in the pool (default: 10).
          </span>
        </div>
      </Modal>

      {/* Import Keys Confirmation Modal */}
      <Modal
        isOpen={!!pendingImport}
        onClose={() => setPendingImport(null)}
        title="Import API Keys"
        size="small"
        footer={
          <>
            <button className="secondaryButton" onClick={() => setPendingImport(null)}>Cancel</button>
            <button className="primaryButton" onClick={confirmImport}>
              <Upload size={14} /> Import
            </button>
          </>
        }
      >
        {pendingImport && (
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            <p style={{ marginBottom: '12px' }}>The following will be loaded into the form:</p>
            <ul style={{ margin: 0, paddingLeft: '18px' }}>
              {pendingImport.keyCount > 0 && <li><strong>{pendingImport.keyCount}</strong> API key{pendingImport.keyCount > 1 ? 's' : ''}</li>}
              {pendingImport.rotationCount > 0 && <li><strong>{pendingImport.rotationCount}</strong> rotation config{pendingImport.rotationCount > 1 ? 's' : ''}</li>}
              {pendingImport.tunnelingCount > 0 && <li><strong>{pendingImport.tunnelingCount}</strong> tunneling field{pendingImport.tunnelingCount > 1 ? 's' : ''}</li>}
            </ul>
            <p style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-tertiary)' }}>
              Empty values and masked values are skipped. You must click <strong>Save Settings</strong> after import to persist.
            </p>
          </div>
        )}
      </Modal>

    </div>
  )
}

// ---------------------------------------------------------------------------
// System Section (version info + update check)
// ---------------------------------------------------------------------------

function SystemSection() {
  const { currentVersion, latestVersion, changelog, updateAvailable, loading } = useVersionCheck()

  const [copied, setCopied] = useState(false)
  const [expandedVersions, setExpandedVersions] = useState<Set<string>>(new Set())

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText('./redamon.sh update').then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [])

  const toggleVersion = (version: string) => {
    setExpandedVersions(prev => {
      const next = new Set(prev)
      if (next.has(version)) next.delete(version)
      else next.add(version)
      return next
    })
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}><Info size={16} /> System</h2>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {/* Version info */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Current version: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>v{currentVersion}</strong>
          </span>

          {latestVersion && !updateAvailable && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '4px',
              fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '4px',
              background: 'var(--status-success-bg)', color: 'var(--status-success-text)',
            }}>
              Up to date
            </span>
          )}

          {updateAvailable && latestVersion && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '4px',
              fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '4px',
              background: 'var(--status-warning-bg)', color: 'var(--status-warning-text)',
            }}>
              v{latestVersion} available
            </span>
          )}

          {loading && (
            <Loader2 size={12} className={styles.spin} style={{ marginLeft: 'auto' }} />
          )}
        </div>

        {/* Update available: show command + changelog */}
        {updateAvailable && (
          <>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              padding: '8px 12px', background: 'var(--bg-primary)',
              border: '1px solid var(--border-default)', borderRadius: '6px',
              fontFamily: 'var(--font-mono)',
            }}>
              <code style={{ flex: 1, fontSize: '13px', color: 'var(--color-success)' }}>
                ./redamon.sh update
              </code>
              <button
                onClick={handleCopy}
                title="Copy command"
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  padding: '4px', background: 'none', border: '1px solid var(--border-default)',
                  borderRadius: '4px', color: 'var(--text-tertiary)', cursor: 'pointer',
                }}
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
              </button>
            </div>

            {/* Changelog */}
            {changelog && changelog.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Changes since v{currentVersion}:
                </span>
                <div style={{
                  maxHeight: '250px', overflowY: 'auto',
                  border: '1px solid var(--border-default)', borderRadius: '6px',
                  background: 'var(--bg-primary)',
                }}>
                  {changelog.map((entry: { version: string; date: string; sections: { title: string; items: string[] }[] }) => {
                    const isExpanded = expandedVersions.has(entry.version)
                    return (
                      <div key={entry.version} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <button
                          type="button"
                          onClick={() => toggleVersion(entry.version)}
                          style={{
                            display: 'flex', alignItems: 'center', gap: '6px',
                            width: '100%', padding: '6px 10px', background: 'none',
                            border: 'none', cursor: 'pointer', fontSize: '12px',
                            color: 'var(--text-primary)', textAlign: 'left',
                          }}
                        >
                          {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                          <strong style={{ fontFamily: 'var(--font-mono)' }}>v{entry.version}</strong>
                          <span style={{ color: 'var(--text-tertiary)', fontSize: '11px', marginLeft: 'auto' }}>{entry.date}</span>
                        </button>
                        {isExpanded && (
                          <div style={{ padding: '0 10px 8px 28px' }}>
                            {entry.sections.map((section: { title: string; items: string[] }) => (
                              <div key={section.title} style={{ marginTop: '4px' }}>
                                <div style={{ fontSize: '10px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                  {section.title}
                                </div>
                                <ul style={{ margin: '2px 0 0', paddingLeft: '16px', listStyle: 'disc' }}>
                                  {section.items.map((item: string, i: number) => (
                                    <li key={i} style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>{item}</li>
                                  ))}
                                </ul>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        )}

        {/* Links */}
        <div style={{ display: 'flex', gap: '12px', fontSize: '11px' }}>
          <a
            href="https://github.com/samugit83/redamon/blob/master/CHANGELOG.md"
            target="_blank"
            rel="noopener noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--text-tertiary)', textDecoration: 'none' }}
          >
            <ExternalLink size={11} /> Changelog
          </a>
        </div>
      </div>
    </div>
  )
}

// Badge color mapping
const BADGE_STYLES: Record<string, React.CSSProperties> = {
  'AI Agent': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'var(--status-info-bg)',
    color: 'var(--status-info-text)',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'Recon Pipeline': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'var(--status-success-bg)',
    color: 'var(--status-success-text)',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'GitHub Secret Hunt': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'rgba(139, 92, 246, 0.12)',
    color: '#8b5cf6',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'TruffleHog': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'rgba(139, 92, 246, 0.12)',
    color: '#8b5cf6',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
}

// Reusable secret field component
function SecretField({
  label,
  hint,
  signupUrl,
  badges,
  value,
  visible,
  onToggle,
  onChange,
  onConfigureRotation,
  rotationInfo,
}: {
  label: string
  hint: string
  signupUrl?: string
  badges?: string[]
  value: string
  visible: boolean
  onToggle: () => void
  onChange: (v: string) => void
  onConfigureRotation?: () => void
  rotationInfo?: RotationInfo | null
}) {
  const mainKeyCount = value && !value.startsWith('••••') ? 1 : value ? 1 : 0
  const totalKeys = mainKeyCount + (rotationInfo?.extraKeyCount || 0)

  return (
    <div className="formGroup">
      <label className="formLabel">
        {label}
        {badges?.map(badge => (
          <span key={badge} style={BADGE_STYLES[badge] || BADGE_STYLES['AI Agent']}>
            {badge}
          </span>
        ))}
      </label>
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <div className={styles.secretInputWrapper} style={{ flex: 1 }}>
          <input
            className="textInput"
            type={visible ? 'text' : 'password'}
            value={value ?? ''}
            onChange={e => onChange(e.target.value)}
            placeholder={`Enter ${label.toLowerCase()}`}
          />
          <button className={styles.secretToggle} onClick={onToggle} type="button">
            {visible ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>
        {onConfigureRotation && (
          <button
            onClick={onConfigureRotation}
            type="button"
            title="Configure key rotation"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              padding: '6px 10px',
              fontSize: '11px',
              fontWeight: 500,
              color: rotationInfo && rotationInfo.extraKeyCount > 0 ? 'var(--accent-secondary)' : 'var(--text-secondary)',
              background: rotationInfo && rotationInfo.extraKeyCount > 0 ? 'var(--accent-secondary-subtle)' : 'var(--bg-tertiary)',
              border: '1px solid var(--border-default)',
              borderRadius: '6px',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}
          >
            <RotateCw size={12} />
            Key Rotation
          </button>
        )}
      </div>
      <span className="formHint">
        {hint}
        {signupUrl && (
          <>
            {' — '}
            <a href={signupUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
              Get API key
            </a>
          </>
        )}
      </span>
      {rotationInfo && rotationInfo.extraKeyCount > 0 && (
        <span style={{
          display: 'inline-block',
          fontSize: '10px',
          fontWeight: 600,
          padding: '2px 8px',
          borderRadius: '4px',
          background: 'var(--accent-secondary-subtle)',
          color: 'var(--accent-secondary)',
          marginTop: '4px',
          letterSpacing: '0.02em',
        }}>
          {totalKeys} keys total, rotate every {rotationInfo.rotateEveryN} calls
        </span>
      )}
    </div>
  )
}
