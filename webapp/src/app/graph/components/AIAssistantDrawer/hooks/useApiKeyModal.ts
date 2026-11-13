import { useState, useCallback, useEffect, useMemo } from 'react'
import { useAlertModal } from '@/components/ui'
import { readApiError, toApiError } from '@/lib/apiError'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'

export const API_KEY_INFO: Record<string, { field: string; label: string; hint: string; url: string }> = {
  web_search: { field: 'tavilyApiKey', label: 'Tavily', hint: 'Enables web_search tool for CVE research and exploit lookups', url: 'https://app.tavily.com/home' },
  shodan: { field: 'shodanApiKey', label: 'Shodan', hint: 'Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)', url: 'https://account.shodan.io/' },
  google_dork: { field: 'serpApiKey', label: 'SerpAPI', hint: 'Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:)', url: 'https://serpapi.com/manage-api-key' },
  execute_wpscan: { field: 'wpscanApiToken', label: 'WPScan', hint: 'Enriches execute_wpscan results with vulnerability data from the WPScan database (free: 25 req/day)', url: 'https://wpscan.com/register' },
  execute_gau: { field: 'urlscanApiKey', label: 'URLScan', hint: 'Enriches execute_gau results with URLScan archived data (free tier available)', url: 'https://urlscan.io/user/signup' },
  cve_intel: { field: 'pdcpApiKey', label: 'PDCP', hint: 'Optional. Lifts the 10 req/min anonymous rate limit on the ProjectDiscovery CVE database (vulnx).', url: 'https://cloud.projectdiscovery.io' },
}

/** The drawer tools whose key the given settings (values, or presence flags) do not hold. */
function missingKeyTools(settings: Record<string, unknown>): Set<string> {
  return new Set(Object.keys(API_KEY_INFO).filter(tool => !settings[API_KEY_INFO[tool].field]))
}

/**
 * The drawer's missing-key warnings and its "add a key" modal. On a project the person does not own
 * (step 5.7) the agent's tools run on the OWNER's keys: the warnings follow the owner catalog's
 * presence flags, `apiKeysReadOnly` is set and nothing opens or saves, since only the owner writes
 * the owner's settings. Otherwise the person's own settings, as before.
 */
export function useApiKeyModal(userId: string) {
  const { alertError } = useAlertModal()
  const owner = useOwnerCatalogSource()
  const apiKeysReadOnly = owner !== null
  const ownerKeys = owner?.catalog?.keys ?? null
  const [ownMissingApiKeys, setMissingApiKeys] = useState<Set<string>>(new Set())
  // While the owner's catalog loads (or failed) no key is called missing, as before the own read.
  const ownerMissingApiKeys = useMemo(() => (ownerKeys ? missingKeyTools(ownerKeys) : new Set<string>()), [ownerKeys])
  const missingApiKeys = apiKeysReadOnly ? ownerMissingApiKeys : ownMissingApiKeys
  const [apiKeyModal, setApiKeyModal] = useState<string | null>(null)
  const [apiKeyValue, setApiKeyValue] = useState('')
  const [apiKeyVisible, setApiKeyVisible] = useState(false)
  const [apiKeySaving, setApiKeySaving] = useState(false)

  const fetchApiKeyStatus = useCallback(() => {
    if (!userId || apiKeysReadOnly) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (!settings) return
        setMissingApiKeys(missingKeyTools(settings))
      })
      .catch(() => {})
  }, [userId, apiKeysReadOnly])

  useEffect(() => { fetchApiKeyStatus() }, [fetchApiKeyStatus])

  const openApiKeyModal = useCallback((toolId: string) => {
    if (apiKeysReadOnly) return
    setApiKeyModal(toolId)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [apiKeysReadOnly])

  const closeApiKeyModal = useCallback(() => {
    setApiKeyModal(null)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const saveApiKey = useCallback(async () => {
    if (!userId || apiKeysReadOnly || !apiKeyModal || !apiKeyValue.trim()) return
    const info = API_KEY_INFO[apiKeyModal]
    if (!info) return
    setApiKeySaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [info.field]: apiKeyValue.trim() }),
      })
      if (!resp.ok) throw await readApiError(resp, `Could not save the ${info.label} key`)
      closeApiKeyModal()
      fetchApiKeyStatus()
    } catch (err) {
      // The modal stays open with the key typed in, so a retry needs no retyping.
      alertError(toApiError(err, `Could not save the ${info.label} key`).message, 'API key not saved')
    } finally {
      setApiKeySaving(false)
    }
  }, [userId, apiKeysReadOnly, apiKeyModal, apiKeyValue, closeApiKeyModal, fetchApiKeyStatus, alertError])

  return {
    missingApiKeys,
    apiKeysReadOnly,
    apiKeyModal,
    apiKeyValue,
    setApiKeyValue,
    apiKeyVisible,
    setApiKeyVisible,
    apiKeySaving,
    openApiKeyModal,
    closeApiKeyModal,
    saveApiKey,
    fetchApiKeyStatus,
  }
}
