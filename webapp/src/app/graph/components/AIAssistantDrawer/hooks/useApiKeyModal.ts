import { useState, useCallback, useEffect } from 'react'

export const API_KEY_INFO: Record<string, { field: string; label: string; hint: string; url: string }> = {
  web_search: { field: 'tavilyApiKey', label: 'Tavily', hint: 'Enables web_search tool for CVE research and exploit lookups', url: 'https://app.tavily.com/home' },
  shodan: { field: 'shodanApiKey', label: 'Shodan', hint: 'Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)', url: 'https://account.shodan.io/' },
  google_dork: { field: 'serpApiKey', label: 'SerpAPI', hint: 'Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:)', url: 'https://serpapi.com/manage-api-key' },
  execute_wpscan: { field: 'wpscanApiToken', label: 'WPScan', hint: 'Enriches execute_wpscan results with vulnerability data from the WPScan database (free: 25 req/day)', url: 'https://wpscan.com/register' },
  execute_gau: { field: 'urlscanApiKey', label: 'URLScan', hint: 'Enriches execute_gau results with URLScan archived data (free tier available)', url: 'https://urlscan.io/user/signup' },
}

export function useApiKeyModal(userId: string) {
  const [missingApiKeys, setMissingApiKeys] = useState<Set<string>>(new Set())
  const [apiKeyModal, setApiKeyModal] = useState<string | null>(null)
  const [apiKeyValue, setApiKeyValue] = useState('')
  const [apiKeyVisible, setApiKeyVisible] = useState(false)
  const [apiKeySaving, setApiKeySaving] = useState(false)

  const fetchApiKeyStatus = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (!settings) return
        const missing = new Set<string>()
        if (!settings.tavilyApiKey) missing.add('web_search')
        if (!settings.shodanApiKey) missing.add('shodan')
        if (!settings.serpApiKey) missing.add('google_dork')
        if (!settings.wpscanApiToken) missing.add('execute_wpscan')
        if (!settings.urlscanApiKey) missing.add('execute_gau')
        setMissingApiKeys(missing)
      })
      .catch(() => {})
  }, [userId])

  useEffect(() => { fetchApiKeyStatus() }, [fetchApiKeyStatus])

  const openApiKeyModal = useCallback((toolId: string) => {
    setApiKeyModal(toolId)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const closeApiKeyModal = useCallback(() => {
    setApiKeyModal(null)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const saveApiKey = useCallback(async () => {
    if (!userId || !apiKeyModal || !apiKeyValue.trim()) return
    const info = API_KEY_INFO[apiKeyModal]
    if (!info) return
    setApiKeySaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [info.field]: apiKeyValue.trim() }),
      })
      if (resp.ok) {
        closeApiKeyModal()
        fetchApiKeyStatus()
      }
    } catch { /* silent */ } finally {
      setApiKeySaving(false)
    }
  }, [userId, apiKeyModal, apiKeyValue, closeApiKeyModal, fetchApiKeyStatus])

  return {
    missingApiKeys,
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
