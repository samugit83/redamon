/**
 * Quick-import chips for the workspace's "Import from URL" dialog.
 *
 * Every URL comes from the Tradecraft presets (lib/tradecraft/presets.ts) by key, except
 * the SecLists Web-Content preset, which is the SecLists URL plus a /tree/ path, so no
 * URL here is typed from memory. The Featured presets are not offered here.
 */
import { TRADECRAFT_PRESETS } from '@/lib/tradecraft/presets'

export interface ImportPreset {
  label: string
  url: string
  description: string
}

function tradecraftUrl(key: string): string {
  const preset = TRADECRAFT_PRESETS.find(p => p.key === key)
  if (!preset) throw new Error(`no Tradecraft preset with key ${key}`)
  return preset.url
}

const SECLISTS = tradecraftUrl('seclists')

export const IMPORT_PRESETS: readonly ImportPreset[] = [
  { label: 'SecLists', url: SECLISTS, description: 'Wordlists for usernames, passwords, URLs and fuzzing payloads' },
  {
    label: 'SecLists: Web-Content',
    url: `${SECLISTS}/tree/master/Discovery/Web-Content`,
    description: 'Only the SecLists folder of web content discovery wordlists',
  },
  { label: 'PayloadsAllTheThings', url: tradecraftUrl('payloadsallthethings'), description: 'Payloads and bypasses for each vulnerability class' },
  { label: 'InternalAllTheThings', url: tradecraftUrl('internalallthethings'), description: 'Active Directory and post-exploitation cheatsheets' },
  { label: 'OWASP CheatSheets', url: tradecraftUrl('owasp-cheatsheets'), description: 'OWASP cheatsheets for each topic (XSS, CSRF, authentication, JWT)' },
  { label: 'OWASP WSTG', url: tradecraftUrl('owasp-wstg'), description: 'The OWASP Web Security Testing Guide, as Markdown' },
  { label: 'GTFOBins', url: tradecraftUrl('gtfobins-source'), description: 'Unix binaries that can be abused to escalate privileges or escape a shell' },
  { label: 'LOLBAS', url: tradecraftUrl('lolbas-source'), description: 'Signed Windows binaries and scripts that can be abused' },
  { label: 'PEASS-ng', url: tradecraftUrl('peass-ng'), description: 'LinPEAS, WinPEAS and MacPEAS privilege-escalation scripts' },
  { label: 'atomic-red-team', url: tradecraftUrl('atomic-red-team'), description: 'Small tests for MITRE ATT&CK techniques' },
]
