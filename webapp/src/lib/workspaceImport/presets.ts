/**
 * Quick-import chips for the workspace's "Import from URL" dialog.
 *
 * Every URL is copied from QUICK_ADD_PRESETS_RAW in
 * components/settings/TradecraftResourceForm.tsx, except the SecLists
 * Web-Content preset, which is the SecLists URL there plus a /tree/ path.
 * presets.test.ts holds both to that, so no URL here is typed from memory.
 */
export interface ImportPreset {
  label: string
  url: string
  description: string
}

const SECLISTS = 'https://github.com/danielmiessler/SecLists'

export const IMPORT_PRESETS: readonly ImportPreset[] = [
  { label: 'SecLists', url: SECLISTS, description: 'Wordlists for usernames, passwords, URLs and fuzzing payloads' },
  {
    label: 'SecLists: Web-Content',
    url: `${SECLISTS}/tree/master/Discovery/Web-Content`,
    description: 'Only the SecLists folder of web content discovery wordlists',
  },
  { label: 'PayloadsAllTheThings', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings', description: 'Payloads and bypasses for each vulnerability class' },
  { label: 'InternalAllTheThings', url: 'https://github.com/swisskyrepo/InternalAllTheThings', description: 'Active Directory and post-exploitation cheatsheets' },
  { label: 'OWASP CheatSheets', url: 'https://github.com/OWASP/CheatSheetSeries', description: 'OWASP cheatsheets for each topic (XSS, CSRF, authentication, JWT)' },
  { label: 'OWASP WSTG', url: 'https://github.com/OWASP/wstg', description: 'The OWASP Web Security Testing Guide, as Markdown' },
  { label: 'GTFOBins', url: 'https://github.com/GTFOBins/GTFOBins.github.io', description: 'Unix binaries that can be abused to escalate privileges or escape a shell' },
  { label: 'LOLBAS', url: 'https://github.com/LOLBAS-Project/LOLBAS', description: 'Signed Windows binaries and scripts that can be abused' },
  { label: 'PEASS-ng', url: 'https://github.com/peass-ng/PEASS-ng', description: 'LinPEAS, WinPEAS and MacPEAS privilege-escalation scripts' },
  { label: 'atomic-red-team', url: 'https://github.com/redcanaryco/atomic-red-team', description: 'Small tests for MITRE ATT&CK techniques' },
]
