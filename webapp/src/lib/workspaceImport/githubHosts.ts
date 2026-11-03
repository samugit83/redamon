/**
 * The hosts that receive the user's GitHub token for a URL import. Exact names
 * only: github.com.example.test contains "github.com" too. No server imports,
 * so the import dialog can use it.
 */
const GITHUB_FAMILY_HOSTS = new Set([
  'github.com', 'www.github.com', 'api.github.com', 'raw.githubusercontent.com',
  'gist.github.com', 'codeload.github.com',
])

export function isGithubFamilyHost(host: string | null | undefined): boolean {
  return GITHUB_FAMILY_HOSTS.has(String(host || '').toLowerCase().replace(/\.$/, ''))
}

export function isGithubFamilyUrl(url: string): boolean {
  try {
    return isGithubFamilyHost(new URL(url).hostname)
  } catch {
    return false
  }
}
