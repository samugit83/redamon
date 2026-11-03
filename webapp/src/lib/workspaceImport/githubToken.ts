/**
 * The signed-in user's GitHub token for a URL import, read on the server. It is
 * sent to the agent only for a GitHub link; the agent attaches it only on hops
 * to an exact GitHub host over https. Server-side only (Prisma).
 */
import prisma from '@/lib/prisma'
import { isGithubFamilyUrl } from './githubHosts'

export async function githubTokenForImport(userId: string, url: string): Promise<string> {
  if (!isGithubFamilyUrl(url)) return ''
  const settings = await prisma.userSettings.findUnique({
    where: { userId },
    select: { githubAccessToken: true },
  })
  return settings?.githubAccessToken || ''
}
