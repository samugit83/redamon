import {
  Activity, FolderKanban, KeyRound, ScrollText, Server, Share2, UserCog, Users,
  type LucideIcon,
} from 'lucide-react'
import type { ConsoleSectionId } from './consoleSections'

// Kept out of consoleSections.ts so that list stays plain data its tests read without React.
export const SECTION_ICONS: Record<ConsoleSectionId, LucideIcon> = {
  users: Users,
  'permission-sets': KeyRound,
  'admin-profiles': UserCog,
  projects: FolderKanban,
  shares: Share2,
  operations: Activity,
  audit: ScrollText,
  instance: Server,
}
