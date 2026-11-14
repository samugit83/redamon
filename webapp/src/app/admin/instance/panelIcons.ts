import {
  Bot, FileCode, Gauge, Globe, History, Network, Puzzle, Radar, Share2, ShieldCheck, UserPlus, Wrench,
  type LucideIcon,
} from 'lucide-react'
import type { PanelId } from './instanceView'

export const PANEL_ICONS: Record<PanelId, LucideIcon> = {
  security: ShieldCheck,
  'public-url': Globe,
  sharing: Share2,
  retention: History,
  'default-set': UserPlus,
  'llm-providers': Bot,
  quotas: Gauge,
  tunnels: Network,
  traffic: Radar,
  nuclei: FileCode,
  plugins: Puzzle,
  'other-tools': Wrench,
}
