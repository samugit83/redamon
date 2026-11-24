import {
  Bot, Compass, FileCode, Gauge, Globe, History, Share2, ShieldCheck, UserPlus,
  type LucideIcon,
} from 'lucide-react'
import type { PanelId } from './instanceView'

export const PANEL_ICONS: Record<PanelId, LucideIcon> = {
  security: ShieldCheck,
  'public-url': Globe,
  sharing: Share2,
  retention: History,
  navigator: Compass,
  'default-set': UserPlus,
  'llm-providers': Bot,
  quotas: Gauge,
  nuclei: FileCode,
}
