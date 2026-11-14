import type { LucideIcon } from 'lucide-react'

/**
 * A user-management action button's content: an icon and the words. The words stay in the DOM so
 * they name the button for assistive technology and tests; the Users page table hides them and
 * shows them as the tooltip, other screens show them next to the icon.
 */
export function ActionLabel({ icon: Icon, children }: { icon: LucideIcon; children: string }) {
  return (
    <>
      <Icon size={14} aria-hidden="true" />
      <span>{children}</span>
    </>
  )
}
