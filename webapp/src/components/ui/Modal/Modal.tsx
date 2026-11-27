'use client'

import { createContext, useContext, useEffect, useCallback, useId, useRef, ReactNode, KeyboardEvent } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import styles from './Modal.module.css'

interface OpenModalEntry {
  id: symbol
  depth: number
  seq: number
}

const ModalDepthContext = createContext(0)
const openModalStack: OpenModalEntry[] = []
let nextModalSeq = 0
const inertBeforeModal = new Map<HTMLElement, boolean>()
let savedBodyOverflow: string | null = null

const INERT_SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEMPLATE', 'LINK', 'NOSCRIPT'])
const LIVE_OR_OVERLAY_SELECTOR =
  '[role="alert"], [role="status"], [aria-live], [role="tooltip"], [role="menu"]'

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

function isTopmost(id: symbol): boolean {
  if (openModalStack.length === 0) return false
  // React mounts nested child effects before parents, so deeper JSX nesting wins ties over mount order.
  let top = openModalStack[0]
  for (let i = 1; i < openModalStack.length; i++) {
    const cur = openModalStack[i]
    if (cur.depth > top.depth || (cur.depth === top.depth && cur.seq > top.seq)) {
      top = cur
    }
  }
  return top.id === id
}

function lockBackground(): void {
  savedBodyOverflow = document.body.style.overflow
  document.body.style.overflow = 'hidden'

  for (const child of Array.from(document.body.children)) {
    if (!(child instanceof HTMLElement)) continue
    if (child.matches('[data-modal-overlay="true"]')) continue
    if (INERT_SKIP_TAGS.has(child.tagName)) continue
    if (child.matches(LIVE_OR_OVERLAY_SELECTOR)) continue

    const prevInert = Boolean(child.inert || child.hasAttribute('inert'))
    inertBeforeModal.set(child, prevInert)
    child.inert = true
    child.setAttribute('inert', '')
  }
}

function unlockBackground(): void {
  document.body.style.overflow = savedBodyOverflow ?? ''
  savedBodyOverflow = null

  inertBeforeModal.forEach((prev, el) => {
    el.inert = prev
    if (!prev) {
      el.removeAttribute('inert')
    }
  })
  inertBeforeModal.clear()
}

function getFocusableElements(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((el) => {
    if (el.hidden || el.hasAttribute('hidden')) return false
    if (el.closest('[inert]')) return false
    const style = window.getComputedStyle(el)
    if (style.display === 'none' || style.visibility === 'hidden') return false
    return true
  })
}

function handleModalTabKey(
  e: { shiftKey: boolean; preventDefault: () => void },
  modalEl: HTMLElement | null
): void {
  if (!modalEl) return
  const focusables = getFocusableElements(modalEl)
  if (focusables.length === 0) {
    e.preventDefault()
    modalEl.focus()
    return
  }

  const first = focusables[0]
  const last = focusables[focusables.length - 1]
  const active = document.activeElement

  if (e.shiftKey) {
    if (active === first || active === modalEl || !modalEl.contains(active)) {
      e.preventDefault()
      last.focus()
    }
  } else if (active === last || !modalEl.contains(active)) {
    e.preventDefault()
    first.focus()
  }
}

interface ModalProps {
  /** Whether the modal is open */
  isOpen: boolean
  /** Callback when modal should close */
  onClose: () => void
  /** Modal title */
  title?: string
  /** Modal content */
  children: ReactNode
  /** Footer content (typically buttons) */
  footer?: ReactNode
  /** Size variant */
  size?: 'small' | 'default' | 'large' | 'xlarge' | 'full'
  /** Whether clicking overlay closes the modal */
  closeOnOverlayClick?: boolean
  /** Whether pressing Escape closes the modal */
  closeOnEscape?: boolean
  /** Whether to show the close button */
  showCloseButton?: boolean
  /** Optional actions rendered in the header (between title and close button) */
  headerActions?: ReactNode
  /** Optional extra class applied to the modal container (e.g. for custom sizing) */
  className?: string
}

export function Modal({
  isOpen,
  onClose,
  title,
  children,
  footer,
  size = 'default',
  closeOnOverlayClick = true,
  closeOnEscape = true,
  showCloseButton = true,
  headerActions,
  className,
}: ModalProps) {
  // Per instance: modals can be open together (an alert over a dialog), and a shared id
  // would name every one of them after the first title in the page.
  const titleId = useId()
  const depth = useContext(ModalDepthContext) + 1
  const overlayRef = useRef<HTMLDivElement>(null)
  const modalRef = useRef<HTMLDivElement>(null)
  const modalIdRef = useRef<symbol | null>(null)
  const previousActiveElement = useRef<HTMLElement | null>(null)
  const pressStartedOnOverlay = useRef(false)
  const onCloseRef = useRef(onClose)
  const closeOnEscapeRef = useRef(closeOnEscape)
  const depthRef = useRef(depth)

  useEffect(() => {
    onCloseRef.current = onClose
    closeOnEscapeRef.current = closeOnEscape
    depthRef.current = depth
  }, [onClose, closeOnEscape, depth])

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      // React bubbles portal synthetic events up the JSX tree; ignore events from nested portals.
      if (e.target instanceof Node && overlayRef.current && !overlayRef.current.contains(e.target)) {
        return
      }
      const modalId = modalIdRef.current
      if (!modalId || !isTopmost(modalId) || e.defaultPrevented) return

      if (e.key === 'Escape') {
        e.stopPropagation()
        if (closeOnEscape) {
          e.preventDefault()
          onClose()
        }
        return
      }

      if (e.key === 'Tab') {
        handleModalTabKey(e, modalRef.current)
      }
    },
    [closeOnEscape, onClose]
  )

  const handleOverlayMouseDown = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    pressStartedOnOverlay.current = e.target === e.currentTarget
  }, [])

  // A press that starts inside the dialog and is released over the backdrop
  // gets its click dispatched to their common ancestor - the overlay. That
  // happens on a text-selection drag, and on a plain click into a field when a
  // password manager draws its icon over it. Only a press that began on the
  // backdrop counts as "clicked outside".
  const handleOverlayClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const startedOnOverlay = pressStartedOnOverlay.current
      pressStartedOnOverlay.current = false
      if (closeOnOverlayClick && startedOnOverlay && e.target === e.currentTarget) {
        onClose()
      }
    },
    [closeOnOverlayClick, onClose]
  )

  // Focus trap, modal stack coordination, and body scroll/inert lock
  useEffect(() => {
    if (!isOpen) return

    if (!modalIdRef.current) {
      modalIdRef.current = Symbol('modal')
    }
    const modalId = modalIdRef.current

    previousActiveElement.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null

    openModalStack.push({ id: modalId, depth: depthRef.current, seq: ++nextModalSeq })
    if (openModalStack.length === 1) {
      lockBackground()
    }

    // An autoFocus field inside has already taken focus by now; keep it there.
    if (!modalRef.current?.contains(document.activeElement)) {
      modalRef.current?.focus()
    }

    const handleDocumentKeyDown = (e: globalThis.KeyboardEvent) => {
      if (!isTopmost(modalId) || e.defaultPrevented) return
      if (e.target instanceof Node && overlayRef.current?.contains(e.target)) return

      if (e.key === 'Escape') {
        if (closeOnEscapeRef.current) {
          e.preventDefault()
          onCloseRef.current()
        }
        return
      }

      if (e.key === 'Tab') {
        handleModalTabKey(e, modalRef.current)
      }
    }

    document.addEventListener('keydown', handleDocumentKeyDown)

    return () => {
      document.removeEventListener('keydown', handleDocumentKeyDown)

      const idx = openModalStack.findIndex((entry) => entry.id === modalId)
      if (idx !== -1) {
        openModalStack.splice(idx, 1)
        if (openModalStack.length === 0) {
          unlockBackground()
        }
      }

      if (previousActiveElement.current?.isConnected) {
        previousActiveElement.current.focus()
      }
    }
  }, [isOpen])

  if (!isOpen) return null

  const sizeClass = {
    small: styles.modalSmall,
    default: '',
    large: styles.modalLarge,
    xlarge: styles.modalXLarge,
    full: styles.modalFull,
  }[size]

  const modalContent = (
    <div
      ref={overlayRef}
      data-modal-overlay="true"
      className={styles.overlay}
      onMouseDown={handleOverlayMouseDown}
      onClick={handleOverlayClick}
      onKeyDown={handleKeyDown}
      role="presentation"
    >
      <div
        ref={modalRef}
        className={`${styles.modal} ${sizeClass}${className ? ` ${className}` : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        tabIndex={-1}
      >
        {(title || showCloseButton) && (
          <div className={styles.header}>
            {title && (
              <h2 id={titleId} className={styles.title}>
                {title}
              </h2>
            )}
            {headerActions && <div style={{ marginLeft: 'auto', marginRight: '8px' }}>{headerActions}</div>}
            {showCloseButton && (
              <button
                type="button"
                className={styles.closeButton}
                onClick={onClose}
                aria-label="Close modal"
              >
                <X size={14} />
              </button>
            )}
          </div>
        )}

        <div className={styles.body}>{children}</div>

        {footer && <div className={styles.footer}>{footer}</div>}
      </div>
    </div>
  )

  // Render in portal
  if (typeof document !== 'undefined') {
    return createPortal(
      <ModalDepthContext.Provider value={depth}>{modalContent}</ModalDepthContext.Provider>,
      document.body
    )
  }

  return null
}
