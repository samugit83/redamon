'use client'

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  ReactNode,
} from 'react'
import { Modal } from '../Modal'
import styles from './AlertModal.module.css'

type AlertType = 'info' | 'error' | 'warning' | 'confirm' | 'danger-confirm'

interface AlertState {
  type: AlertType
  title?: string
  message: string
  resolve: (value: boolean) => void
}

interface AlertContextValue {
  /** Show an informational alert modal. Returns a promise that resolves when dismissed. */
  alert: (message: string, title?: string) => Promise<void>
  /** Show an error alert modal. Returns a promise that resolves when dismissed. */
  alertError: (message: string, title?: string) => Promise<void>
  /** Show a warning alert modal. Returns a promise that resolves when dismissed. */
  alertWarning: (message: string, title?: string) => Promise<void>
  /** Show a confirmation modal. Returns true if confirmed, false if cancelled. */
  confirm: (message: string, title?: string) => Promise<boolean>
  /** Show a destructive confirmation modal (red confirm button). Returns true if confirmed. */
  dangerConfirm: (message: string, title?: string) => Promise<boolean>
}

const AlertContext = createContext<AlertContextValue | null>(null)

export function useAlertModal() {
  const context = useContext(AlertContext)
  if (!context) {
    throw new Error('useAlertModal must be used within an AlertProvider')
  }
  return context
}

interface AlertProviderProps {
  children: ReactNode
}

export function AlertProvider({ children }: AlertProviderProps) {
  const [current, setCurrent] = useState<AlertState | null>(null)
  const queueRef = useRef<AlertState[]>([])

  const showNext = useCallback(() => {
    if (queueRef.current.length > 0) {
      setCurrent(queueRef.current.shift()!)
    } else {
      setCurrent(null)
    }
  }, [])

  const enqueue = useCallback(
    (type: AlertType, message: string, title?: string): Promise<boolean> => {
      return new Promise<boolean>((resolve) => {
        const state: AlertState = { type, title, message, resolve }
        if (current) {
          queueRef.current.push(state)
        } else {
          setCurrent(state)
        }
      })
    },
    [current]
  )

  const alert = useCallback(
    (message: string, title?: string) =>
      enqueue('info', message, title).then(() => {}),
    [enqueue]
  )

  const alertError = useCallback(
    (message: string, title?: string) =>
      enqueue('error', message, title ?? 'Error').then(() => {}),
    [enqueue]
  )

  const alertWarning = useCallback(
    (message: string, title?: string) =>
      enqueue('warning', message, title ?? 'Warning').then(() => {}),
    [enqueue]
  )

  const confirmFn = useCallback(
    (message: string, title?: string) =>
      enqueue('confirm', message, title ?? 'Confirm'),
    [enqueue]
  )

  const dangerConfirm = useCallback(
    (message: string, title?: string) =>
      enqueue('danger-confirm', message, title ?? 'Confirm'),
    [enqueue]
  )

  const handleResolve = useCallback(
    (value: boolean) => {
      current?.resolve(value)
      showNext()
    },
    [current, showNext]
  )

  const isConfirm = current?.type === 'confirm' || current?.type === 'danger-confirm'

  return (
    <AlertContext.Provider
      value={{ alert, alertError, alertWarning, confirm: confirmFn, dangerConfirm }}
    >
      {children}
      <Modal
        isOpen={!!current}
        onClose={() => handleResolve(false)}
        title={current?.title}
        size="small"
        closeOnOverlayClick={!isConfirm}
        showCloseButton={!isConfirm}
        footer={
          current && (
            <div className={styles.actions}>
              {isConfirm ? (
                <>
                  <button
                    type="button"
                    className={styles.btnSecondary}
                    onClick={() => handleResolve(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className={
                      current.type === 'danger-confirm'
                        ? styles.btnDanger
                        : styles.btnPrimary
                    }
                    onClick={() => handleResolve(true)}
                  >
                    Confirm
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className={styles.btnPrimary}
                  onClick={() => handleResolve(true)}
                >
                  OK
                </button>
              )}
            </div>
          )
        }
      >
        {current && <p className={styles.message}>{current.message}</p>}
      </Modal>
    </AlertContext.Provider>
  )
}
