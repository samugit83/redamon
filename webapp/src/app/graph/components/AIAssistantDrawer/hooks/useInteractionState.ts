import { useState, useRef } from 'react'
import type { ApprovalRequestPayload, QuestionRequestPayload, ToolConfirmationRequestPayload } from '@/lib/websocket-types'

export function useInteractionState() {
  // Approval state
  const [awaitingApproval, setAwaitingApproval] = useState(false)
  const [approvalRequest, setApprovalRequest] = useState<ApprovalRequestPayload | null>(null)
  const [modificationText, setModificationText] = useState('')

  // Tool confirmation state
  const [awaitingToolConfirmation, setAwaitingToolConfirmation] = useState(false)
  const [toolConfirmationRequest, setToolConfirmationRequest] = useState<ToolConfirmationRequestPayload | null>(null)

  // Q&A state
  const [awaitingQuestion, setAwaitingQuestion] = useState(false)
  const [questionRequest, setQuestionRequest] = useState<QuestionRequestPayload | null>(null)
  const [answerText, setAnswerText] = useState('')
  const [selectedOptions, setSelectedOptions] = useState<string[]>([])

  // Double-submit prevention refs
  const isProcessingApproval = useRef(false)
  const awaitingApprovalRef = useRef(false)
  const isProcessingQuestion = useRef(false)
  const awaitingQuestionRef = useRef(false)
  const isProcessingToolConfirmation = useRef(false)
  const awaitingToolConfirmationRef = useRef(false)
  const pendingApprovalToolId = useRef<string | null>(null)
  const pendingApprovalWaveId = useRef<string | null>(null)

  function resetInteractionState() {
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAwaitingToolConfirmation(false)
    setToolConfirmationRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    awaitingToolConfirmationRef.current = false
    isProcessingToolConfirmation.current = false
    pendingApprovalToolId.current = null
    pendingApprovalWaveId.current = null
  }

  return {
    // Approval
    awaitingApproval,
    setAwaitingApproval,
    approvalRequest,
    setApprovalRequest,
    modificationText,
    setModificationText,
    // Tool confirmation
    awaitingToolConfirmation,
    setAwaitingToolConfirmation,
    toolConfirmationRequest,
    setToolConfirmationRequest,
    // Q&A
    awaitingQuestion,
    setAwaitingQuestion,
    questionRequest,
    setQuestionRequest,
    answerText,
    setAnswerText,
    selectedOptions,
    setSelectedOptions,
    // Refs
    isProcessingApproval,
    awaitingApprovalRef,
    isProcessingQuestion,
    awaitingQuestionRef,
    isProcessingToolConfirmation,
    awaitingToolConfirmationRef,
    pendingApprovalToolId,
    pendingApprovalWaveId,
    // Reset
    resetInteractionState,
  }
}
