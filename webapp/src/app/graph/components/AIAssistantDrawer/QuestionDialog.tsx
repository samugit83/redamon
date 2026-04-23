'use client'

import React from 'react'
import { HelpCircle } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import type { QuestionRequestPayload } from '@/lib/websocket-types'
import styles from './AIAssistantDrawer.module.css'

interface QuestionDialogProps {
  awaitingQuestion: boolean
  questionRequest: QuestionRequestPayload | null
  answerText: string
  selectedOptions: string[]
  isLoading: boolean
  setAnswerText: (v: string) => void
  setSelectedOptions: (v: string[]) => void
  handleAnswer: () => void
}

export function QuestionDialog({
  awaitingQuestion,
  questionRequest,
  answerText,
  selectedOptions,
  isLoading,
  setAnswerText,
  setSelectedOptions,
  handleAnswer,
}: QuestionDialogProps) {
  if (!awaitingQuestion || !questionRequest) return null

  return (
    <div className={styles.questionDialog}>
      <div className={styles.questionHeader}>
        <HelpCircle size={16} />
        <span>Agent Question</span>
      </div>
      <div className={styles.questionContent}>
        <div className={styles.questionText}>
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              code({ className, children, ...props }: any) {
                const match = /language-(\w+)/.exec(className || '')
                const language = match ? match[1] : ''
                const isInline = !className

                return !isInline && language ? (
                  <SyntaxHighlighter
                    style={vscDarkPlus as any}
                    language={language}
                    PreTag="div"
                  >
                    {String(children).replace(/\n$/, '')}
                  </SyntaxHighlighter>
                ) : (
                  <code className={className} {...props}>
                    {children}
                  </code>
                )
              }
            }}
          >
            {questionRequest.question}
          </ReactMarkdown>
        </div>
        {questionRequest.context && (
          <div className={styles.questionContext}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {questionRequest.context}
            </ReactMarkdown>
          </div>
        )}

        {questionRequest.format === 'text' && (
          <textarea
            className={styles.answerInput}
            placeholder={questionRequest.default_value || 'Type your answer...'}
            value={answerText}
            onChange={(e) => setAnswerText(e.target.value)}
          />
        )}

        {questionRequest.format === 'single_choice' && questionRequest.options.length > 0 && (
          <div className={styles.optionsList}>
            {questionRequest.options.map((option, i) => (
              <label key={i} className={styles.optionRadio}>
                <input
                  type="radio"
                  name="question-option"
                  value={option}
                  checked={selectedOptions[0] === option}
                  onChange={() => setSelectedOptions([option])}
                />
                <span>{option}</span>
              </label>
            ))}
          </div>
        )}

        {questionRequest.format === 'multi_choice' && questionRequest.options.length > 0 && (
          <div className={styles.optionsList}>
            {questionRequest.options.map((option, i) => (
              <label key={i} className={styles.optionCheckbox}>
                <input
                  type="checkbox"
                  value={option}
                  checked={selectedOptions.includes(option)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedOptions([...selectedOptions, option])
                    } else {
                      setSelectedOptions(selectedOptions.filter(o => o !== option))
                    }
                  }}
                />
                <span>{option}</span>
              </label>
            ))}
          </div>
        )}
      </div>
      <div className={styles.questionActions}>
        <button
          className={`${styles.answerButton} ${styles.answerButtonSubmit}`}
          onClick={handleAnswer}
          disabled={isLoading || (questionRequest.format === 'text' ? !answerText.trim() : selectedOptions.length === 0)}
        >
          Submit Answer
        </button>
      </div>
    </div>
  )
}
