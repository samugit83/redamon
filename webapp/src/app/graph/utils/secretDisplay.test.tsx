/**
 * The graph views show a secret as its last four characters with a copy button
 * and open a full link, secret included.
 * Run: npx vitest run src/app/graph/utils/secretDisplay.test.tsx
 */
import { afterEach, describe, expect, test } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { getNodeUrl } from './nodeHelpers'
import { propertyTitle, renderPropertyValue } from './renderPropertyValue'
import { isSecretValueProp } from '@/lib/secrets/secretProps'
import type { GraphNode } from '../types'

afterEach(cleanup)

const KEY = 'ak9Q2w8E3r7T4y6U1i0O5pLz'
const node = (type: string, properties: Record<string, unknown>): GraphNode =>
  ({ id: '1', type, name: 'n', properties }) as GraphNode

describe('which properties are secrets', () => {
  test('the display-only values, and matched_text on a Secret only', () => {
    expect(isSecretValueProp('secret_value')).toBe(true)
    expect(isSecretValueProp('paired_secret', 'Secret')).toBe(true)
    expect(isSecretValueProp('secret_values', 'Vulnerability')).toBe(true)
    expect(isSecretValueProp('matched_text', 'Secret')).toBe(true)
    expect(isSecretValueProp('matched_text', 'JsReconFinding')).toBe(false)
    expect(isSecretValueProp('unmasked_url', 'Secret')).toBe(false)
  })
})

describe('renderPropertyValue', () => {
  test('a secret shows its last four characters and a copy button, never the rest', () => {
    const { container } = render(<>{renderPropertyValue(KEY, 'secret_value', 'Secret')}</>)
    expect(screen.getByText('••••5pLz')).toBeTruthy()
    expect(screen.getByTitle('Copy full value')).toBeTruthy()
    expect(container.innerHTML).not.toContain('ak9Q2w8E')
  })

  test('a list of secrets gives one value each', () => {
    render(<>{renderPropertyValue([KEY, 'zz-other-1234'], 'secret_values', 'Vulnerability')}</>)
    expect(screen.getAllByTitle('Copy full value')).toHaveLength(2)
    expect(screen.getByText('••••1234')).toBeTruthy()
  })

  test('a full link is a link that opens whole', () => {
    const url = `https://app.example.test/api?apikey=${KEY}`
    render(<>{renderPropertyValue(url, 'unmasked_url', 'Secret')}</>)
    expect(screen.getByRole('link').getAttribute('href')).toBe(url)
  })

  test('a secret cell has no tooltip with the value', () => {
    expect(propertyTitle(KEY, 'secret_value', 'Secret')).toBe('')
    expect(propertyTitle('plain', 'name', 'Secret')).toBe('plain')
  })
})

describe('getNodeUrl', () => {
  test('prefers the full link over the masked one', () => {
    const full = 'https://auth.example.test/reset?token=Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd'
    expect(getNodeUrl(node('Vulnerability', { url: 'https://auth.example.test/reset?token=***', unmasked_url: full })))
      .toBe(full)
    expect(getNodeUrl(node('Endpoint', {
      method: 'GET', baseurl: 'https://auth.example.test', path: '/reset/{token}', unmasked_url: full,
    }))).toBe(full)
  })

  test('without a full link, the usual URL', () => {
    expect(getNodeUrl(node('Vulnerability', { url: 'https://a.example.test/x' }))).toBe('https://a.example.test/x')
  })
})
