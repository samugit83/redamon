import { describe, test, expect } from 'vitest'
import { isGithubFamilyHost, isGithubFamilyUrl } from './githubHosts'
import { redactUrl } from './redactUrl'

describe('isGithubFamilyHost', () => {
  test('exact hosts only', () => {
    for (const h of ['github.com', 'WWW.GitHub.com', 'api.github.com', 'raw.githubusercontent.com', 'gist.github.com', 'codeload.github.com']) {
      expect(isGithubFamilyHost(h)).toBe(true)
    }
    for (const h of ['github.com.example.test', 'evilgithub.com', 'gitlab.com', '', undefined, 'gist.githubusercontent.com']) {
      expect(isGithubFamilyHost(h)).toBe(false)
    }
    expect(isGithubFamilyUrl('https://github.com.example.test/o/r')).toBe(false)
    expect(isGithubFamilyUrl('not a url')).toBe(false)
  })
})

describe('redactUrl', () => {
  test('redactUrl strips userinfo, query and fragment', () => {
    expect(redactUrl('https://u:p@Example.TEST:8443/a/b?token=x#f')).toBe('https://example.test:8443/a/b')
    expect(redactUrl('nope')).toBe('<unparseable url>')
  })
})
