// `npm run lint`. Next 16 removed `next lint`, so ESLint runs directly on Next's own flat
// configs (core web vitals + TypeScript), the ones `next lint` applied.
import { defineConfig, globalIgnores } from 'eslint/config'
import nextVitals from 'eslint-config-next/core-web-vitals'
import nextTs from 'eslint-config-next/typescript'

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    // Test doubles: mocks are typed loosely on purpose, and the small components a test
    // renders inline need no display name.
    files: ['**/*.test.ts', '**/*.test.tsx', '**/__testing__/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'react/display-name': 'off',
    },
  },
  {
    // CommonJS has no import statement: require() is how these files load modules.
    files: ['**/*.cjs'],
    rules: { '@typescript-eslint/no-require-imports': 'off' },
  },
  globalIgnores(['.next/**', 'out/**', 'build/**', 'coverage/**', 'next-env.d.ts']),
])
