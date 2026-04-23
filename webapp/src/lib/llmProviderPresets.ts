/**
 * Presets for OpenAI-Compatible LLM provider base URLs.
 */
export interface LlmProviderPreset {
  name: string
  baseUrl: string
  description: string
}

export const OPENAI_COMPAT_PRESETS: LlmProviderPreset[] = [
  {
    name: 'Ollama',
    baseUrl: 'http://host.docker.internal:11434/v1',
    description: 'Local Ollama server',
  },
  {
    name: 'vLLM',
    baseUrl: 'http://host.docker.internal:8000/v1',
    description: 'vLLM inference server',
  },
  {
    name: 'LM Studio',
    baseUrl: 'http://host.docker.internal:1234/v1',
    description: 'LM Studio local server',
  },
  {
    name: 'Groq',
    baseUrl: 'https://api.groq.com/openai/v1',
    description: 'Groq cloud inference',
  },
  {
    name: 'Together AI',
    baseUrl: 'https://api.together.xyz/v1',
    description: 'Together AI cloud',
  },
  {
    name: 'Fireworks AI',
    baseUrl: 'https://api.fireworks.ai/inference/v1',
    description: 'Fireworks AI cloud',
  },
  {
    name: 'Mistral AI',
    baseUrl: 'https://api.mistral.ai/v1',
    description: 'Mistral AI cloud',
  },
  {
    name: 'Deepinfra',
    baseUrl: 'https://api.deepinfra.com/v1/openai',
    description: 'Deepinfra cloud',
  },
  {
    name: 'Custom',
    baseUrl: '',
    description: 'Enter a custom base URL',
  },
]

export const PROVIDER_TYPES = [
  { id: 'openai', name: 'OpenAI', description: 'Direct OpenAI API access', icon: '🟢' },
  { id: 'anthropic', name: 'Anthropic', description: 'Direct Anthropic API access', icon: '🟠' },
  { id: 'openrouter', name: 'OpenRouter', description: 'Access 200+ models via OpenRouter', icon: '🔵' },
  { id: 'bedrock', name: 'AWS Bedrock', description: 'AWS Bedrock foundation models', icon: '🟡' },
  { id: 'openai_compatible', name: 'OpenAI-Compatible', description: 'Any OpenAI-compatible endpoint (Ollama, vLLM, Groq, etc.)', icon: '⚙️' },
] as const

export type ProviderType = typeof PROVIDER_TYPES[number]['id']
