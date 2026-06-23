import type { ComponentType, SVGProps } from 'react'
import { SiOpenai, SiAnthropic, SiGooglegemini } from 'react-icons/si'
import { FaAws } from 'react-icons/fa6'
import { LuSettings, LuSparkles } from 'react-icons/lu'
import { SiDeepseek, SiOpenrouter, SiMoonshot, SiQwen, SiXai, SiMistral } from '@/components/icons/ProviderBrandIcons'

/**
 * Presets for OpenAI-Compatible LLM provider base URLs.
 */
export interface LlmProviderPreset {
  name: string
  baseUrl: string
  description: string
}

export type ProviderIcon = ComponentType<SVGProps<SVGSVGElement> & { size?: number | string }>

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
    name: 'Atlas Cloud',
    baseUrl: 'https://api.atlascloud.ai/v1',
    description: 'Atlas Cloud — 300+ models via one OpenAI-compatible endpoint',
  },
  {
    name: 'Custom',
    baseUrl: '',
    description: 'Enter a custom base URL',
  },
]

export const PROVIDER_TYPES = [
  { id: 'openai', name: 'OpenAI', description: 'Direct OpenAI API access', Icon: SiOpenai as ProviderIcon, apiKeyUrl: 'https://platform.openai.com/api-keys' },
  { id: 'anthropic', name: 'Anthropic', description: 'Direct Anthropic API access', Icon: SiAnthropic as ProviderIcon, apiKeyUrl: 'https://console.anthropic.com/settings/keys' },
  { id: 'openrouter', name: 'OpenRouter', description: 'Access 200+ models via OpenRouter', Icon: SiOpenrouter as ProviderIcon, apiKeyUrl: 'https://openrouter.ai/settings/keys' },
  { id: 'deepseek', name: 'DeepSeek', description: 'Direct DeepSeek API access', Icon: SiDeepseek as ProviderIcon, apiKeyUrl: 'https://platform.deepseek.com/api_keys' },
  { id: 'gemini', name: 'Google Gemini', description: 'Direct Google AI Studio API access', Icon: SiGooglegemini as ProviderIcon, apiKeyUrl: 'https://aistudio.google.com/app/apikey' },
  { id: 'glm', name: 'GLM (Zhipu AI)', description: 'Chinese AI models with strong multilingual capabilities.', Icon: LuSparkles as ProviderIcon, apiKeyUrl: 'https://open.bigmodel.cn/usercenter/apikeys' },
  { id: 'kimi', name: 'Kimi (Moonshot)', description: 'Long-context models with up to 200k tokens support.', Icon: SiMoonshot as ProviderIcon, apiKeyUrl: 'https://platform.moonshot.ai/console/api-keys' },
  { id: 'qwen', name: 'Qwen (Alibaba)', description: 'Open-source models from Alibaba with strong reasoning.', Icon: SiQwen as ProviderIcon, apiKeyUrl: 'https://bailian.console.aliyun.com/?apiKey=1#/api-key' },
  { id: 'xai', name: 'xAI (Grok)', description: 'Grok models by xAI — state-of-the-art reasoning.', Icon: SiXai as ProviderIcon, apiKeyUrl: 'https://console.x.ai/' },
  { id: 'mistral', name: 'Mistral AI', description: 'Mistral models — open-weight and commercial.', Icon: SiMistral as ProviderIcon, apiKeyUrl: 'https://console.mistral.ai/api-keys/' },
  { id: 'bedrock', name: 'AWS Bedrock', description: 'AWS Bedrock foundation models', Icon: FaAws as ProviderIcon, apiKeyUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials' },
  { id: 'openai_compatible', name: 'OpenAI-Compatible', description: 'Any OpenAI-compatible endpoint (Ollama, vLLM, Groq, etc.)', Icon: LuSettings as ProviderIcon, apiKeyUrl: '' },
] as const

export type ProviderType = typeof PROVIDER_TYPES[number]['id']
