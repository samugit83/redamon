import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',

  serverExternalPackages: ['neo4j-driver'],

  images: {
    remotePatterns: [],
  },

  env: {
    NEO4J_URI: process.env.NEO4J_URI,
    NEO4J_USER: process.env.NEO4J_USER,
    NEO4J_PASSWORD: process.env.NEO4J_PASSWORD,
  },
}

export default nextConfig
