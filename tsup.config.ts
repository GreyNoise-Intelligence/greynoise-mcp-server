import { defineConfig } from 'tsup'
import { copyFileSync, existsSync, rmSync } from 'fs'
import { resolve } from 'path'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  outDir: 'build',
  clean: true,
  minify: false, // Keep readable for debugging
  sourcemap: true,
  bundle: true,
  splitting: false,
  banner: {
    js: '#!/usr/bin/env node'
  },
  onSuccess: async () => {
    // Clean up any extra directories from previous builds
    const extraDirs = ['build/prompts', 'build/tools', 'build/types', 'build/utils']
    extraDirs.forEach(dir => {
      if (existsSync(dir)) {
        rmSync(dir, { recursive: true, force: true })
      }
    })
    
    // Copy .env file if it exists
    const envPath = resolve('.env')
    const buildEnvPath = resolve('build/.env')
    
    if (existsSync(envPath)) {
      copyFileSync(envPath, buildEnvPath)
      console.log('✓ Copied .env to build directory')
    }
  },
  external: [
    // Node.js built-ins
    'fs',
    'path',
    'url',
    'stream',
    'util',
    'events',
    'buffer',
    'string_decoder',
    'querystring',
    'http',
    'https',
    'net',
    'tls',
    'crypto',
    'os',
    'child_process',
    'worker_threads',
    'zlib',
    'assert',
    'dns',
    'readline',
    'perf_hooks',
    // Express ecosystem - keep external due to dynamic require issues
    'express',
    'dotenv'
  ],
  noExternal: [
    // Bundle only these safe dependencies for standalone operation
    '@modelcontextprotocol/sdk',
    'node-fetch',
    'zod'
  ],
  esbuildOptions(options) {
    options.platform = 'node'
    options.packages = 'external'
  }
})