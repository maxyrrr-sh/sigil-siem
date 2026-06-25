import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// Frontend is served separately and talks to the Sigil API via `/api/*`.
// In dev, proxy that to a local `sigil run` (override with SIGIL_API).
// In prod, an nginx reverse-proxy plays the same role (see deploy/).
const API_TARGET = process.env.SIGIL_API ?? 'http://127.0.0.1:8080'

// Pass `/api/*` through unchanged — the backend serves the versioned API under
// `/api/v1`. SSE needs buffering disabled.
const proxy = {
  '/api': {
    target: API_TARGET,
    changeOrigin: true,
  },
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
})
