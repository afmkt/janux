/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'
import { resolve } from 'path'


// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    babel({ presets: [reactCompilerPreset()] })
  ],
  build: {
    rollupOptions: {
      input: {
        login: resolve(__dirname, 'login.html'),
        consent: resolve(__dirname, 'consent.html'),
        device: resolve(__dirname, 'device.html'),
        admin: resolve(__dirname, 'admin.html'),
      },
    },
  },
  // Vitest runs the unit/api suite (src/**/*.test.ts). The browser-driven
  // specs under e2e/*.spec.ts belong to Playwright (npm run e2e); letting
  // Vitest collect them makes it import @playwright/test, which rejects the
  // test.describe() calls (two runners fighting the same files).
  test: {
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'e2e/**',
      '**/.{idea,git,cache,output,temp}/**',
    ],
  },
  server: {
    proxy: {
      '/api': {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      '/.well-known': {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      '/authorize': {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      '/consent': {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      '/device-login': {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
})
