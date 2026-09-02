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
