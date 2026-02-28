import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/projects': 'http://localhost:9000',
      '/scans': 'http://localhost:9000',
      '/health': 'http://localhost:9000',
    }
  }
})
