import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// En desarrollo, el backend corre con: sudo minired gui --origen-extra http://localhost:5173
const backend = 'http://127.0.0.1:8787';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 1500 },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: backend, changeOrigin: true },
      '/ws': { target: backend.replace('http', 'ws'), ws: true, changeOrigin: true },
    },
  },
  test: { environment: 'node' },
});
