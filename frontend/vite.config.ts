import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  server: {
    watch: {
      // Same reasoning as WATCHFILES_FORCE_POLLING in docker-compose.yml's
      // backend service — OS-level file-change events don't reliably cross
      // a Docker bind mount on Windows/WSL2, so Vite's default watcher can
      // miss edits. Only matters inside the container; harmless natively.
      usePolling: true,
    },
  },
});
