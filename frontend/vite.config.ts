import { defineConfig, createLogger } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Suppress noisy backend-offline errors so the terminal stays clean when
// the FastAPI server isn't running yet. The patterns below cover both the
// HTTP proxy and the WebSocket upgrade path.
const SUPPRESS = ['ECONNREFUSED', 'ECONNABORTED', 'ECONNRESET', 'ws proxy socket error'];

const logger = createLogger();
const _warn  = logger.warn.bind(logger);
const _error = logger.error.bind(logger);
logger.warn  = (msg, opts) => { if (!SUPPRESS.some(p => msg.includes(p))) _warn(msg, opts); };
logger.error = (msg, opts) => { if (!SUPPRESS.some(p => msg.includes(p))) _error(msg, opts); };

export default defineConfig({
  customLogger: logger,
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
        configure: (proxy) => {
          // Catch http-proxy 'error' events (HTTP path).
          proxy.on('error', (err: NodeJS.ErrnoException) => {
            if (!SUPPRESS.some(p => p === err.code)) {
              console.warn('[proxy]', err.message);
            }
          });
          // Catch raw socket errors on the WebSocket upgrade path.
          proxy.on('proxyReqWs', (_req, _socket, _head, _opts, _proxyReq) => {
            (_proxyReq as unknown as NodeJS.EventEmitter)?.on?.('error', () => {});
          });
        },
      },
    },
  },
});
