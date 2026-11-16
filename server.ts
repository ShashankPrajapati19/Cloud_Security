import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDatabase } from './src/server/db';
import { apiRouter } from './src/server/api';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  // Initialize SQLite database schema and seed data
  initDatabase();
  console.log('[CloudGuard DB] SQLite database initialized and seeded successfully.');

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Mount backend API routes
  app.use('/api', apiRouter);

  // In development, mount Vite middleware
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        host: '0.0.0.0',
        port: PORT
      },
      appType: 'spa'
    });

    app.use(vite.middlewares);
    console.log('[CloudGuard Dev] Vite dev middleware mounted on Express.');
  } else {
    // In production, serve static built files
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CloudGuard Server] Cloud Security Auditor running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[CloudGuard Server Error]', err);
  process.exit(1);
});
