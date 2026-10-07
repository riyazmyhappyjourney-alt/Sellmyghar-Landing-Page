import express, { Request, Response, NextFunction } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { processLeadSubmission } from './src/server/leadService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Security Headers
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Request body limits to prevent payload bombs & buffer overruns
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// Handle JSON parsing errors safely without leaking internal stack traces
app.use((err: Error, _req: Request, res: Response, next: NextFunction) => {
  if (err && 'status' in err && (err as { status?: number }).status === 400) {
    return res.status(400).json({
      success: false,
      message: 'Malformed request payload.'
    });
  }
  next(err);
});

// Production-grade Lead Capture API Endpoint
app.post('/api/leads', async (req: Request, res: Response) => {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json') && !contentType.includes('application/x-www-form-urlencoded')) {
    return res.status(415).json({
      success: false,
      message: 'Unsupported Media Type. Please send application/json.'
    });
  }

  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || '';

  try {
    const result = await processLeadSubmission(req.body, clientIp, userAgent);
    return res.status(result.statusCode).json(result.response);
  } catch (err) {
    // Secure generic error to client, details kept internally
    console.error('Unhandled lead processing error:', err);
    return res.status(500).json({
      success: false,
      message: "We couldn't submit your request right now. Please try again."
    });
  }
});

// Reject unsupported HTTP methods on lead endpoint
app.all('/api/leads', (_req: Request, res: Response) => {
  res.status(405).json({
    success: false,
    message: 'Method Not Allowed'
  });
});

// Vite Middleware for SPA and Static Serving
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'dist')));
  app.get('/thank-you', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'dist/thank-you/index.html'));
  });
  app.get('*', (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'dist/index.html'));
  });
} else {
  const { createServer } = await import('vite');
  const vite = await createServer({
    server: { middlewareMode: true },
    appType: 'spa'
  });
  app.use(vite.middlewares);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Lead capture server running on port ${PORT}`);
});
