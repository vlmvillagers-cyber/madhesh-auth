/**
 * MADHESH ON TOP - Authentication Backend Server
 * 
 * Secure backend API for KeyAuth license validation and session management.
 * Protects KeyAuth credentials from client-side inspection.
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Strict body parsing limits to mitigate DoS / payload tampering
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// CORS configuration
// Restrict to allowed origin or allow chrome-extension:// origins
const allowedOrigin = process.env.ALLOWED_ORIGIN || '*';
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigin === '*' || origin === allowedOrigin || origin.startsWith('chrome-extension://')) {
      callback(null, true);
    } else {
      callback(new Error('CORS_NOT_ALLOWED'));
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Basic rate limiting to prevent brute force license guessing
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    authenticated: false,
    error: 'TOO_MANY_REQUESTS',
    message: 'Too many requests. Please try again later.'
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'madhesh-auth-backend',
    timestamp: new Date().toISOString()
  });
});

// Mount authentication routes under rate limiter
app.use('/api/auth', authLimiter, authRoutes);

// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'NOT_FOUND',
    message: 'Endpoint not found.'
  });
});

// Centralized generic error handler (Never leak stack traces in responses)
app.use((err, req, res, next) => {
  const safeMessage = err.message === 'CORS_NOT_ALLOWED' 
    ? 'Cross-origin request blocked.' 
    : 'Internal server error.';
  
  res.status(err.status || 500).json({
    success: false,
    authenticated: false,
    error: 'SERVER_ERROR',
    message: safeMessage
  });
});

// Start HTTP server on 0.0.0.0 to accept connections from localhost and 127.0.0.1
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MADHESH AUTH BACKEND] Listening on http://localhost:${PORT} and http://127.0.0.1:${PORT}`);
  console.log(`[MADHESH AUTH BACKEND] Ready for extension license verification.`);
});

module.exports = { app, server };
