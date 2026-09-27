/**
 * Authentication Routes
 * 
 * Endpoints for license activation, session verification, and logout.
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const keyauthService = require('../services/keyauth');

// Session storage with expiry
// In production or multi-instance deployments, this can be backed by Redis
const sessions = new Map();

const SESSION_DURATION_MS = (parseInt(process.env.SESSION_DURATION_SECONDS, 10) || 86400) * 1000;

// Periodic cleanup of expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(token);
    }
  }
}, 300000); // Every 5 minutes

/**
 * Generate a cryptographically secure random session token
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * POST /api/auth/activate
 * Validates a license key with KeyAuth and creates a new session.
 */
router.post('/activate', async (req, res) => {
  try {
    const { license } = req.body || {};

    if (!license || typeof license !== 'string' || !license.trim()) {
      return res.status(400).json({
        success: false,
        authenticated: false,
        error: 'INVALID_LICENSE',
        message: 'Invalid license key.'
      });
    }

    const trimmedLicense = license.trim();

    // Call KeyAuth adapter to validate
    const result = await keyauthService.validateLicense(trimmedLicense);

    if (!result.success) {
      return res.status(200).json({
        success: false,
        authenticated: false,
        error: result.error || 'INVALID_LICENSE',
        message: result.message || 'Invalid license key.'
      });
    }

    // Generate secure session token
    const sessionToken = generateSessionToken();
    const expiresAt = Date.now() + SESSION_DURATION_MS;

    sessions.set(sessionToken, {
      createdAt: Date.now(),
      expiresAt,
      licenseMetadata: result.license || {
        expiry: new Date(expiresAt).toISOString(),
        username: 'KeyAuth User'
      }
    });

    return res.status(200).json({
      success: true,
      authenticated: true,
      sessionToken,
      license: result.license || {
        expiry: new Date(expiresAt).toISOString(),
        username: 'KeyAuth User'
      }
    });
  } catch (err) {
    // Fail-closed: Never reveal internal error details
    return res.status(500).json({
      success: false,
      authenticated: false,
      error: 'SERVER_ERROR',
      message: 'Authentication service unavailable.'
    });
  }
});

/**
 * POST /api/auth/verify
 * Verifies if an existing session token is valid and active.
 */
router.post('/verify', async (req, res) => {
  try {
    const { sessionToken } = req.body || {};

    if (!sessionToken || typeof sessionToken !== 'string') {
      return res.status(200).json({
        success: false,
        authenticated: false,
        error: 'INVALID_SESSION',
        message: 'No session token provided.'
      });
    }

    const session = sessions.get(sessionToken);

    if (!session) {
      return res.status(200).json({
        success: false,
        authenticated: false,
        error: 'INVALID_SESSION',
        message: 'Session not found or expired.'
      });
    }

    if (Date.now() >= session.expiresAt) {
      sessions.delete(sessionToken);
      return res.status(200).json({
        success: false,
        authenticated: false,
        error: 'EXPIRED_SESSION',
        message: 'Session has expired.'
      });
    }

    return res.status(200).json({
      success: true,
      authenticated: true,
      license: session.licenseMetadata
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      authenticated: false,
      error: 'SERVER_ERROR',
      message: 'Authentication service unavailable.'
    });
  }
});

/**
 * POST /api/auth/logout
 * Destroys an active session.
 */
router.post('/logout', (req, res) => {
  try {
    const { sessionToken } = req.body || {};

    if (sessionToken && typeof sessionToken === 'string') {
      sessions.delete(sessionToken);
    }

    return res.status(200).json({
      success: true,
      authenticated: false,
      message: 'Logged out successfully.'
    });
  } catch (err) {
    return res.status(200).json({
      success: true,
      authenticated: false
    });
  }
});

module.exports = router;
