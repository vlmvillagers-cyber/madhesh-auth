/**
 * KeyAuth Service Adapter
 * 
 * Secure, server-side adapter for KeyAuth License Authentication.
 * Handles communication with KeyAuth API without exposing secrets to the client.
 * Supports official KeyAuth Manager platform (keyauth-manager.online) and keyauth.win.
 * 
 * SECURITY:
 * - Never log license keys, tokens, or KeyAuth secrets.
 * - Redact all sensitive fields before logging.
 * - Return normalized, generic status codes to callers.
 */

const https = require('https');
const crypto = require('crypto');

class KeyAuthService {
  constructor() {
    this.activeApiUrl = null;
    this.reloadConfig();
  }

  reloadConfig() {
    this.appName = (process.env.KEYAUTH_APP_NAME || '').replace(/^["']|["']$/g, '').trim();
    this.ownerId = (process.env.KEYAUTH_OWNER_ID || '').replace(/^["']|["']$/g, '').trim();
    this.appSecret = (process.env.KEYAUTH_APP_SECRET || '').replace(/^["']|["']$/g, '').trim();
    this.version = (process.env.KEYAUTH_VERSION || '1.0').replace(/^["']|["']$/g, '').trim();
    this.devTestLicense = (process.env.DEV_TEST_LICENSE || '').replace(/^["']|["']$/g, '').trim();
    this.apiUrl = (process.env.KEYAUTH_API_URL || 'https://keyauth-manager.online/api/1.3/').trim();
  }

  /**
   * Check if KeyAuth credentials are fully configured
   */
  isConfigured() {
    this.reloadConfig();
    return Boolean(
      this.appName && 
      this.ownerId && 
      this.appSecret &&
      !this.ownerId.includes('...') &&
      !this.appSecret.includes('...')
    );
  }

  /**
   * Helper to make secure HTTPS POST requests to KeyAuth endpoints
   * @param {string} urlString 
   * @param {Record<string, string>} postData 
   * @param {number} timeoutMs 
   * @returns {Promise<any>}
   */
  async _request(urlString, postData, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
      const url = new URL(urlString);
      const params = new URLSearchParams(postData).toString();

      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + (url.search ? url.search : ''),
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(params),
          'User-Agent': 'KeyAuth'
        },
        timeout: timeoutMs
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            resolve(parsed);
          } catch (err) {
            if (typeof body === 'string' && body.includes('KeyAuth_Invalid')) {
              reject(new Error('KEYAUTH_INVALID_CREDENTIALS'));
            } else {
              reject(new Error('INVALID_JSON_RESPONSE'));
            }
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('KEYAUTH_TIMEOUT'));
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.write(params);
      req.end();
    });
  }

  /**
   * Initialize a KeyAuth session (supports keyauth-manager.online and keyauth.win)
   * @returns {Promise<string>} sessionId
   */
  async _initSession() {
    const postData = {
      type: 'init',
      name: this.appName,
      ownerid: this.ownerId,
      ver: this.version
    };

    const endpoints = [
      this.apiUrl,
      'https://keyauth-manager.online/api/1.3/',
      'https://keyauth.win/api/1.3/'
    ];
    const uniqueEndpoints = [...new Set(endpoints)];

    let lastError = null;
    for (const endpoint of uniqueEndpoints) {
      try {
        const res = await this._request(endpoint, postData);
        if (res && res.success && res.sessionid) {
          this.activeApiUrl = endpoint;
          return res.sessionid;
        }
        if (res && res.message) {
          lastError = new Error(res.message);
        }
      } catch (err) {
        lastError = err;
      }
    }

    throw lastError || new Error('KEYAUTH_INIT_FAILED');
  }

  /**
   * Validate license key against KeyAuth
   * 
   * @param {string} licenseKey - The license key provided by the user
   * @returns {Promise<{
   *   success: boolean;
   *   error?: string;
   *   message?: string;
   *   license?: { expiry: string; username: string };
   * }>}
   */
  async validateLicense(licenseKey) {
    this.reloadConfig();

    // 1. Basic sanitization / validation
    if (!licenseKey || typeof licenseKey !== 'string') {
      return { success: false, error: 'INVALID_LICENSE', message: 'License key is required.' };
    }

    const trimmedKey = licenseKey.trim();
    if (trimmedKey.length < 1 || trimmedKey.length > 128) {
      return { success: false, error: 'INVALID_LICENSE', message: 'Invalid license format.' };
    }

    // 2. Optional Development / Test mode (supports single or comma-separated test keys)
    if (this.devTestLicense) {
      const testKeys = this.devTestLicense.split(',').map((k) => k.trim());
      if (testKeys.includes(trimmedKey)) {
        return {
          success: true,
          license: {
            expiry: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
            username: 'madhesh1'
          }
        };
      }
    }

    // 3. Verify that production KeyAuth credentials are set
    if (!this.isConfigured()) {
      return {
        success: false,
        error: 'SERVER_MISCONFIGURED',
        message: 'KeyAuth credentials are not configured on the authentication server. Please set real credentials in backend/.env'
      };
    }

    // 4. Official KeyAuth API integration
    try {
      // Step A: Initialize session with KeyAuth API
      const sessionId = await this._initSession();
      const endpoint = this.activeApiUrl || this.apiUrl;

      // Step B: Authenticate the license key
      const hwid = crypto.createHash('sha256').update(this.ownerId + trimmedKey).digest('hex');
      const licensePayload = {
        type: 'license',
        key: trimmedKey,
        sessionid: sessionId,
        name: this.appName,
        ownerid: this.ownerId,
        hwid: hwid
      };

      const res = await this._request(endpoint, licensePayload);

      if (res && res.success) {
        let expiry = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
        const rawExpiry = res.info?.subscriptions?.[0]?.expiry;
        if (rawExpiry && Number(rawExpiry) > 0) {
          expiry = new Date(Number(rawExpiry) * 1000).toISOString();
        }

        return {
          success: true,
          license: {
            expiry: expiry,
            username: res.info?.username || 'KeyAuth User'
          }
        };
      }

      // Handle KeyAuth responses securely
      const rawMsg = (res?.message || '').toLowerCase();
      if (rawMsg.includes('expired')) {
        return { success: false, error: 'EXPIRED_LICENSE', message: 'This license has expired.' };
      }
      if (rawMsg.includes('banned') || rawMsg.includes('disabled') || rawMsg.includes('paused')) {
        return { success: false, error: 'DISABLED_LICENSE', message: 'This license has been disabled.' };
      }
      if (rawMsg.includes('not found') || rawMsg.includes('invalid') || rawMsg.includes('doesn\'t exist')) {
        return { success: false, error: 'INVALID_LICENSE', message: 'Invalid license key.' };
      }

      return {
        success: false,
        error: 'INVALID_LICENSE',
        message: res?.message || 'Invalid license key.'
      };
    } catch (err) {
      let errCode = 'KEYAUTH_UNAVAILABLE';
      let message = 'Unable to connect to KeyAuth authentication server.';

      if (err.message === 'KEYAUTH_INVALID_CREDENTIALS') {
        errCode = 'INVALID_CREDENTIALS';
        message = 'Invalid KeyAuth credentials. Please verify your Owner ID and App Secret in Render Environment.';
      } else if (err.message === 'KEYAUTH_TIMEOUT') {
        errCode = 'NETWORK_ERROR';
        message = 'KeyAuth server timed out.';
      }

      return {
        success: false,
        error: errCode,
        message: message
      };
    }
  }
}

module.exports = new KeyAuthService();
