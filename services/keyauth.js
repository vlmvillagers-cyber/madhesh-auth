/**
 * KeyAuth Service Adapter
 * 
 * Secure, server-side adapter for KeyAuth License Authentication.
 * Handles communication with KeyAuth API without exposing secrets to the client.
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
    this.reloadConfig();
  }

  reloadConfig() {
    this.appName = (process.env.KEYAUTH_APP_NAME || '').replace(/^["']|["']$/g, '').trim();
    this.ownerId = (process.env.KEYAUTH_OWNER_ID || '').replace(/^["']|["']$/g, '').trim();
    this.appSecret = (process.env.KEYAUTH_APP_SECRET || '').replace(/^["']|["']$/g, '').trim();
    this.version = (process.env.KEYAUTH_VERSION || '1.0').replace(/^["']|["']$/g, '').trim();
    this.devTestLicense = (process.env.DEV_TEST_LICENSE || '').replace(/^["']|["']$/g, '').trim();
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
          'User-Agent': 'Madhesh-Auth-Backend/1.0'
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
            reject(new Error('INVALID_JSON_RESPONSE'));
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
   * Initialize a KeyAuth session (Official KeyAuth 1.3 flow)
   * @returns {Promise<string>} sessionId
   */
  async _initSession() {
    const postData = {
      type: 'init',
      name: this.appName,
      ownerid: this.ownerId,
      ver: this.version
    };

    if (this.appSecret) {
      postData.secret = this.appSecret;
    }

    const res = await this._request('https://keyauth.win/api/1.3/', postData);
    if (!res || !res.success || !res.sessionid) {
      throw new Error(res?.message || 'KEYAUTH_INIT_FAILED');
    }
    return res.sessionid;
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

      const res = await this._request('https://keyauth.win/api/1.3/', licensePayload);

      if (res && res.success) {
        const expiry = res.info?.subscriptions?.[0]?.expiry
          ? new Date(Number(res.info.subscriptions[0].expiry) * 1000).toISOString()
          : new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();

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
      const errCode = err.message === 'KEYAUTH_TIMEOUT' ? 'NETWORK_ERROR' : 'KEYAUTH_UNAVAILABLE';
      return {
        success: false,
        error: errCode,
        message: 'Unable to connect to KeyAuth authentication server.'
      };
    }
  }
}

module.exports = new KeyAuthService();
