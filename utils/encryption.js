const crypto = require('crypto');

// Use a fixed key for demonstration purposes
// In production, this should be stored securely in environment variables
const ENCRYPTION_KEY = 'university-app-secret-key-32!'; // Must be 32 characters
const ALGORITHM = 'aes-256-cbc';

/**
 * Encrypt a string
 */
function encrypt(text) {
  if (!text) return text;

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV + encrypted data (separated by :)
  return iv.toString('hex') + ':' + encrypted;
}

/**
 * Decrypt an encrypted string
 */
function decrypt(text) {
  if (!text || !text.includes(':')) return text;

  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];

    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error.message);
    return text; // Return original if decryption fails
  }
}

/**
 * Check if a string looks encrypted
 */
function isEncrypted(str) {
  return str && typeof str === 'string' && str.includes(':') && str.length > 32;
}

module.exports = {
  encrypt,
  decrypt,
  isEncrypted
};
