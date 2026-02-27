const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Default key for demonstration purposes
const DEFAULT_ENCRYPTION_KEY = 'university-app-secret-key-32!'; // Must be 32 characters
const ALGORITHM = 'aes-256-cbc';
const CUSTOM_KEY_PATH = path.join(__dirname, '..', 'keys', 'custom-key.txt');

// Current active encryption key (can be default or custom)
let currentEncryptionKey = DEFAULT_ENCRYPTION_KEY;

/**
 * Load custom encryption key from file if it exists
 * @returns {string} The loaded key or default key
 */
function loadCustomKey() {
  try {
    if (fs.existsSync(CUSTOM_KEY_PATH)) {
      const keyData = fs.readFileSync(CUSTOM_KEY_PATH, 'utf8').trim();

      // Validate and normalize key to 32 bytes for AES-256
      const normalizedKey = normalizeKey(keyData);

      console.log('✓ Custom encryption key loaded from', CUSTOM_KEY_PATH);
      return normalizedKey;
    }
  } catch (error) {
    console.error('Error loading custom key:', error.message);
  }

  return DEFAULT_ENCRYPTION_KEY;
}

/**
 * Normalize key to exactly 32 bytes for AES-256
 * Accepts base64-encoded keys from openssl rand -base64 32
 */
function normalizeKey(keyData) {
  // If key is base64-encoded, decode it first
  let keyBuffer;
  try {
    // Try to decode as base64
    keyBuffer = Buffer.from(keyData, 'base64');
  } catch (e) {
    // If not base64, use as-is
    keyBuffer = Buffer.from(keyData, 'utf8');
  }

  // Ensure exactly 32 bytes (pad or truncate)
  if (keyBuffer.length < 32) {
    // Pad with zeros if too short
    const padded = Buffer.alloc(32);
    keyBuffer.copy(padded);
    return padded.toString('utf8');
  } else if (keyBuffer.length > 32) {
    // Truncate if too long
    return keyBuffer.slice(0, 32).toString('utf8');
  }

  return keyBuffer.toString('utf8');
}

/**
 * Save a custom encryption key
 * @param {string} keyData - Base64-encoded key from openssl rand -base64 32
 * @returns {object} Result with success status
 */
function saveCustomKey(keyData) {
  try {
    if (!keyData || keyData.trim().length < 16) {
      return { success: false, error: 'Key must be at least 16 characters' };
    }

    // Normalize and validate key
    const normalizedKey = normalizeKey(keyData.trim());

    // Ensure keys directory exists
    const keysDir = path.dirname(CUSTOM_KEY_PATH);
    if (!fs.existsSync(keysDir)) {
      fs.mkdirSync(keysDir, { recursive: true });
    }

    // Save key to file
    fs.writeFileSync(CUSTOM_KEY_PATH, keyData.trim(), { mode: 0o600 });

    // Update current key
    currentEncryptionKey = normalizedKey;

    console.log('✓ Custom encryption key saved to', CUSTOM_KEY_PATH);
    return { success: true, message: 'Custom encryption key saved successfully' };
  } catch (error) {
    console.error('Error saving custom key:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Delete custom encryption key and revert to default
 * @returns {object} Result with success status
 */
function deleteCustomKey() {
  try {
    if (fs.existsSync(CUSTOM_KEY_PATH)) {
      fs.unlinkSync(CUSTOM_KEY_PATH);
      currentEncryptionKey = DEFAULT_ENCRYPTION_KEY;
      console.log('✓ Custom encryption key deleted, reverted to default');
      return { success: true, message: 'Custom key deleted, reverted to default key' };
    }
    return { success: false, error: 'No custom key found' };
  } catch (error) {
    console.error('Error deleting custom key:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Get information about the current encryption key
 * @returns {object} Key status information
 */
function getKeyInfo() {
  const isCustom = fs.existsSync(CUSTOM_KEY_PATH);
  return {
    usingCustomKey: isCustom,
    keyType: isCustom ? 'Custom' : 'Default',
    keyPath: isCustom ? CUSTOM_KEY_PATH : 'Built-in default key'
  };
}

/**
 * Encrypt a string using the current encryption key
 */
function encrypt(text) {
  if (!text) return text;

  // Guard against double-encryption
  if (isEncrypted(text)) {
    return text;
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(currentEncryptionKey), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV + encrypted data (separated by :)
  return iv.toString('hex') + ':' + encrypted;
}

/**
 * Decrypt an encrypted string using the current encryption key.
 * Throws on failure to prevent silent data corruption.
 */
function decrypt(text) {
  if (!text || !text.includes(':')) return text;

  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];

  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(currentEncryptionKey), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Safe decrypt wrapper that returns a result object instead of throwing.
 * Use this when you want to handle decryption failures gracefully (e.g., display).
 */
function safeDecrypt(text) {
  try {
    return { success: true, value: decrypt(text) };
  } catch (error) {
    console.error('Decryption error:', error.message);
    return { success: false, value: text, error: error.message };
  }
}

/**
 * Check if a string looks encrypted
 */
function isEncrypted(str) {
  return str && typeof str === 'string' && str.includes(':') && str.length > 32;
}

// Initialize: Load custom key on module import if it exists
currentEncryptionKey = loadCustomKey();

module.exports = {
  encrypt,
  decrypt,
  safeDecrypt,
  isEncrypted,
  saveCustomKey,
  deleteCustomKey,
  getKeyInfo,
  loadCustomKey
};
