const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

/**
 * Hash a plaintext password
 */
async function hashPassword(password) {
  return await bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Compare plaintext password with hash
 */
async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Check if a string looks like a bcrypt hash
 */
function isBcryptHash(str) {
  return str && typeof str === 'string' && str.startsWith('$2b$');
}

module.exports = {
  hashPassword,
  comparePassword,
  isBcryptHash
};
