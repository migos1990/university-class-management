const fs = require('fs');
const path = require('path');

// Load translation files
let translations = {};

try {
  translations.en = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../config/translations/en.json'), 'utf8')
  );
  translations.fr = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../config/translations/fr.json'), 'utf8')
  );
  console.log('✓ Translations loaded: EN, FR');
} catch (error) {
  console.error('Error loading translation files:', error.message);
  // Fallback to minimal translations
  translations.en = { common: { appName: 'University Class Management' } };
  translations.fr = { common: { appName: 'Gestion des Cours Universitaires' } };
}

/**
 * Get translation for a key
 * @param {string} lang - Language code (en or fr)
 * @param {string} key - Translation key (e.g., "common.login")
 * @param {object} params - Optional parameters for interpolation
 * @returns {string} Translated string or key if not found
 */
function t(lang, key, params = {}) {
  // Default to English if language not supported
  const language = ['en', 'fr'].includes(lang) ? lang : 'en';

  // Split the key by dots to navigate nested structure
  const keys = key.split('.');
  let value = translations[language];

  // Navigate through the nested structure
  for (const k of keys) {
    if (value && typeof value === 'object' && k in value) {
      value = value[k];
    } else {
      // Key not found, try English fallback
      if (language !== 'en') {
        value = translations.en;
        for (const fallbackKey of keys) {
          if (value && typeof value === 'object' && fallbackKey in value) {
            value = value[fallbackKey];
          } else {
            console.warn(`Translation missing: ${lang}.${key} (and fallback)`);
            return key; // Return key if translation not found in both languages
          }
        }
      } else {
        console.warn(`Translation missing: ${lang}.${key}`);
        return key; // Return key if translation not found
      }
    }
  }

  // Simple parameter interpolation
  if (typeof value === 'string' && Object.keys(params).length > 0) {
    return value.replace(/\{(\w+)\}/g, (match, paramKey) => {
      return params[paramKey] !== undefined ? params[paramKey] : match;
    });
  }

  return value;
}

/**
 * Middleware to set language from session and make translation function available in views
 */
function languageMiddleware(req, res, next) {
  // Default to English if no language set in session
  const lang = req.session && req.session.language ? req.session.language : 'en';

  // Make translation function available in all views
  res.locals.t = (key, params) => t(lang, key, params);

  // Make current language available
  res.locals.currentLang = lang;

  next();
}

module.exports = {
  t,
  languageMiddleware,
  translations
};
