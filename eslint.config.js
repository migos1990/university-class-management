const js = require('@eslint/js');
const globals = require('globals');
const eslintConfigPrettier = require('eslint-config-prettier/flat');

module.exports = [
  // Global ignores (standalone object = global ignore, not file-level filter)
  {
    ignores: [
      'node_modules/',
      'database/',
      'backups/',
      'instances/',
      'public/vendor/**',
    ],
  },
  // Main configuration using eslint:recommended
  {
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off', // Console output is part of teaching experience (per user decision)
      'no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_', // Allow _prefixed unused params (Express middleware signatures)
          varsIgnorePattern: '^_',
        },
      ],
    },
  },
  // Disable ESLint rules that conflict with Prettier (must be last)
  eslintConfigPrettier,
];
