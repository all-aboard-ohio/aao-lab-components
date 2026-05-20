#!/usr/bin/env node
/**
 * generate-hash.js — Generate EVENT_CODE_HASH for the aao-event-gate Worker
 *
 * Run this before each event to produce the hash you'll store as a secret.
 * The event code itself is never stored — only this derived hash.
 *
 * Usage:
 *   node generate-hash.js "your event code"
 *
 * Example:
 *   node generate-hash.js "blazing-cardinal-2026"
 *
 * Output:
 *   EVENT_CODE_HASH=k3Xv8...base64...==
 *
 *   Then set it as a secret (never commit the hash to source control):
 *   wrangler secret put EVENT_CODE_HASH
 *
 * The hash uses PBKDF2-SHA256 with 100,000 iterations and the fixed salt
 * "aao-event-gate-v1" — matching the Worker's deriveCodeHash() function.
 * Rotate by generating a new hash for every event and updating the secret.
 */

const { pbkdf2 } = require('node:crypto');

const SALT       = 'aao-event-gate-v1';
const ITERATIONS = 100_000;
const KEY_LEN    = 32; // 256 bits

const code = process.argv[2];

if (!code || code.trim().length === 0) {
  console.error('');
  console.error('  Usage: node generate-hash.js "your event code"');
  console.error('');
  console.error('  Example: node generate-hash.js "blazing-cardinal-2026"');
  console.error('');
  process.exit(1);
}

if (code.length > 256) {
  console.error('Error: Event code must be 256 characters or fewer.');
  process.exit(1);
}

console.log('');
console.log(`Deriving hash for event code... (this takes a moment)`);

pbkdf2(code.trim(), SALT, ITERATIONS, KEY_LEN, 'sha256', (err, key) => {
  if (err) {
    console.error('Hash derivation failed:', err.message);
    process.exit(1);
  }

  const hash = key.toString('base64');

  console.log('');
  console.log('─'.repeat(60));
  console.log(`EVENT_CODE_HASH=${hash}`);
  console.log('─'.repeat(60));
  console.log('');
  console.log('Next steps:');
  console.log('  1. Set it as a Cloudflare Worker secret (recommended):');
  console.log('       wrangler secret put EVENT_CODE_HASH');
  console.log('       [paste the hash value above when prompted]');
  console.log('');
  console.log('  2. Or add it to wrangler.toml [vars] for local dev only:');
  console.log(`       EVENT_CODE_HASH = "${hash}"`);
  console.log('');
  console.log('  ⚠  Never commit the event code or this hash to source control.');
  console.log('  ⚠  Rotate the code and re-run this script before each event.');
  console.log('');
});
