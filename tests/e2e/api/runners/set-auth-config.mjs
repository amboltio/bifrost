#!/usr/bin/env node
// Legacy auth_config mutation has no role in canonical management tests.
// Validate a normal administrator session; never turn management authentication off.
import { managementHeaders } from './lib/management-session.mjs';
const mode = process.argv[2];
if (mode !== 'enable' && mode !== 'disable') throw new Error('Usage: set-auth-config.mjs <enable|disable>');
if (mode === 'disable') throw new Error('Canonical management authentication cannot be disabled by the test runner');
await managementHeaders(process.env.BIFROST_E2E_BASE_URL || process.env.BIFROST_BASE_URL || 'http://localhost:8080');
console.log('Canonical administrator session verified');
