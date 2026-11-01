#!/usr/bin/env node
import { managementHeaders, provisionAdmin } from './lib/management-session.mjs';
if (process.argv[2] === '--provision') {
  if (!process.argv[3] || !process.argv[4]) throw new Error('Usage: management-session.mjs --provision <binary> <app-dir>');
  provisionAdmin(process.argv[3], process.argv[4]);
} else {
  const baseURL = process.env.BIFROST_E2E_BASE_URL || process.env.BIFROST_BASE_URL || 'http://localhost:8080';
  process.stdout.write((await managementHeaders(baseURL)).Authorization);
}
