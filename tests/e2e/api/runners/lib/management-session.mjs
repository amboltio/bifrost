import { spawnSync } from 'node:child_process';

export const adminEmail = process.env.BIFROST_E2E_ADMIN_EMAIL || 'e2e-admin@example.com';
export const adminPassword = process.env.BIFROST_E2E_ADMIN_PASSWORD || 'Bifrost-E2E-Admin-Pass1!';

// Provision only a test instance whose binary and data directory the runner owns.
export function provisionAdmin(binary, appDir, env = process.env) {
  const result = spawnSync(binary, ['createsuperadmin', '--app-dir', appDir, '--email', adminEmail,
    '--display-name', 'E2E Administrator', '--password-stdin'], {
    input: `${adminPassword}\n`, encoding: 'utf8', env,
  });
  if (result.status !== 0) throw new Error(`Test administrator provisioning failed (exit ${result.status}). Use a fresh test store; existing emails are never overwritten.`);
}

export async function managementHeaders(baseURL) {
  if (process.env.BIFROST_E2E_AUTH_HEADER || process.env.BIFROST_ADMIN_AUTH) {
    return { Authorization: process.env.BIFROST_E2E_AUTH_HEADER || process.env.BIFROST_ADMIN_AUTH };
  }
  const res = await fetch(`${baseURL.replace(/\/+$/, '')}/api/session/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  if (!res.ok) throw new Error(`Canonical administrator login failed (${res.status}); provision a test administrator with createsuperadmin and configure BIFROST_E2E_ADMIN_EMAIL/PASSWORD.`);
  const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [res.headers.get('set-cookie') || ''];
  const cookie = cookies.map((value) => value.split(';')[0]).find((value) => value.startsWith('token='));
  if (!cookie) throw new Error('Administrator login returned no session cookie');
  return { Authorization: `Bearer ${decodeURIComponent(cookie.slice('token='.length))}` };
}
