import assert from 'node:assert/strict';
import { adminEmail, adminPassword, managementHeaders } from './management-session.mjs';

const savedFetch = globalThis.fetch;
const savedHeader = process.env.BIFROST_E2E_AUTH_HEADER;
const savedAdminAuth = process.env.BIFROST_ADMIN_AUTH;
let passed = 0;
async function test(name, fn) {
  delete process.env.BIFROST_E2E_AUTH_HEADER;
  delete process.env.BIFROST_ADMIN_AUTH;
  await fn();
  passed++;
  console.log(`  ok - ${name}`);
}
try {
  await test('an explicitly supplied canonical session avoids another login', async () => {
    process.env.BIFROST_E2E_AUTH_HEADER = 'Bearer existing-session';
    globalThis.fetch = () => { throw new Error('unexpected login'); };
    assert.deepEqual(await managementHeaders('http://gateway'), { Authorization: 'Bearer existing-session' });
  });
  await test('the external harness session alias is supported', async () => {
    process.env.BIFROST_ADMIN_AUTH = 'Bearer external-session';
    assert.deepEqual(await managementHeaders('http://gateway'), { Authorization: 'Bearer external-session' });
  });
  await test('ordinary email login yields the canonical cookie session, with no legacy auth', async () => {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, 'http://gateway/api/session/login');
      assert.equal(options.method, 'POST');
      assert.deepEqual(JSON.parse(options.body), { email: adminEmail, password: adminPassword });
      assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
      return { ok: true, headers: { getSetCookie: () => ['other=x; Path=/', 'token=canonical%2Bsession; HttpOnly; Path=/'] } };
    };
    assert.deepEqual(await managementHeaders('http://gateway///'), { Authorization: 'Bearer canonical+session' });
  });
  await test('a refused login fails without exposing the supplied password', async () => {
    globalThis.fetch = async () => ({ ok: false, status: 401 });
    await assert.rejects(managementHeaders('http://gateway'), (error) => {
      assert.match(error.message, /Canonical administrator login failed \(401\)/);
      assert.ok(!error.message.includes(adminPassword));
      return true;
    });
  });
  await test('a successful response without a canonical cookie is rejected', async () => {
    globalThis.fetch = async () => ({ ok: true, headers: { getSetCookie: () => ['other=x; Path=/'] } });
    await assert.rejects(managementHeaders('http://gateway'), /no session cookie/);
  });
} finally {
  globalThis.fetch = savedFetch;
  if (savedHeader === undefined) delete process.env.BIFROST_E2E_AUTH_HEADER;
  else process.env.BIFROST_E2E_AUTH_HEADER = savedHeader;
  if (savedAdminAuth === undefined) delete process.env.BIFROST_ADMIN_AUTH;
  else process.env.BIFROST_ADMIN_AUTH = savedAdminAuth;
}
console.log(`${passed} passed`);
