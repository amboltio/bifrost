import { APIRequestContext } from '@playwright/test'

export const adminCredentials = {
  email: process.env.BIFROST_E2E_ADMIN_EMAIL || 'e2e-admin@example.com',
  password: process.env.BIFROST_E2E_ADMIN_PASSWORD || 'Bifrost-E2E-Admin-Pass1!',
}

export async function loginAdmin(request: APIRequestContext) {
  const response = await request.post('/api/session/login', { data: adminCredentials })
  if (!response.ok()) {
    throw new Error(`Canonical administrator login failed (${response.status()}); provision the test administrator with createsuperadmin first`)
  }
  return response
}
