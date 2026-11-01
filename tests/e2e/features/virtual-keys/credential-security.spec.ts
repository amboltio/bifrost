import { expect, test } from '../../core/fixtures/base.fixture'
import { loginAdmin } from '../../core/actions/auth'

// Runs entirely against local management APIs; no LLM provider calls.
test.use({ skipAutoLogin: true })

test.beforeEach(async ({ page }) => {
  await loginAdmin(page.request)
})

test('stored keys are prefix-only and rotation issues a hidden one-time replacement', async ({ page }) => {
  const name = `Credential security ${Date.now()}`
  const created = await page.request.post('/api/governance/virtual-keys', { data: { name, description: 'Retain this setting', is_active: true } })
  expect(created.status(), await created.text()).toBe(200)
  expect(created.headers()['cache-control']).toContain('no-store')
  const issued = await created.json()
  const oldSecret = issued.issued_secret
  expect(oldSecret).toMatch(/^sk-bf-/)
  expect(issued.virtual_key.value).toBe('')
  expect(issued.virtual_key.value_prefix).toBe(oldSecret.slice(0, 10))
  const id = issued.virtual_key.id
  try {
    const detail = await page.request.get(`/api/governance/virtual-keys/${id}`)
    expect(detail.status()).toBe(200)
    expect(await detail.text()).not.toContain(oldSecret)
    await page.goto('/workspace/governance/virtual-keys')
    const row = page.getByTestId(`vk-row-${name}`)
    await expect(row).toBeVisible()
    await expect(row.getByTestId('vk-key-value')).toHaveText('••••••••••')
    await page.getByTestId(`vk-visibility-btn-${name}`).click()
    await expect(row.getByTestId('vk-key-value')).toHaveText(`${oldSecret.slice(0, 10)}…`)
    await expect(page.getByTestId(`vk-copy-btn-${name}`)).toHaveCount(0)
    await page.getByTestId(`vk-actions-btn-${name}`).click()
    await page.getByTestId(`vk-edit-btn-${name}`).click()
    await page.getByTestId('vk-rotate-btn').click()
    const rotation = page.waitForResponse((response) => response.url().endsWith(`/${id}/rotate`) && response.request().method() === 'POST')
    await page.getByTestId('vk-rotate-confirm-btn').click()
    const rotatedResponse = await rotation
    expect(rotatedResponse.status(), await rotatedResponse.text()).toBe(200)
    const rotated = await rotatedResponse.json()
    expect(rotated.issued_secret).not.toBe(oldSecret)
    expect(rotated.virtual_key.description).toBe('Retain this setting')
    expect(rotated.virtual_key.value).toBe('')
    await expect(page.getByTestId('vk-issued-secret-value')).toHaveText('••••••••••••••••')
    await page.getByTestId('vk-issued-secret-reveal').click()
    await expect(page.getByTestId('vk-issued-secret-value')).toHaveText(rotated.issued_secret)
    await page.getByTestId('vk-issued-secret-close').click()
    await expect(page.getByTestId('vk-issued-secret-dialog')).toHaveCount(0)
    const oldQuota = await page.request.get('/api/governance/virtual-keys/quota', {headers: {'x-bf-vk': oldSecret}})
    expect(oldQuota.status()).toBe(401)
    const newQuota = await page.request.get('/api/governance/virtual-keys/quota', {headers: {'x-bf-vk': rotated.issued_secret}})
    expect(newQuota.status(), await newQuota.text()).toBe(200)
    const stored = await page.request.get(`/api/governance/virtual-keys/${id}`)
    expect(await stored.text()).not.toContain(rotated.issued_secret)
  } finally { await page.request.delete(`/api/governance/virtual-keys/${id}`, {timeout: 5000}).catch(() => {}) }
})

test('admins reset local passwords and revoke the target sessions', async ({ page, browser, baseURL }) => {
  const email = `reset-${Date.now()}@example.test`
  const roles = await (await page.request.get('/api/governance/roles')).json()
  const viewer = roles.roles.find((role: {name: string}) => role.name === 'viewer')
  expect(viewer).toBeDefined()
  const result = await page.request.post('/api/governance/users', {data: {email, display_name: 'Reset test user', password: 'Old-local-password-1!', role_ids: [viewer.id]}})
  expect(result.status(), await result.text()).toBe(201)
  const user = await result.json()
  const other = await browser.newContext({baseURL})
  try {
    expect((await other.request.post('/api/session/login', {data: {email, password: 'Old-local-password-1!'}})).status()).toBe(200)
    expect((await other.request.post(`/api/governance/users/${user.id}/password`, {data: {new_password: 'Forbidden-password-1!', confirm_password: 'Forbidden-password-1!'}})).status()).toBe(403)
    await page.goto('/workspace/governance/users')
    await page.getByTestId(`user-reset-password-${user.id}`).click()
    await page.getByTestId('password-new_password').fill('New-local-password-2!')
    await page.getByTestId('password-confirm_password').fill('New-local-password-2!')
    const response = page.waitForResponse((r) => r.url().endsWith(`/users/${user.id}/password`))
    await page.getByTestId('password-submit').click()
    expect((await response).status()).toBe(204)
    await expect(page.getByTestId('password-dialog-form')).toHaveCount(0)
    expect((await other.request.get('/api/session/current-user')).status()).toBe(401)
    expect((await other.request.post('/api/session/login', {data: {email, password: 'New-local-password-2!'}})).status()).toBe(200)
    const ownPage = await other.newPage()
    await ownPage.goto('/workspace/dashboard')
    await ownPage.getByTestId('topbar-menu-btn').click()
    await ownPage.getByTestId('account-change-password').click()
    await ownPage.getByTestId('password-current_password').fill('Wrong-current-password')
    await ownPage.getByTestId('password-new_password').fill('Self-service-password-3!')
    await ownPage.getByTestId('password-confirm_password').fill('Self-service-password-3!')
    await ownPage.getByTestId('password-submit').click()
    await expect(ownPage.getByTestId('password-error')).toContainText('Current password is incorrect')
    await ownPage.getByTestId('password-current_password').fill('New-local-password-2!')
    await ownPage.getByTestId('password-submit').click()
    await expect(ownPage).toHaveURL(/\/login/)
    expect((await other.request.post('/api/session/login', {data: {email, password: 'Self-service-password-3!'}})).status()).toBe(200)
  } finally { await other.close(); await page.request.delete(`/api/governance/users/${user.id}`) }
})

test('product news does not fetch or render while operational notices remain', async ({ page }) => {
  const news: string[] = []
  page.on('request', (request) => { if (/\/api\/(rss|releases|latest-release)/.test(request.url())) news.push(request.url()) })
  await page.route('**/api/notifications*', (route) => route.fulfill({json: {notifications: [{id: 'local-failure', severity: 'error', title: 'Configuration failed', message: 'Local operational test', created_at: new Date().toISOString()}]}}))
  await page.goto('/workspace/dashboard')
  await page.getByTestId('topbar-notifications-btn').click()
  await expect(page.getByTestId('notification-item-local-failure')).toBeVisible()
  await expect(page.getByTestId('notification-tab-news')).toHaveCount(0)
  await expect(page.getByText('View release notes')).toHaveCount(0)
  expect(news).toEqual([])
})
