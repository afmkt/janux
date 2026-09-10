import { test, expect } from '@playwright/test'
import { readState } from './support/harness'

// Device SPA (`/device-login`) — the OAuth2 device-authorization flow. A
// codeless device shows the code, the user opens this page and types it.
// The no-session negative path (a bogus code) is genuinely exercised here: the
// page calls the real /device-login/info endpoint and surfaces its rejection,
// without needing a live device grant or login (G-165).

test.describe('device SPA', () => {
   test('renders the enter-code form', async ({ page }) => {
      const { baseURL } = readState()
      await page.goto(`${baseURL}/device-login`)
      await expect(page.getByRole('heading', { name: /Device authorization/i })).toBeVisible()
      await expect(page.getByLabel(/^Code$/i)).toBeVisible()
      await expect(page.getByRole('button', { name: /^Continue$/i })).toBeVisible()
     })

   test('reports an unknown or expired code', async ({ page }) => {
      const { baseURL } = readState()
      await page.goto(`${baseURL}/device-login`)
      await page.getByLabel(/^Code$/i).fill('ZZZZ-9999')
      await page.getByRole('button', { name: /^Continue$/i }).click()
       await expect(page.getByText(/User code not found or expired/i)).toBeVisible()
     })

   test('guards an empty code before any request goes out', async ({ page }) => {
      const { baseURL } = readState()
      const requests: string[] = []
      page.on('request', (r) => {
         if (r.url().includes('/device-login/info')) requests.push(r.url())
        })
      await page.goto(`${baseURL}/device-login`)
      await page.getByRole('button', { name: /^Continue$/i }).click()
      await new Promise((r) => setTimeout(r, 200))
      expect(requests).toEqual([])
     })
})
