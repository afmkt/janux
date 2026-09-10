import { test, expect, type Page } from '@playwright/test'
import { readState, latestMagicLink } from './support/harness'

// Admin SPA (`/admin`) — the root-only console. Two paths are genuinely
// covered (G-165): the unauthenticated guard bounces to login; and the magic-
// link login followed by a real console render drives the protect/policy +
// admin-openapi stack through a browser.

const ADMIN = { name: 'admin', email: 'admin@example.com' }

// Complete a magic-link login in `page` — the same click-through the login SPA
// test drives, ending on the "Signed in." alert.
async function signIn(page: Page): Promise<void> {
   const { baseURL, mockUrl } = readState()
   await page.goto(`${baseURL}/login`)
   await page.getByLabel(/Username/i).fill(ADMIN.name)
   await page.getByRole('button', { name: /Email me a sign-in link/i }).click()
   await page.getByLabel(/Email address/i).fill(ADMIN.email)
   await page.getByRole('button', { name: /^Send link$/i }).click()
   await expect(page.getByText(/Check your inbox/i)).toBeVisible()
   const link = await latestMagicLink(mockUrl)
   expect(link).toContain('token=')
   await page.goto(`${baseURL}/login?${link}`)
   await expect(page.getByText(/Signed in\./i)).toBeVisible()
}

test.describe('admin SPA', () => {
   test('bounces an unauthenticated visitor to login', async ({ page }) => {
      const { baseURL } = readState()
      await page.goto(`${baseURL}/admin`)
      // No session yet: the guard redirects to /login carrying a redirect_uri.
      await expect(page).toHaveURL(new RegExp('/admin|/login\\?.*redirect_uri='))
      await expect(
         page.getByText(/Redirecting to sign-in|Email me a sign-in link/i),
       ).toBeVisible()
      // It must have ended up on the login route.
      await expect(new URL(page.url()).pathname).toBe('/login')
      })

   test('renders the console after a magic-link login', async ({ page }) => {
      const { baseURL } = readState()
      await signIn(page)
       // Same-tab navigation keeps the session marker + HttpOnly cookie, so the
       // console renders and its admin APIs authorize against the live server.
      await page.goto(`${baseURL}/admin`)
      await expect(page.getByRole('heading', { name: /Admin console/i })).toBeVisible()
      await expect(page.getByText(/^Users$/)).toBeVisible()
      // The users list loads the seeded admin from the real API; assert the row
      // itself (not a bare /admin/ match, which also hits the "First admin"
      // label and the roles column).
      await expect(page.getByRole('row', { name: /admin/i }).first()).toBeVisible({
         timeout: 15_000,
         })
      })
})
