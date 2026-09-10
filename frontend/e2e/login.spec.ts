import { test, expect } from '@playwright/test'
import { readState, latestMagicLink } from './support/harness'

// Login SPA (`/login`) — the front door: email magic-link, MFA, OTP, password,
// passkey, social. This spec drives a *real* browser through the genuine
// magic-link flow against the real janux backend (G-165).
//
// The form renders a username field plus an "Email me a sign-in link" button.
// Clicking it opens the email field + "Send link"; submitting POSTs to
// /api/v1/auth/email/request and the server drops a verification link onto the
// wire — captured here by the mock Resend endpoint, then followed in-browser
// exactly as a user would click the email.

const ADMIN = { name: 'admin', email: 'admin@example.com' }

test.describe('login SPA', () => {
   test('renders the sign-in form with a link factor', async ({ page }) => {
      const { baseURL } = readState()
      await page.goto(`${baseURL}/login`)
      const h = page.getByRole('heading', { name: /Sign in/i })
      await expect(h).toBeVisible()
      // The email factor renders "Email me a sign-in link".
      await expect(page.getByRole('button', { name: /Email me a sign-in link/i })).toBeVisible()
      await expect(page.getByLabel(/Username/i)).toBeVisible()
    })

   test('guards an empty username before any request goes out', async ({
      page,
    }) => {
      const { baseURL } = readState()
      const requests: string[] = []
      page.on('request', (r) => {
         if (r.url().includes('/email/request')) requests.push(r.url())
       })
      await page.goto(`${baseURL}/login`)
      // With no username, selecting the link factor still opens the email field
      // but no request flies out yet.
      await page.getByRole('button', { name: /Email me a sign-in link/i }).click()
      await expect(page.getByLabel(/Email address/i)).toBeVisible()
      // Click "Send link" with an empty username — it must alert, not send.
      await page.getByRole('button', { name: /^Send link$/i }).click()
      await expect(page.getByText(/Enter your username first/i)).toBeVisible()
      // No request should have been made.
      await new Promise((r) => setTimeout(r, 200))
      expect(requests).toEqual([])
    })

   test('completes a magic link and lands signed-in', async ({ page }) => {
      const { baseURL, mockUrl } = readState()
       // 1. Fill the username and pick the email (magic-link) factor, which
       //    reveals the email field.
      await page.goto(`${baseURL}/login`)
      await page.getByLabel(/Username/i).fill(ADMIN.name)
      await page.getByRole('button', { name: /Email me a sign-in link/i }).click()
      await page.getByLabel(/Email address/i).fill(ADMIN.email)

       // 2. "Send link" fires the real POST /api/v1/auth/email/request.
      await page.getByRole('button', { name: /^Send link$/i }).click()
      await expect(page.getByText(/Check your inbox/i)).toBeVisible()

       // 3. Pull the genuine ceremony link out of the captured email and follow
       //    it in the browser, exactly as a user would click it.
      const link = await latestMagicLink(mockUrl)
      expect(link).toContain('token=')
      await page.goto(`${baseURL}/login?${link}`)

       // 4. The landing auto-POSTs to /api/v1/auth/email/verify, the server sets
       //    the session cookie, and the app lands on the "Signed in." alert.
      await expect(page.getByText(/Signed in\./i)).toBeVisible()
      await expect(page.getByRole('button', { name: /Email me a sign-in link/i })).not.toBeVisible()
    })
})
