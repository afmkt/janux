# Janux usability test — your role (the "user")

You are the **end user**. I am the devops agent: I stood up the environment and
I'm watching the system. Your job is to move through it like a real first-time
user and tell me what you feel — confusing, fast, broken, unclear, etc.

**No passwords anywhere.** Sign-in is a magic-link email. Because this is a local
test, that email lands in a web inbox (Mailpit) instead of a real mailbox.

---

## What's running

| URL | What it is |
|---|---|
| `https://localhost/app` | **The thing you're trying to reach** — a protected page behind Janux's gate. Start here. |
| `https://localhost/login` | The sign-in page (you'll be bounced here automatically). |
| `http://localhost:8025` | **Mailpit web inbox** — this is where your magic-link email shows up. Keep it open. |
| `https://localhost/admin` | (optional) the admin console — try it only for probe C. |

On first `https://localhost/...` load the browser may show a **certificate
warning** — the CA is local/self-signed. Two options, pick one:
- **Quick:** click through the warning once; the session cookie still works over
  untrusted HTTPS. It won't reappear for the rest of the session.
- **One-time clean:** in your own terminal run
  `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db dogfood/caddy-root.crt`
  (a dialog may appear — confirm it), then reload. The cert is at `dogfood/caddy-root.crt`.

---

## Primary flow — sign in and reach the protected page

1. Open `http://localhost:8025` (Mailpit) in one tab, and `https://localhost/app`
   in another.
2. `/app` will **not** load — it bounces you to `https://localhost/login`.
   *(Note how it tells you why — or doesn't.)*
3. On the login page, enter **`tester@example.com`** and request the magic link.
4. Go to the Mailpit tab. A **"Janux login"** email to `tester@example.com`
   appears. Click the link inside it.
5. The link auto-completes sign-in and sets your session. Go back to the `/app`
   tab and reload.
6. You should see a page titled **"Protected content ✓"** with a `200 — you are
   authenticated` badge. **That's the goal.**

Tell me: how did it feel? Where did it hesitate or confuse you?

---

## Optional probes (do the ones that interest you)

- **A. Stay logged in** — reload `/app`. Still works? Open an **incognito**
  window to `/app` — it should bounce to login again. (Session is per-browser.)
- **B. Sign out** — find the sign-out control, sign out, reload `/app`. Should
  bounce to login again.
- **C. Admin surface** — open `https://localhost/admin`, sign in as
  `admin@example.com` (read that magic link from Mailpit too). Look at the
  tenant/RBAC/policy view. Does it make sense?
- **D. Wrong account** — sign in as `tester@example.com` but try to reach a path
  no role is granted. *(Most paths are denied by default-deny — note what you see.)*

---

## What to report back (to me, in chat)

After the primary flow (and any probes), tell me:

1. **Onboarding** — was the first screen clear? Did you know what to do?
2. **The magic-link flow** — the bounce → login → Mailpit → click → back-to-app
   loop. Smooth? The Mailpit hop is the one "weird" part; how did it land?
3. **The landing page** — does `/app` feel like it worked?
4. **Errors / dead-ends** — anything that stopped you or felt wrong?
5. **One-line overall impression.**

Just type it plainly — I transcribe it into the test journal as we go.
