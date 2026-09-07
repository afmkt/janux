/// The canonical HttpOnly session cookie name — must match the server's
/// `utils::SESSION_COOKIE`. The session JWT itself never lives in
/// JS-readable storage (G-139): the verify endpoints store it in this
/// HttpOnly cookie, the browser attaches it to same-origin requests, and
/// the server's `get_jwt` reads it back. The sessionStorage marker below
/// only records "this tab holds a session" for UI gating — it carries
/// nothing an XSS could exfiltrate.
export const SESSION_COOKIE = 'janux.session'

const SESSION_MARKER = 'janux.session.present'

export function markSession(): void {
  sessionStorage.setItem(SESSION_MARKER, '1')
}

export function hasSession(): boolean {
  return sessionStorage.getItem(SESSION_MARKER) === '1'
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_MARKER)
}
