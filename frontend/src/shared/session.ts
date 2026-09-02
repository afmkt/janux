const SESSION_KEY = 'janux.session'

export function storeSession(jwt: string): void {
  sessionStorage.setItem(SESSION_KEY, jwt)
}

export function loadSession(): string | null {
  return sessionStorage.getItem(SESSION_KEY)
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY)
}
