import { describe, expect, it, vi } from 'vitest'
import { sameOriginRedirect, sessionJwt } from './api'

vi.stubGlobal('window', { location: { origin: 'http://localhost' } })

describe('sameOriginRedirect (G-61)', () => {
  it('accepts same-origin relative paths', () => {
    expect(sameOriginRedirect('/admin')).toBe('http://localhost/admin')
    expect(sameOriginRedirect('/device-login?user_code=ABCD-1234')).toBe(
      'http://localhost/device-login?user_code=ABCD-1234',
    )
  })

  it('refuses absolute URLs to foreign origins', () => {
    expect(sameOriginRedirect('https://evil.example/')).toBeNull()
    expect(sameOriginRedirect('http://evil.example/login')).toBeNull()
  })

  it('refuses protocol-relative and backslash evasion', () => {
    expect(sameOriginRedirect('//evil.example')).toBeNull()
    expect(sameOriginRedirect('/\\evil.example')).toBeNull()
  })

  it('treats a leading-backslash path as an internal path', () => {
    expect(sameOriginRedirect('\\evil.example')).toBe('http://localhost/evil.example')
  })
})

describe('sessionJwt', () => {
  it('prefers the jwt field', () => {
    expect(sessionJwt({ jwt: 'a', data: 'b' })).toBe('a')
  })

  it('falls back to data (social redeem shape)', () => {
    expect(sessionJwt({ data: 'b' })).toBe('b')
  })

  it('throws when no session was issued', () => {
    expect(() => sessionJwt({})).toThrow(/no session/)
  })
})
