import { describe, expect, it } from 'vitest'
import { envelope, isUnauthorized, pageItems, problemText } from './api'

describe('problemText', () => {
  it('prefers the RFC 7807 detail', () => {
    expect(problemText({ detail: 'level gate refused' }, 403)).toBe('level gate refused')
  })

  it('falls back to msg, then to a status string', () => {
    expect(problemText({ msg: 'Failure' }, 400)).toBe('Failure')
    expect(problemText(null, 500)).toBe('Request failed (500)')
    expect(problemText(undefined)).toBe('Request failed (?)')
  })
})

describe('isUnauthorized', () => {
  it('matches only 401 — 403 carries its own signals (G-155)', () => {
    expect(isUnauthorized(401)).toBe(true)
    expect(isUnauthorized(403)).toBe(false)
    expect(isUnauthorized(undefined)).toBe(false)
  })
})

describe('envelope / pageItems', () => {
  it('unwraps the ok/data envelope defensively', () => {
    expect(envelope<{ a: number }>({ ok: true, data: { a: 1 } }).data).toEqual({ a: 1 })
    expect(envelope(null).data).toBeUndefined()
  })

  it('reads paginated items without throwing on odd shapes', () => {
    expect(pageItems({ data: { items: ['a', 'b'] } })).toEqual(['a', 'b'])
    expect(pageItems({})).toEqual([])
    expect(pageItems(null)).toEqual([])
  })
})
