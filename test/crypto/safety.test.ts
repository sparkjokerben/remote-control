import { describe, expect, it } from 'vitest'

import { safetyNumber } from '../../src/crypto/safety'

describe('safetyNumber', () => {
  it('renders 20 digits as four groups of five', () => {
    const value = safetyNumber('bundle-hash-a', 'bundle-hash-b')
    expect(value).toMatch(/^\d{5} \d{5} \d{5} \d{5}$/)
    expect(value.replaceAll(' ', '')).toHaveLength(20)
  })

  it('is order independent', () => {
    expect(safetyNumber('a', 'b')).toBe(safetyNumber('b', 'a'))
  })

  it('is deterministic and input dependent', () => {
    expect(safetyNumber('a', 'b')).toBe(safetyNumber('a', 'b'))
    expect(safetyNumber('a', 'b')).not.toBe(safetyNumber('a', 'c'))
  })

  it('left-pads small values to 20 digits', () => {
    let padded: string | undefined
    for (let index = 0; index < 500 && !padded; index += 1) {
      const value = safetyNumber(`seed-${index}`, 'peer')
      if (value.startsWith('0')) padded = value
    }
    expect(padded).toBeDefined()
    expect(padded).toHaveLength(23)
    expect(padded?.slice(0, 5)).toMatch(/^0\d{4}$/)
  })

  it('rejects empty inputs', () => {
    expect(() => safetyNumber('', 'b')).toThrow()
    expect(() => safetyNumber('a', '')).toThrow()
  })
})
