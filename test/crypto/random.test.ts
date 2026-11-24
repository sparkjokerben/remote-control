import { afterEach, describe, expect, it, vi } from 'vitest'

import { createSeededRng, systemRng } from '../../src/crypto/random'

function seed(value: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (value * 17 + index * 7) & 0xff)
}

describe('createSeededRng', () => {
  it('reproduces the same stream for the same seed', () => {
    const first = createSeededRng(seed(1))
    const second = createSeededRng(seed(1))
    expect(first(32)).toEqual(second(32))
    expect(first(7)).toEqual(second(7))
    expect(first(100)).toEqual(second(100))
  })

  it('differs across seeds and across calls', () => {
    expect(createSeededRng(seed(1))(32)).not.toEqual(createSeededRng(seed(2))(32))
    const rng = createSeededRng(seed(3))
    expect(rng(32)).not.toEqual(rng(32))
  })

  it('honours the requested length at and around block boundaries', () => {
    const rng = createSeededRng(seed(4))
    for (const length of [0, 1, 31, 32, 63, 64, 65, 127, 128, 129]) {
      expect(rng(length)).toHaveLength(length)
    }
  })

  it('rejects invalid seeds and lengths', () => {
    expect(() => createSeededRng(new Uint8Array(31))).toThrow()
    const rng = createSeededRng(seed(5))
    expect(() => rng(-1)).toThrow(RangeError)
    expect(() => rng(1.5)).toThrow(RangeError)
    expect(() => rng(Number.NaN)).toThrow(RangeError)
  })
})

describe('systemRng', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('fills the requested length from globalThis.crypto', () => {
    const bytes = systemRng(48)
    expect(bytes).toHaveLength(48)
    expect(systemRng(48)).not.toEqual(bytes)
  })

  it('chunks requests above the 65536 byte getRandomValues limit', () => {
    expect(systemRng(70_000)).toHaveLength(70_000)
  })

  it('throws a clear error when getRandomValues is unavailable', () => {
    vi.stubGlobal('crypto', undefined)
    expect(() => systemRng(16)).toThrow(/getRandomValues/)
  })
})
