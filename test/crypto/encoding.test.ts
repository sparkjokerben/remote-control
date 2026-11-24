import { describe, expect, it } from 'vitest'

import {
  base64UrlDecode,
  base64UrlEncode,
  bytesEqual,
  concatBytes,
  utf8Decode,
  utf8Encode,
} from '../../src/crypto/encoding'

describe('utf8Encode / utf8Decode', () => {
  it('encodes 1..4 byte sequences without TextEncoder', () => {
    expect(Array.from(utf8Encode('hello'))).toEqual([104, 101, 108, 108, 111])
    expect(Array.from(utf8Encode('é'))).toEqual([0xc3, 0xa9])
    expect(Array.from(utf8Encode('中'))).toEqual([0xe4, 0xb8, 0xad])
    expect(Array.from(utf8Encode('😀'))).toEqual([0xf0, 0x9f, 0x98, 0x80])
  })

  it('round-trips mixed text including NUL and astral symbols', () => {
    const text = 'dsh 远程控制 🚀\u0000 tail \u{10ffff}'
    expect(utf8Decode(utf8Encode(text))).toBe(text)
  })

  it('rejects unpaired surrogates', () => {
    expect(() => utf8Encode('\ud800')).toThrow(/surrogate/)
    expect(() => utf8Encode('\udc00')).toThrow(/surrogate/)
    expect(() => utf8Encode('a\ud800b')).toThrow(/surrogate/)
  })

  it('rejects malformed byte sequences', () => {
    expect(() => utf8Decode(Uint8Array.from([0x80]))).toThrow()
    expect(() => utf8Decode(Uint8Array.from([0xc0, 0xae]))).toThrow(/invalid lead|overlong/)
    expect(() => utf8Decode(Uint8Array.from([0xe4, 0xb8]))).toThrow(/truncated/)
    expect(() => utf8Decode(Uint8Array.from([0xed, 0xa0, 0x80]))).toThrow(/surrogate/)
    expect(() => utf8Decode(Uint8Array.from([0xf4, 0x90, 0x80, 0x80]))).toThrow(/out of range/)
    expect(() => utf8Decode(Uint8Array.from([0xe4, 0x28, 0xad]))).toThrow(/continuation/)
  })
})

describe('base64UrlEncode / base64UrlDecode', () => {
  it('matches known vectors and never emits padding', () => {
    expect(base64UrlEncode(new Uint8Array())).toBe('')
    expect(base64UrlEncode(Uint8Array.from([0]))).toBe('AA')
    expect(base64UrlEncode(utf8Encode('hello'))).toBe('aGVsbG8')
    expect(base64UrlEncode(Uint8Array.from([0xfb, 0xff]))).toBe('-_8')
  })

  it('round-trips every byte length 0..63', () => {
    for (let length = 0; length < 64; length += 1) {
      const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + length * 11) & 0xff)
      const encoded = base64UrlEncode(bytes)
      expect(encoded).not.toContain('=')
      expect(base64UrlDecode(encoded)).toEqual(bytes)
    }
  })

  it('rejects padding, foreign alphabets, bad lengths and non-canonical tails', () => {
    expect(() => base64UrlDecode('aGVsbG8=')).toThrow()
    expect(() => base64UrlDecode('a+b/')).toThrow()
    expect(() => base64UrlDecode('A')).toThrow(/length/)
    expect(() => base64UrlDecode('AB')).toThrow(/canonical/)
    expect(() => base64UrlDecode('AAB')).toThrow(/canonical/)
  })

  it('decodes 2 and 3 character tails to the right byte lengths', () => {
    expect(base64UrlDecode('AA')).toHaveLength(1)
    expect(base64UrlDecode('AAA')).toHaveLength(2)
  })
})

describe('byte helpers', () => {
  it('concatenates in order', () => {
    const joined = concatBytes(Uint8Array.from([1, 2]), new Uint8Array(0), Uint8Array.from([3]))
    expect(Array.from(joined)).toEqual([1, 2, 3])
  })

  it('compares bytes by value', () => {
    expect(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 2]))).toBe(true)
    expect(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 3]))).toBe(false)
    expect(bytesEqual(Uint8Array.from([1]), Uint8Array.from([1, 2]))).toBe(false)
  })
})
