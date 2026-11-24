/**
 * 手写 UTF-8 与 base64url 编解码。
 * 小程序运行时没有 Buffer/atob/btoa/TextEncoder，全部转换在此实现。
 */

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

export function isUint8Array(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array
}

export function assertBytes(value: unknown, label: string, length?: number): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${label}: expected Uint8Array`)
  if (length !== undefined && value.length !== length) {
    throw new Error(`${label}: expected ${length} bytes, got ${value.length}`)
  }
  return value
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const part of parts) total += assertBytes(part, 'concatBytes').length
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i]
  return diff === 0
}

export function utf8Encode(input: string): Uint8Array {
  if (typeof input !== 'string') throw new TypeError('utf8Encode: expected string')
  const bytes: number[] = []
  for (let i = 0; i < input.length; i += 1) {
    const unit = input.charCodeAt(i)
    if (unit < 0x80) {
      bytes.push(unit)
      continue
    }
    if (unit < 0x800) {
      bytes.push(0xc0 | (unit >> 6), 0x80 | (unit & 0x3f))
      continue
    }
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < input.length ? input.charCodeAt(i + 1) : -1
      if (next < 0xdc00 || next > 0xdfff) throw new Error('utf8Encode: lone high surrogate')
      const codePoint = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00)
      bytes.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      )
      i += 1
      continue
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('utf8Encode: lone low surrogate')
    bytes.push(0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f))
  }
  return Uint8Array.from(bytes)
}

export function utf8Decode(input: Uint8Array): string {
  assertBytes(input, 'utf8Decode')
  let out = ''
  let i = 0
  while (i < input.length) {
    const lead = input[i]
    if (lead < 0x80) {
      out += String.fromCharCode(lead)
      i += 1
      continue
    }
    let needed: number
    let codePoint: number
    let minimum: number
    if (lead >= 0xc2 && lead <= 0xdf) {
      needed = 1
      codePoint = lead & 0x1f
      minimum = 0x80
    } else if (lead >= 0xe0 && lead <= 0xef) {
      needed = 2
      codePoint = lead & 0x0f
      minimum = 0x800
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      needed = 3
      codePoint = lead & 0x07
      minimum = 0x10000
    } else {
      throw new Error(`utf8Decode: invalid lead byte 0x${lead.toString(16)}`)
    }
    if (i + needed >= input.length) throw new Error('utf8Decode: truncated sequence')
    for (let k = 1; k <= needed; k += 1) {
      const byte = input[i + k]
      if ((byte & 0xc0) !== 0x80) throw new Error('utf8Decode: invalid continuation byte')
      codePoint = (codePoint << 6) | (byte & 0x3f)
    }
    if (codePoint < minimum) throw new Error('utf8Decode: overlong sequence')
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) throw new Error('utf8Decode: surrogate code point')
    if (codePoint > 0x10ffff) throw new Error('utf8Decode: code point out of range')
    if (codePoint <= 0xffff) {
      out += String.fromCharCode(codePoint)
    } else {
      const offset = codePoint - 0x10000
      out += String.fromCharCode(0xd800 + (offset >> 10), 0xdc00 + (offset & 0x3ff))
    }
    i += needed + 1
  }
  return out
}

export function base64UrlEncode(input: Uint8Array): string {
  assertBytes(input, 'base64UrlEncode')
  let out = ''
  let index = 0
  while (index + 3 <= input.length) {
    const chunk = (input[index] << 16) | (input[index + 1] << 8) | input[index + 2]
    out +=
      BASE64URL_ALPHABET[chunk >>> 18] +
      BASE64URL_ALPHABET[(chunk >>> 12) & 0x3f] +
      BASE64URL_ALPHABET[(chunk >>> 6) & 0x3f] +
      BASE64URL_ALPHABET[chunk & 0x3f]
    index += 3
  }
  const remaining = input.length - index
  if (remaining === 1) {
    const chunk = input[index] << 16
    out += BASE64URL_ALPHABET[chunk >>> 18] + BASE64URL_ALPHABET[(chunk >>> 12) & 0x3f]
  } else if (remaining === 2) {
    const chunk = (input[index] << 16) | (input[index + 1] << 8)
    out +=
      BASE64URL_ALPHABET[chunk >>> 18] +
      BASE64URL_ALPHABET[(chunk >>> 12) & 0x3f] +
      BASE64URL_ALPHABET[(chunk >>> 6) & 0x3f]
  }
  return out
}

function base64UrlCharValue(charCode: number): number {
  if (charCode >= 65 && charCode <= 90) return charCode - 65
  if (charCode >= 97 && charCode <= 122) return charCode - 71
  if (charCode >= 48 && charCode <= 57) return charCode + 4
  if (charCode === 45) return 62
  if (charCode === 95) return 63
  return -1
}

export function base64UrlDecode(input: string): Uint8Array {
  if (typeof input !== 'string') throw new TypeError('base64UrlDecode: expected string')
  if (input.length % 4 === 1) throw new Error('base64UrlDecode: invalid length')
  const bytes: number[] = []
  let index = 0
  while (index + 4 <= input.length) {
    const a = base64UrlCharValue(input.charCodeAt(index))
    const b = base64UrlCharValue(input.charCodeAt(index + 1))
    const c = base64UrlCharValue(input.charCodeAt(index + 2))
    const d = base64UrlCharValue(input.charCodeAt(index + 3))
    if (a < 0 || b < 0 || c < 0 || d < 0) throw new Error('base64UrlDecode: invalid character')
    bytes.push((a << 2) | (b >>> 4), ((b & 0x0f) << 4) | (c >>> 2), ((c & 0x03) << 6) | d)
    index += 4
  }
  const remaining = input.length - index
  if (remaining === 2) {
    const a = base64UrlCharValue(input.charCodeAt(index))
    const b = base64UrlCharValue(input.charCodeAt(index + 1))
    if (a < 0 || b < 0) throw new Error('base64UrlDecode: invalid character')
    if ((b & 0x0f) !== 0) throw new Error('base64UrlDecode: non-canonical trailing bits')
    bytes.push((a << 2) | (b >>> 4))
  } else if (remaining === 3) {
    const a = base64UrlCharValue(input.charCodeAt(index))
    const b = base64UrlCharValue(input.charCodeAt(index + 1))
    const c = base64UrlCharValue(input.charCodeAt(index + 2))
    if (a < 0 || b < 0 || c < 0) throw new Error('base64UrlDecode: invalid character')
    if ((c & 0x03) !== 0) throw new Error('base64UrlDecode: non-canonical trailing bits')
    bytes.push((a << 2) | (b >>> 4), ((b & 0x0f) << 4) | (c >>> 2))
  }
  return Uint8Array.from(bytes)
}
