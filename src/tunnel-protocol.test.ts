import { describe, expect, it } from 'vitest'

import {
  BINARY_KIND_HTTP_BODY,
  BINARY_KIND_HTTP_END,
  BINARY_KIND_WS_BINARY,
  BINARY_KIND_WS_TEXT,
  MAX_BINARY_PAYLOAD_BYTES,
  decodeBinaryFrame,
  decodeTextFrame,
  encodeBinaryFrame,
  encodeTextFrame,
  TunnelProtocolError,
} from './tunnel-protocol'

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (err) {
    return (err as TunnelProtocolError).code
  }
  return undefined
}

describe('tunnel text frames', () => {
  it('round-trips JSON frames', () => {
    const frame = { t: 'ping', ts: 1234 }
    expect(decodeTextFrame(encodeTextFrame(frame))).toEqual(frame)
  })

  it('rejects malformed frames', () => {
    expect(codeOf(() => decodeTextFrame('{'))).toBe('REMOTE_TUNNEL_BAD_TEXT_FRAME')
    expect(codeOf(() => decodeTextFrame('[]'))).toBe('REMOTE_TUNNEL_BAD_TEXT_FRAME')
    expect(codeOf(() => decodeTextFrame('{"ts":1}'))).toBe('REMOTE_TUNNEL_BAD_TEXT_FRAME')
  })
})

describe('tunnel binary frames', () => {
  it('writes the 6-byte big-endian header', () => {
    const encoded = encodeBinaryFrame(BINARY_KIND_HTTP_BODY, 0x01020304, new Uint8Array([0xaa, 0xbb]))
    expect([...encoded]).toEqual([0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb])
    const decoded = decodeBinaryFrame(encoded)
    expect(decoded.kind).toBe(BINARY_KIND_HTTP_BODY)
    expect(decoded.streamId).toBe(0x01020304)
    expect([...decoded.payload]).toEqual([0xaa, 0xbb])
  })

  it('supports all four kinds and empty payloads', () => {
    for (const kind of [BINARY_KIND_HTTP_BODY, BINARY_KIND_HTTP_END, BINARY_KIND_WS_TEXT, BINARY_KIND_WS_BINARY] as const) {
      const decoded = decodeBinaryFrame(encodeBinaryFrame(kind, 7, new Uint8Array()))
      expect(decoded.kind).toBe(kind)
      expect(decoded.streamId).toBe(7)
      expect(decoded.payload).toHaveLength(0)
    }
  })

  it('accepts a full 64 KiB payload and rejects one byte more', () => {
    const full = new Uint8Array(MAX_BINARY_PAYLOAD_BYTES).fill(9)
    expect(() => encodeBinaryFrame(BINARY_KIND_HTTP_BODY, 1, full)).not.toThrow()
    expect(codeOf(() => encodeBinaryFrame(BINARY_KIND_HTTP_BODY, 1, new Uint8Array(MAX_BINARY_PAYLOAD_BYTES + 1)))).toBe(
      'REMOTE_TUNNEL_FRAME_TOO_LARGE',
    )
  })

  it('rejects short headers, unknown kinds and non-zero flags', () => {
    expect(codeOf(() => decodeBinaryFrame(new Uint8Array([0x01, 0x00])))).toBe('REMOTE_TUNNEL_BAD_BINARY_FRAME')
    expect(codeOf(() => decodeBinaryFrame(new Uint8Array([0x99, 0, 0, 0, 0, 1])))).toBe(
      'REMOTE_TUNNEL_UNKNOWN_FRAME_KIND',
    )
    expect(codeOf(() => decodeBinaryFrame(new Uint8Array([0x01, 0x01, 0, 0, 0, 1])))).toBe(
      'REMOTE_TUNNEL_BAD_BINARY_FRAME',
    )
    expect(codeOf(() => encodeBinaryFrame(0x99 as never, 1, new Uint8Array()))).toBe(
      'REMOTE_TUNNEL_UNKNOWN_FRAME_KIND',
    )
  })

  it('decodes Node Buffers and rejects out-of-range stream ids', () => {
    const encoded = encodeBinaryFrame(BINARY_KIND_HTTP_END, 42, new Uint8Array([1, 2, 3]))
    expect(decodeBinaryFrame(Buffer.from(encoded)).streamId).toBe(42)
    expect(codeOf(() => encodeBinaryFrame(BINARY_KIND_HTTP_END, 0, new Uint8Array()))).toBe(
      'REMOTE_TUNNEL_BAD_BINARY_FRAME',
    )
    expect(codeOf(() => encodeBinaryFrame(BINARY_KIND_HTTP_END, -1, new Uint8Array()))).toBe(
      'REMOTE_TUNNEL_BAD_BINARY_FRAME',
    )
    expect(codeOf(() => encodeBinaryFrame(BINARY_KIND_HTTP_END, 0x1_0000_0000, new Uint8Array()))).toBe(
      'REMOTE_TUNNEL_BAD_BINARY_FRAME',
    )
  })
})
