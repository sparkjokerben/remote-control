import { describe, expect, it } from 'vitest'

import { base64UrlDecode, base64UrlEncode, utf8Decode } from '../../src/crypto/encoding'
import {
  createRatchet,
  MAX_SKIPPED_MESSAGE_KEYS,
  RatchetError,
  type EncryptedFrame,
  type RatchetOptions,
  type RatchetSession,
} from '../../src/crypto/ratchet'

function chainKey(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

function options(overrides: Partial<RatchetOptions> = {}): RatchetOptions {
  return {
    nodeId: 'node-1',
    sessionId: 'session-1',
    senderId: 'client-1',
    peerSenderId: 'node-1',
    sendChainKey: chainKey(1),
    recvChainKey: chainKey(2),
    ...overrides,
  }
}

function pair(): { client: RatchetSession; node: RatchetSession } {
  return {
    client: createRatchet(options()),
    node: createRatchet(
      options({
        senderId: 'node-1',
        peerSenderId: 'client-1',
        sendChainKey: chainKey(2),
        recvChainKey: chainKey(1),
      }),
    ),
  }
}

function errorCode(run: () => unknown): string {
  try {
    run()
  } catch (error) {
    expect(error).toBeInstanceOf(RatchetError)
    return (error as RatchetError).code
  }
  throw new Error('expected a RatchetError')
}

function flipLastByte(encoded: string): string {
  const bytes = base64UrlDecode(encoded)
  bytes[bytes.length - 1] ^= 0x01
  return base64UrlEncode(bytes)
}

describe('ratchet encryption', () => {
  it('encrypts and decrypts both directions', () => {
    const { client, node } = pair()
    expect(utf8Decode(node.decrypt(client.encrypt('hello')))).toBe('hello')
    expect(Array.from(client.decrypt(node.encrypt(Uint8Array.from([0, 1, 2, 255]))))).toEqual([
      0, 1, 2, 255,
    ])
  })

  it('advances seq per message and never repeats ciphertext', () => {
    const { client, node } = pair()
    const first = client.encrypt('same plaintext')
    const second = client.encrypt('same plaintext')
    expect(first.seq).toBe(1)
    expect(second.seq).toBe(2)
    expect(first.ct).not.toBe(second.ct)
    expect(first.nonce).not.toBe(second.nonce)
    expect(client.sendSeq).toBe(3)
    expect(utf8Decode(node.decrypt(first))).toBe('same plaintext')
    expect(utf8Decode(node.decrypt(second))).toBe('same plaintext')
    expect(node.recvSeq).toBe(3)
  })
})

describe('ratchet authentication', () => {
  it('rejects tampered ciphertext and keeps receive state intact', () => {
    const { client, node } = pair()
    const frame = client.encrypt('secret')
    const tampered: EncryptedFrame = { ...frame, ct: flipLastByte(frame.ct) }
    expect(errorCode(() => node.decrypt(tampered))).toBe('DECRYPT_FAILED')
    expect(node.recvSeq).toBe(1)
    expect(utf8Decode(node.decrypt(frame))).toBe('secret')
    expect(node.recvSeq).toBe(2)
  })

  it('rejects tampered nonce', () => {
    const { client, node } = pair()
    const frame = client.encrypt('secret')
    const tampered: EncryptedFrame = { ...frame, nonce: flipLastByte(frame.nonce) }
    expect(errorCode(() => node.decrypt(tampered))).toBe('DECRYPT_FAILED')
    expect(utf8Decode(node.decrypt(frame))).toBe('secret')
  })

  it('binds the seq into the AAD', () => {
    const { client, node } = pair()
    const frame = client.encrypt('seq-bound')
    const shifted: EncryptedFrame = { ...frame, seq: frame.seq + 1 }
    expect(errorCode(() => node.decrypt(shifted))).toBe('DECRYPT_FAILED')
    expect(node.recvSeq).toBe(1)
    expect(utf8Decode(node.decrypt(frame))).toBe('seq-bound')
  })

  it('binds AAD to nodeId, sessionId and senderId', () => {
    const frame = pair().client.encrypt('bound')
    const variants: RatchetOptions[] = [
      options({ senderId: 'node-1', peerSenderId: 'client-9', sendChainKey: chainKey(2), recvChainKey: chainKey(1) }),
      options({ sessionId: 'session-2', senderId: 'node-1', peerSenderId: 'client-1', sendChainKey: chainKey(2), recvChainKey: chainKey(1) }),
      options({ nodeId: 'node-2', senderId: 'node-2', peerSenderId: 'client-1', sendChainKey: chainKey(2), recvChainKey: chainKey(1) }),
    ]
    for (const variant of variants) {
      const receiver = createRatchet(variant)
      expect(errorCode(() => receiver.decrypt(frame))).toBe('DECRYPT_FAILED')
    }
  })
})

describe('ratchet ordering', () => {
  it('decrypts arbitrary out-of-order delivery within the window', () => {
    const { client, node } = pair()
    const frames = Array.from({ length: 6 }, (_, index) => client.encrypt(`m${index}`))
    for (const index of [3, 0, 5, 2, 1, 4]) {
      expect(utf8Decode(node.decrypt(frames[index]))).toBe(`m${index}`)
    }
    expect(node.recvSeq).toBe(7)
  })

  it('rejects replays and consumes skipped keys exactly once', () => {
    const { client, node } = pair()
    const frames = [client.encrypt('a'), client.encrypt('b'), client.encrypt('c')]
    expect(utf8Decode(node.decrypt(frames[2]))).toBe('c')
    expect(utf8Decode(node.decrypt(frames[0]))).toBe('a')
    expect(errorCode(() => node.decrypt(frames[0]))).toBe('REPLAY')
    expect(utf8Decode(node.decrypt(frames[1]))).toBe('b')
    expect(errorCode(() => node.decrypt(frames[1]))).toBe('REPLAY')
  })

  it('rejects a seq regression with no buffered key', () => {
    const { client, node } = pair()
    const first = client.encrypt('a')
    node.decrypt(first)
    expect(errorCode(() => node.decrypt(first))).toBe('REPLAY')
  })

  it('accepts a skip of exactly 256 messages and drains the buffer', () => {
    const { client, node } = pair()
    const frames = Array.from({ length: MAX_SKIPPED_MESSAGE_KEYS + 1 }, (_, index) =>
      client.encrypt(`m${index}`),
    )
    const last = frames[frames.length - 1]
    expect(utf8Decode(node.decrypt(last))).toBe(`m${frames.length - 1}`)
    for (let index = 0; index < frames.length - 1; index += 1) {
      expect(utf8Decode(node.decrypt(frames[index]))).toBe(`m${index}`)
    }
    expect(node.recvSeq).toBe(MAX_SKIPPED_MESSAGE_KEYS + 2)
  })

  it('rejects a skip beyond the 256 message window', () => {
    const { client, node } = pair()
    const frames = Array.from({ length: MAX_SKIPPED_MESSAGE_KEYS + 2 }, (_, index) =>
      client.encrypt(`m${index}`),
    )
    const last = frames[frames.length - 1]
    expect(errorCode(() => node.decrypt(last))).toBe('WINDOW_EXCEEDED')
    expect(node.recvSeq).toBe(1)
    expect(utf8Decode(node.decrypt(frames[0]))).toBe('m0')
  })

  it('caps the total skipped-key buffer at 256 entries', () => {
    const { client, node } = pair()
    const frames = Array.from({ length: 514 }, (_, index) => client.encrypt(`m${index}`))
    expect(utf8Decode(node.decrypt(frames[256]))).toBe('m256')
    expect(errorCode(() => node.decrypt(frames[513]))).toBe('WINDOW_EXCEEDED')
  })
})

describe('ratchet frame validation', () => {
  it('rejects malformed frames before touching the chain', () => {
    const { node } = pair()
    const valid = pair().client.encrypt('x')
    const cases: Array<Record<string, unknown>> = [
      { ...valid, v: 2 },
      { ...valid, seq: 0 },
      { ...valid, seq: 1.5 },
      { ...valid, seq: '1' },
      { ...valid, nonce: base64UrlEncode(new Uint8Array(11)) },
      { ...valid, ct: base64UrlEncode(new Uint8Array(15)) },
      { ...valid, ct: '***' },
      { ...valid, nonce: 42 },
    ]
    for (const entry of cases) {
      expect(errorCode(() => node.decrypt(entry as unknown as EncryptedFrame))).toBe('INVALID_FRAME')
    }
    expect(node.recvSeq).toBe(1)
  })

  it('validates configuration', () => {
    expect(() => createRatchet(options({ nodeId: '' }))).toThrow(RatchetError)
    expect(() => createRatchet(options({ sessionId: 'a|b' }))).toThrow(RatchetError)
    expect(() => createRatchet(options({ sendChainKey: new Uint8Array(31) }))).toThrow(RatchetError)
    expect(() => createRatchet(options({ recvChainKey: 'not-bytes' as unknown as Uint8Array }))).toThrow(
      RatchetError,
    )
    expect(() => createRatchet(options({ senderId: 'node-1' }))).toThrow(RatchetError)
  })

  it('rejects non-string, non-byte plaintext', () => {
    const { client } = pair()
    expect(errorCode(() => client.encrypt(42 as unknown as string))).toBe('INVALID_INPUT')
  })
})

describe('ratchet JSON helpers', () => {
  it('round-trips JSON payloads', () => {
    const { client, node } = pair()
    const frame = client.encryptJson({ t: 'ping', ts: 123 })
    expect(node.decryptJson(frame)).toEqual({ t: 'ping', ts: 123 })
  })

  it('rejects non-JSON plaintext and unserializable values', () => {
    const { client, node } = pair()
    expect(errorCode(() => node.decryptJson(client.encrypt('not json')))).toBe('INVALID_INPUT')
    const circular: Record<string, unknown> = {}
    circular.self = circular
    expect(errorCode(() => client.encryptJson(circular))).toBe('INVALID_INPUT')
  })
})
