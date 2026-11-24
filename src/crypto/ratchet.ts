/**
 * 对称 HKDF 棘轮 + ChaCha20-Poly1305（契约 §2.4）。
 * 发送/接收链各自推进 seq；接收端缓存至多 256 个跳过消息密钥，回退与越界直接拒绝。
 */
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { assertBytes, base64UrlDecode, base64UrlEncode, utf8Decode, utf8Encode } from './encoding'

export interface EncryptedFrame {
  v: 1
  seq: number
  nonce: string
  ct: string
}

export type RatchetErrorCode =
  | 'INVALID_CONFIG'
  | 'INVALID_INPUT'
  | 'INVALID_FRAME'
  | 'DECRYPT_FAILED'
  | 'REPLAY'
  | 'WINDOW_EXCEEDED'

export class RatchetError extends Error {
  readonly code: RatchetErrorCode

  constructor(code: RatchetErrorCode, message: string) {
    super(message)
    this.name = 'RatchetError'
    this.code = code
  }
}

export const MAX_SKIPPED_MESSAGE_KEYS = 256

const RATCHET_INFO = 'gt-remote-ratchet-v1'
const NONCE_INFO = 'gt-remote-nonce-v1'
const AAD_PREFIX = 'gt-remote-aad-v1'
const CHAIN_KEY_LENGTH = 32
const NONCE_LENGTH = 12
const TAG_LENGTH = 16

export interface RatchetOptions {
  nodeId: string
  sessionId: string
  senderId: string
  peerSenderId: string
  sendChainKey: Uint8Array
  recvChainKey: Uint8Array
}

export interface RatchetSession {
  readonly sendSeq: number
  readonly recvSeq: number
  encrypt(plaintext: Uint8Array | string): EncryptedFrame
  decrypt(frame: EncryptedFrame): Uint8Array
  encryptJson(value: unknown): EncryptedFrame
  decryptJson<T = unknown>(frame: EncryptedFrame): T
}

function assertIdentifier(value: string, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RatchetError('INVALID_CONFIG', `${label} must be a non-empty string`)
  }
  if (value.includes('|')) throw new RatchetError('INVALID_CONFIG', `${label} must not contain "|"`)
  return value
}

function assertChainKey(value: unknown, label: string): Uint8Array {
  try {
    return assertBytes(value, label, CHAIN_KEY_LENGTH).slice()
  } catch (error) {
    throw new RatchetError('INVALID_CONFIG', (error as Error).message)
  }
}

interface ChainStep {
  nextChainKey: Uint8Array
  messageKey: Uint8Array
}

function advanceChain(chainKey: Uint8Array): ChainStep {
  const okm = hkdf(sha256, chainKey, undefined, utf8Encode(RATCHET_INFO), 64)
  return {
    nextChainKey: okm.slice(0, CHAIN_KEY_LENGTH),
    messageKey: okm.slice(CHAIN_KEY_LENGTH, 64),
  }
}

function deriveNonce(chainKey: Uint8Array): Uint8Array {
  return hkdf(sha256, chainKey, undefined, utf8Encode(NONCE_INFO), NONCE_LENGTH)
}

function openMessage(messageKey: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  try {
    return chacha20poly1305(messageKey, nonce, aad).decrypt(ct)
  } catch {
    throw new RatchetError('DECRYPT_FAILED', 'message authentication failed')
  }
}

function parseFrame(frame: EncryptedFrame): { seq: number; nonce: Uint8Array; ct: Uint8Array } {
  if (!frame || typeof frame !== 'object') throw new RatchetError('INVALID_FRAME', 'frame must be an object')
  const candidate = frame as { v?: unknown; seq?: unknown; nonce?: unknown; ct?: unknown }
  if (candidate.v !== 1) throw new RatchetError('INVALID_FRAME', `unsupported frame version ${String(candidate.v)}`)
  const seq = candidate.seq
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) {
    throw new RatchetError('INVALID_FRAME', 'frame seq must be a positive integer')
  }
  if (typeof candidate.nonce !== 'string' || typeof candidate.ct !== 'string') {
    throw new RatchetError('INVALID_FRAME', 'frame nonce and ct must be base64url strings')
  }
  let nonce: Uint8Array
  let ct: Uint8Array
  try {
    nonce = assertBytes(base64UrlDecode(candidate.nonce), 'frame.nonce', NONCE_LENGTH)
    ct = base64UrlDecode(candidate.ct)
  } catch {
    throw new RatchetError('INVALID_FRAME', 'frame contains invalid base64url')
  }
  if (ct.length < TAG_LENGTH) throw new RatchetError('INVALID_FRAME', 'frame ciphertext is too short')
  return { seq, nonce, ct }
}

export function createRatchet(options: RatchetOptions): RatchetSession {
  const nodeId = assertIdentifier(options.nodeId, 'nodeId')
  const sessionId = assertIdentifier(options.sessionId, 'sessionId')
  const senderId = assertIdentifier(options.senderId, 'senderId')
  const peerSenderId = assertIdentifier(options.peerSenderId, 'peerSenderId')
  if (senderId === peerSenderId) {
    throw new RatchetError('INVALID_CONFIG', 'senderId and peerSenderId must differ')
  }

  let sendChainKey = assertChainKey(options.sendChainKey, 'sendChainKey')
  let recvChainKey = assertChainKey(options.recvChainKey, 'recvChainKey')
  let sendSeq = 1
  let recvSeq = 1
  const skippedMessageKeys = new Map<number, Uint8Array>()

  const aadFor = (id: string, seq: number): Uint8Array =>
    utf8Encode(`${AAD_PREFIX}|${nodeId}|${sessionId}|${id}|${seq}`)

  function encrypt(plaintext: Uint8Array | string): EncryptedFrame {
    let data: Uint8Array
    if (typeof plaintext === 'string') {
      try {
        data = utf8Encode(plaintext)
      } catch {
        throw new RatchetError('INVALID_INPUT', 'plaintext is not valid UTF-16')
      }
    } else if (plaintext instanceof Uint8Array) data = plaintext
    else throw new RatchetError('INVALID_INPUT', 'plaintext must be a string or Uint8Array')

    const seq = sendSeq
    const nonce = deriveNonce(sendChainKey)
    const step = advanceChain(sendChainKey)
    const ct = chacha20poly1305(step.messageKey, nonce, aadFor(senderId, seq)).encrypt(data)
    sendChainKey = step.nextChainKey
    sendSeq = seq + 1
    return { v: 1, seq, nonce: base64UrlEncode(nonce), ct: base64UrlEncode(ct) }
  }

  function decrypt(frame: EncryptedFrame): Uint8Array {
    const parsed = parseFrame(frame)
    if (parsed.seq < recvSeq) {
      const messageKey = skippedMessageKeys.get(parsed.seq)
      if (!messageKey) {
        throw new RatchetError('REPLAY', `seq ${parsed.seq} is below receive seq ${recvSeq} and not buffered`)
      }
      const plaintext = openMessage(messageKey, parsed.nonce, aadFor(peerSenderId, parsed.seq), parsed.ct)
      skippedMessageKeys.delete(parsed.seq)
      return plaintext
    }

    const gap = parsed.seq - recvSeq
    if (gap > MAX_SKIPPED_MESSAGE_KEYS || skippedMessageKeys.size + gap > MAX_SKIPPED_MESSAGE_KEYS) {
      throw new RatchetError(
        'WINDOW_EXCEEDED',
        `seq ${parsed.seq} is too far ahead of receive seq ${recvSeq}`,
      )
    }

    let chainKey = recvChainKey
    const pending: Array<{ seq: number; messageKey: Uint8Array }> = []
    for (let seq = recvSeq; seq < parsed.seq; seq += 1) {
      const step = advanceChain(chainKey)
      chainKey = step.nextChainKey
      pending.push({ seq, messageKey: step.messageKey })
    }
    const target = advanceChain(chainKey)
    const plaintext = openMessage(target.messageKey, parsed.nonce, aadFor(peerSenderId, parsed.seq), parsed.ct)

    // 认证成功后才提交接收状态，避免伪造帧破坏棘轮。
    recvChainKey = target.nextChainKey
    recvSeq = parsed.seq + 1
    for (const entry of pending) skippedMessageKeys.set(entry.seq, entry.messageKey)
    return plaintext
  }

  function encryptJson(value: unknown): EncryptedFrame {
    let json: string | undefined
    try {
      json = JSON.stringify(value)
    } catch {
      throw new RatchetError('INVALID_INPUT', 'value is not JSON serializable')
    }
    if (json === undefined) throw new RatchetError('INVALID_INPUT', 'value is not JSON serializable')
    return encrypt(json)
  }

  function decryptJson<T = unknown>(frame: EncryptedFrame): T {
    const plaintext = decrypt(frame)
    try {
      return JSON.parse(utf8Decode(plaintext)) as T
    } catch {
      throw new RatchetError('INVALID_INPUT', 'decrypted payload is not valid JSON')
    }
  }

  return {
    get sendSeq() {
      return sendSeq
    },
    get recvSeq() {
      return recvSeq
    },
    encrypt,
    decrypt,
    encryptJson,
    decryptJson,
  }
}
