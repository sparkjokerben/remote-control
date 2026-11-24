/**
 * 显式注入的随机源。小程序没有 globalThis.crypto 时用 wx.getRandomValues 取一次 32B
 * 种子交给 createSeededRng，其余场景直接使用 systemRng。
 */
import { chacha20 } from '@noble/ciphers/chacha.js'

import { assertBytes } from './encoding'

export type Rng = (length: number) => Uint8Array

const CHACHA_BLOCK_SIZE = 64
const MAX_GET_RANDOM_VALUES_CHUNK = 65536

interface CryptoLike {
  getRandomValues<T extends ArrayBufferView>(array: T): T
}

function assertLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError(`rng: invalid byte length ${String(length)}`)
  }
}

function randomSource(): CryptoLike | undefined {
  const candidate = (globalThis as unknown as { crypto?: unknown }).crypto
  if (!candidate || typeof candidate !== 'object') return undefined
  const source = candidate as { getRandomValues?: unknown }
  if (typeof source.getRandomValues !== 'function') return undefined
  return candidate as CryptoLike
}

export function systemRng(length: number): Uint8Array {
  assertLength(length)
  const source = randomSource()
  if (!source) {
    throw new Error(
      'systemRng: globalThis.crypto.getRandomValues is unavailable; inject an Rng such as wx.getRandomValues',
    )
  }
  const out = new Uint8Array(length)
  for (let offset = 0; offset < length; offset += MAX_GET_RANDOM_VALUES_CHUNK) {
    const end = Math.min(offset + MAX_GET_RANDOM_VALUES_CHUNK, length)
    source.getRandomValues(out.subarray(offset, end))
  }
  return out
}

/**
 * ChaCha20 keystream 派生的确定性 RNG。每次调用使用独立的 32-bit 流编号写入 nonce，
 * 同一种子必然复现同一字节序列。
 */
export function createSeededRng(seed: Uint8Array): Rng {
  const key = assertBytes(seed, 'createSeededRng(seed)', 32).slice()
  let streamCounter = 0
  return (length: number): Uint8Array => {
    assertLength(length)
    if (length === 0) return new Uint8Array(0)
    const blocks = Math.ceil(length / CHACHA_BLOCK_SIZE)
    if (streamCounter + blocks > 0xffffffff) throw new Error('createSeededRng: keystream exhausted')
    const nonce = new Uint8Array(12)
    new DataView(nonce.buffer).setUint32(8, streamCounter, false)
    const keystream = chacha20(key, nonce, new Uint8Array(blocks * CHACHA_BLOCK_SIZE))
    streamCounter += blocks
    return keystream.slice(0, length)
  }
}
