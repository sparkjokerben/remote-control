/**
 * 20 位分组安全码：双方用同一对密钥包哈希计算，结果必须一致。
 */
import { sha256 } from '@noble/hashes/sha2.js'

import { utf8Encode } from './encoding'

const SAFETY_CONTEXT = 'gt-remote-safety-v1'
const SAFETY_MODULUS = 10n ** 20n
const SAFETY_DIGITS = 20
const SAFETY_BYTES = 12

export function safetyNumber(first: string, second: string): string {
  if (typeof first !== 'string' || typeof second !== 'string' || first.length === 0 || second.length === 0) {
    throw new TypeError('safetyNumber: expected two non-empty strings')
  }
  const ordered = first <= second ? [first, second] : [second, first]
  const digest = sha256(utf8Encode(`${SAFETY_CONTEXT}|${ordered[0]}|${ordered[1]}`))
  let value = 0n
  for (let i = 0; i < SAFETY_BYTES; i += 1) value = (value << 8n) | BigInt(digest[i])
  const decimal = (value % SAFETY_MODULUS).toString().padStart(SAFETY_DIGITS, '0')
  return [decimal.slice(0, 5), decimal.slice(5, 10), decimal.slice(10, 15), decimal.slice(15, 20)].join(' ')
}
