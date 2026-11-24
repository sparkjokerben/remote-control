import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'

import { base64UrlDecode, base64UrlEncode, utf8Encode } from '../../src/crypto/encoding'
import {
  bundleHash,
  decodeDevicePrivateKeys,
  generateDeviceKeys,
  verifyDeviceBundle,
  type DeviceKeyBundle,
} from '../../src/crypto/keys'
import { createSeededRng } from '../../src/crypto/random'

function seed(value: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (value * 23 + index * 11) & 0xff)
}

function keys(value: number) {
  return generateDeviceKeys(createSeededRng(seed(value)))
}

describe('generateDeviceKeys', () => {
  it('is deterministic for a seeded RNG', () => {
    expect(keys(1)).toEqual(keys(1))
    expect(keys(1).bundle).not.toEqual(keys(2).bundle)
  })

  it('emits contract-sized base64url fields', () => {
    const { bundle, privateKeys } = keys(3)
    expect(bundle.keyId).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(base64UrlDecode(bundle.keyId)).toHaveLength(32)
    expect(base64UrlDecode(bundle.ikSignPub)).toHaveLength(32)
    expect(base64UrlDecode(bundle.ikDhPub)).toHaveLength(32)
    expect(base64UrlDecode(bundle.spkPub)).toHaveLength(32)
    expect(base64UrlDecode(bundle.spkSig)).toHaveLength(64)
    const decodedPrivate = decodeDevicePrivateKeys(privateKeys)
    expect(decodedPrivate.ikSignPriv).toHaveLength(32)
    expect(decodedPrivate.ikDhPriv).toHaveLength(32)
    expect(decodedPrivate.spkPriv).toHaveLength(32)
  })

  it('derives keyId from the Ed25519 public key', () => {
    const { bundle } = keys(4)
    expect(bundle.keyId).toBe(base64UrlEncode(sha256(base64UrlDecode(bundle.ikSignPub))))
  })
})

describe('verifyDeviceBundle', () => {
  it('accepts generated bundles', () => {
    for (let value = 10; value < 15; value += 1) expect(verifyDeviceBundle(keys(value).bundle)).toBe(true)
  })

  it('rejects tampered or malformed fields', () => {
    const bundle = keys(20).bundle
    const other = keys(21).bundle
    expect(verifyDeviceBundle({ ...bundle, keyId: other.keyId })).toBe(false)
    expect(verifyDeviceBundle({ ...bundle, ikSignPub: other.ikSignPub })).toBe(false)
    expect(verifyDeviceBundle({ ...bundle, spkPub: other.spkPub })).toBe(false)
    const last = bundle.spkSig.slice(-1) === 'A' ? 'B' : 'A'
    expect(verifyDeviceBundle({ ...bundle, spkSig: bundle.spkSig.slice(0, -1) + last })).toBe(false)
    expect(verifyDeviceBundle({ ...bundle, ikDhPub: 'not base64!' })).toBe(false)
    expect(verifyDeviceBundle({ ...bundle, spkSig: base64UrlEncode(new Uint8Array(63)) })).toBe(false)
    expect(verifyDeviceBundle(undefined as unknown as DeviceKeyBundle)).toBe(false)
  })
})

describe('bundleHash', () => {
  it('hashes the canonical five-field JSON in the fixed order', () => {
    const { bundle } = keys(30)
    const expected = base64UrlEncode(
      sha256(
        utf8Encode(
          JSON.stringify({
            keyId: bundle.keyId,
            ikSignPub: bundle.ikSignPub,
            ikDhPub: bundle.ikDhPub,
            spkPub: bundle.spkPub,
            spkSig: bundle.spkSig,
          }),
        ),
      ),
    )
    expect(bundleHash(bundle)).toBe(expected)
    const reordered = {
      spkSig: bundle.spkSig,
      spkPub: bundle.spkPub,
      ikDhPub: bundle.ikDhPub,
      ikSignPub: bundle.ikSignPub,
      keyId: bundle.keyId,
    }
    expect(bundleHash(reordered)).toBe(expected)
    expect(bundleHash(keys(31).bundle)).not.toBe(expected)
  })
})
