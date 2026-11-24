/**
 * 设备长期密钥包：Ed25519 签名身份 + X25519 身份 DH + 签名预共享密钥（SPK）。
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { assertBytes, base64UrlDecode, base64UrlEncode, bytesEqual, utf8Encode } from './encoding'
import type { Rng } from './random'

export interface DeviceKeyBundle {
  keyId: string
  ikSignPub: string
  ikDhPub: string
  spkPub: string
  spkSig: string
}

export interface DevicePrivateKeys {
  ikSignPriv: string
  ikDhPriv: string
  spkPriv: string
}

export interface DeviceKeyMaterial {
  bundle: DeviceKeyBundle
  privateKeys: DevicePrivateKeys
}

export interface DecodedDeviceBundle {
  keyId: Uint8Array
  ikSignPub: Uint8Array
  ikDhPub: Uint8Array
  spkPub: Uint8Array
  spkSig: Uint8Array
}

export interface DecodedPrivateKeys {
  ikSignPriv: Uint8Array
  ikDhPriv: Uint8Array
  spkPriv: Uint8Array
}

const KEY_ID_LENGTH = 32
const PUBLIC_KEY_LENGTH = 32
const SIGNATURE_LENGTH = 64
const SPK_CONTEXT = 'gt-remote-spk-v1'

function randomKey(rng: Rng, label: string): Uint8Array {
  if (typeof rng !== 'function') throw new TypeError(`${label}: rng must be a function`)
  return assertBytes(rng(32), label, 32).slice()
}

function decodeBase64Url(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string') throw new TypeError(`${label}: expected base64url string`)
  return base64UrlDecode(value)
}

function spkSignaturePayload(keyId: string, spkPub: string): Uint8Array {
  return utf8Encode(`${SPK_CONTEXT}|${keyId}|${spkPub}`)
}

export function generateDeviceKeys(rng: Rng): DeviceKeyMaterial {
  const ikSignPriv = randomKey(rng, 'generateDeviceKeys ikSignPriv')
  const ikSignPub = ed25519.getPublicKey(ikSignPriv)
  const ikDhPriv = randomKey(rng, 'generateDeviceKeys ikDhPriv')
  const ikDhPub = x25519.getPublicKey(ikDhPriv)
  const spkPriv = randomKey(rng, 'generateDeviceKeys spkPriv')
  const spkPub = x25519.getPublicKey(spkPriv)

  const keyId = base64UrlEncode(sha256(ikSignPub))
  const spkPubEncoded = base64UrlEncode(spkPub)
  const spkSig = ed25519.sign(spkSignaturePayload(keyId, spkPubEncoded), ikSignPriv)

  return {
    bundle: {
      keyId,
      ikSignPub: base64UrlEncode(ikSignPub),
      ikDhPub: base64UrlEncode(ikDhPub),
      spkPub: spkPubEncoded,
      spkSig: base64UrlEncode(spkSig),
    },
    privateKeys: {
      ikSignPriv: base64UrlEncode(ikSignPriv),
      ikDhPriv: base64UrlEncode(ikDhPriv),
      spkPriv: base64UrlEncode(spkPriv),
    },
  }
}

export function decodeDeviceBundle(bundle: DeviceKeyBundle): DecodedDeviceBundle {
  if (!bundle || typeof bundle !== 'object') throw new TypeError('decodeDeviceBundle: expected object')
  const decoded: DecodedDeviceBundle = {
    keyId: assertBytes(decodeBase64Url(bundle.keyId, 'bundle.keyId'), 'bundle.keyId', KEY_ID_LENGTH),
    ikSignPub: assertBytes(decodeBase64Url(bundle.ikSignPub, 'bundle.ikSignPub'), 'bundle.ikSignPub', PUBLIC_KEY_LENGTH),
    ikDhPub: assertBytes(decodeBase64Url(bundle.ikDhPub, 'bundle.ikDhPub'), 'bundle.ikDhPub', PUBLIC_KEY_LENGTH),
    spkPub: assertBytes(decodeBase64Url(bundle.spkPub, 'bundle.spkPub'), 'bundle.spkPub', PUBLIC_KEY_LENGTH),
    spkSig: assertBytes(decodeBase64Url(bundle.spkSig, 'bundle.spkSig'), 'bundle.spkSig', SIGNATURE_LENGTH),
  }
  return decoded
}

export function decodeDevicePrivateKeys(privateKeys: DevicePrivateKeys): DecodedPrivateKeys {
  if (!privateKeys || typeof privateKeys !== 'object') {
    throw new TypeError('decodeDevicePrivateKeys: expected object')
  }
  return {
    ikSignPriv: assertBytes(
      decodeBase64Url(privateKeys.ikSignPriv, 'privateKeys.ikSignPriv'),
      'privateKeys.ikSignPriv',
      PUBLIC_KEY_LENGTH,
    ),
    ikDhPriv: assertBytes(
      decodeBase64Url(privateKeys.ikDhPriv, 'privateKeys.ikDhPriv'),
      'privateKeys.ikDhPriv',
      PUBLIC_KEY_LENGTH,
    ),
    spkPriv: assertBytes(
      decodeBase64Url(privateKeys.spkPriv, 'privateKeys.spkPriv'),
      'privateKeys.spkPriv',
      PUBLIC_KEY_LENGTH,
    ),
  }
}

export function verifyDeviceBundle(bundle: DeviceKeyBundle): boolean {
  try {
    const decoded = decodeDeviceBundle(bundle)
    if (!bytesEqual(decoded.keyId, sha256(decoded.ikSignPub))) return false
    if (!ed25519.utils.isValidPublicKey(decoded.ikSignPub)) return false
    return ed25519.verify(
      decoded.spkSig,
      spkSignaturePayload(bundle.keyId, bundle.spkPub),
      decoded.ikSignPub,
    )
  } catch {
    return false
  }
}

export function bundleHash(bundle: DeviceKeyBundle): string {
  const canonical = {
    keyId: bundle.keyId,
    ikSignPub: bundle.ikSignPub,
    ikDhPub: bundle.ikDhPub,
    spkPub: bundle.spkPub,
    spkSig: bundle.spkSig,
  }
  return base64UrlEncode(sha256(utf8Encode(JSON.stringify(canonical))))
}
