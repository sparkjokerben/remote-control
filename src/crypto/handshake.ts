/**
 * 1-RTT X3DH 握手（契约 §2.3）：客户端（小程序）发起，节点（dsh）应答。
 * 双方用 4 个 DH 与 bundle 哈希派生根密钥，再分出方向链；签名覆盖 transcript。
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { assertBytes, base64UrlDecode, base64UrlEncode, bytesEqual, concatBytes, utf8Encode } from './encoding'
import {
  bundleHash,
  decodeDeviceBundle,
  decodeDevicePrivateKeys,
  verifyDeviceBundle,
  type DecodedDeviceBundle,
  type DecodedPrivateKeys,
  type DeviceKeyBundle,
  type DeviceKeyMaterial,
} from './keys'
import type { Rng } from './random'
import { safetyNumber } from './safety'

export interface HandshakeInit {
  t: 'handshake.init'
  v: 1
  nodeId: string
  sessionId: string
  clientId: string
  clientKey: DeviceKeyBundle
  ephemeralPub: string
  signature: string
}

export interface HandshakeAck {
  t: 'handshake.ack'
  v: 1
  nodeId: string
  sessionId: string
  clientId: string
  nodeKey: DeviceKeyBundle
  ephemeralPub: string
  signature: string
  safetyNumber: string
}

export type HandshakeErrorCode = 'IDENTITY_KEY_CHANGED' | 'INVALID_SIGNATURE' | 'UNSUPPORTED_VERSION'

export interface HandshakeErr {
  t: 'handshake.err'
  v: 1
  nodeId: string
  sessionId: string
  code: HandshakeErrorCode
  message?: string
  peerKey?: DeviceKeyBundle
}

export class HandshakeError extends Error {
  readonly code: HandshakeErrorCode
  readonly peerKey?: DeviceKeyBundle

  constructor(code: HandshakeErrorCode, message: string, peerKey?: DeviceKeyBundle) {
    super(message)
    this.name = 'HandshakeError'
    this.code = code
    this.peerKey = peerKey
  }
}

export interface HandshakeSession {
  nodeId: string
  sessionId: string
  clientId: string
  sendSenderId: string
  recvSenderId: string
  sendChainKey: Uint8Array
  recvChainKey: Uint8Array
  safetyNumber: string
  peerBundleHash: string
}

export interface ClientHandshakeContext {
  nodeId: string
  sessionId: string
  clientId: string
  clientKey: DeviceKeyBundle
  nodeKey: DeviceKeyBundle
  clientBundleHash: string
  nodeBundleHash: string
  clientEphemeralPub: string
  ephemeralPriv: Uint8Array
  ikDhPriv: Uint8Array
  pinnedNodeHash?: string
}

export interface CreateHandshakeInitOptions {
  nodeId: string
  sessionId: string
  clientId: string
  identity: DeviceKeyMaterial
  nodeKey: DeviceKeyBundle
  rng: Rng
  pinnedNodeHash?: string
}

export interface AcceptHandshakeInitOptions {
  nodeId: string
  init: HandshakeInit
  identity: DeviceKeyMaterial
  rng: Rng
  pinnedClientHash?: string
}

export interface HandshakeFailure {
  ok: false
  error: HandshakeErr
}

export interface AcceptHandshakeSuccess {
  ok: true
  ack: HandshakeAck
  session: HandshakeSession
  peerBundleHash: string
}

export type AcceptHandshakeResult = AcceptHandshakeSuccess | HandshakeFailure

export interface CompleteHandshakeSuccess {
  ok: true
  session: HandshakeSession
  peerBundleHash: string
}

export type CompleteHandshakeResult = CompleteHandshakeSuccess | HandshakeFailure

const PROTOCOL_VERSION = 1
const DH_KEY_LENGTH = 32
const SIGNATURE_LENGTH = 64

function assertIdentifier(value: string, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new HandshakeError('INVALID_SIGNATURE', `${label} must be a non-empty string`)
  if (value.includes('|')) throw new HandshakeError('INVALID_SIGNATURE', `${label} must not contain "|"`)
  return value
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function randomKey(rng: Rng, label: string): Uint8Array {
  if (typeof rng !== 'function') throw new HandshakeError('INVALID_SIGNATURE', `${label}: rng must be a function`)
  return assertBytes(rng(32), label, 32).slice()
}

function decodeBase64Url(value: unknown, label: string, length: number): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label}: expected base64url string`)
  return assertBytes(base64UrlDecode(value), label, length)
}

function verifySignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey)
  } catch {
    return false
  }
}

function decodeLocalIdentity(identity: DeviceKeyMaterial): {
  bundle: DecodedDeviceBundle
  privateKeys: DecodedPrivateKeys
} {
  if (!verifyDeviceBundle(identity.bundle)) {
    throw new HandshakeError('INVALID_SIGNATURE', 'local device key bundle is invalid')
  }
  const bundle = decodeDeviceBundle(identity.bundle)
  const privateKeys = decodeDevicePrivateKeys(identity.privateKeys)
  if (!bytesEqual(ed25519.getPublicKey(privateKeys.ikSignPriv), bundle.ikSignPub)) {
    throw new HandshakeError('INVALID_SIGNATURE', 'local Ed25519 identity key does not match its bundle')
  }
  if (!bytesEqual(x25519.getPublicKey(privateKeys.ikDhPriv), bundle.ikDhPub)) {
    throw new HandshakeError('INVALID_SIGNATURE', 'local X25519 identity key does not match its bundle')
  }
  if (!bytesEqual(x25519.getPublicKey(privateKeys.spkPriv), bundle.spkPub)) {
    throw new HandshakeError('INVALID_SIGNATURE', 'local signed prekey does not match its bundle')
  }
  return { bundle, privateKeys }
}

function sortPair(first: string, second: string): [string, string] {
  return first <= second ? [first, second] : [second, first]
}

function sessionSalt(clientBundleHash: string, nodeBundleHash: string): Uint8Array {
  const [first, second] = sortPair(clientBundleHash, nodeBundleHash)
  return sha256(utf8Encode(`${first}|${second}`))
}

function initSignaturePayload(input: {
  nodeId: string
  sessionId: string
  clientId: string
  clientBundleHash: string
  nodeBundleHash: string
  ephemeralPub: string
}): Uint8Array {
  return utf8Encode(
    `gt-remote-x3dh-init-v1|${input.nodeId}|${input.sessionId}|${input.clientId}|${input.clientBundleHash}|${input.nodeBundleHash}|${input.ephemeralPub}`,
  )
}

function ackSignaturePayload(input: {
  nodeId: string
  sessionId: string
  clientId: string
  nodeBundleHash: string
  clientBundleHash: string
  nodeEphemeralPub: string
  clientEphemeralPub: string
}): Uint8Array {
  return utf8Encode(
    `gt-remote-x3dh-ack-v1|${input.nodeId}|${input.sessionId}|${input.clientId}|${input.nodeBundleHash}|${input.clientBundleHash}|${input.nodeEphemeralPub}|${input.clientEphemeralPub}`,
  )
}

interface DirectionalChains {
  nodeToClient: Uint8Array
  clientToNode: Uint8Array
}

function deriveChains(ikm: Uint8Array, salt: Uint8Array, nodeId: string, sessionId: string): DirectionalChains {
  const root = hkdf(sha256, ikm, salt, utf8Encode(`gt-remote-x3dh-v1|${nodeId}|${sessionId}`), 32)
  return {
    nodeToClient: hkdf(sha256, root, undefined, utf8Encode('gt-remote-chain-v1|n2c'), 32),
    clientToNode: hkdf(sha256, root, undefined, utf8Encode('gt-remote-chain-v1|c2n'), 32),
  }
}

function buildSession(input: {
  nodeId: string
  sessionId: string
  clientId: string
  role: 'node' | 'client'
  clientBundleHash: string
  nodeBundleHash: string
  chains: DirectionalChains
}): HandshakeSession {
  const fromNode = input.role === 'node'
  return {
    nodeId: input.nodeId,
    sessionId: input.sessionId,
    clientId: input.clientId,
    sendSenderId: fromNode ? input.nodeId : input.clientId,
    recvSenderId: fromNode ? input.clientId : input.nodeId,
    sendChainKey: fromNode ? input.chains.nodeToClient : input.chains.clientToNode,
    recvChainKey: fromNode ? input.chains.clientToNode : input.chains.nodeToClient,
    safetyNumber: safetyNumber(input.nodeBundleHash, input.clientBundleHash),
    peerBundleHash: fromNode ? input.clientBundleHash : input.nodeBundleHash,
  }
}

function failure(
  nodeId: string,
  sessionId: string,
  code: HandshakeErrorCode,
  message: string,
  peerKey?: DeviceKeyBundle,
): HandshakeFailure {
  const error: HandshakeErr = { t: 'handshake.err', v: PROTOCOL_VERSION, nodeId, sessionId, code, message }
  if (peerKey) error.peerKey = peerKey
  return { ok: false, error }
}

export function createHandshakeInit(options: CreateHandshakeInitOptions): {
  init: HandshakeInit
  context: ClientHandshakeContext
} {
  const nodeId = assertIdentifier(options.nodeId, 'nodeId')
  const sessionId = assertIdentifier(options.sessionId, 'sessionId')
  const clientId = assertIdentifier(options.clientId, 'clientId')
  const { privateKeys } = decodeLocalIdentity(options.identity)
  if (!verifyDeviceBundle(options.nodeKey)) {
    throw new HandshakeError('INVALID_SIGNATURE', 'node device key bundle is invalid')
  }
  // 契约 §2.2：nodeId 必须是节点设备公钥包的 keyId，防止中继替换公钥后仍冒用原 nodeId。
  if (nodeId !== options.nodeKey.keyId) {
    throw new HandshakeError('INVALID_SIGNATURE', 'node id does not match node key bundle')
  }
  const nodeBundleHash = bundleHash(options.nodeKey)
  if (options.pinnedNodeHash !== undefined && options.pinnedNodeHash !== nodeBundleHash) {
    throw new HandshakeError('IDENTITY_KEY_CHANGED', 'node identity key changed', options.nodeKey)
  }

  const clientBundleHash = bundleHash(options.identity.bundle)
  const ephemeralPriv = randomKey(options.rng, 'createHandshakeInit ephemeralPriv')
  const ephemeralPub = base64UrlEncode(x25519.getPublicKey(ephemeralPriv))
  const signature = ed25519.sign(
    initSignaturePayload({
      nodeId,
      sessionId,
      clientId,
      clientBundleHash,
      nodeBundleHash,
      ephemeralPub,
    }),
    privateKeys.ikSignPriv,
  )

  return {
    init: {
      t: 'handshake.init',
      v: PROTOCOL_VERSION,
      nodeId,
      sessionId,
      clientId,
      clientKey: options.identity.bundle,
      ephemeralPub,
      signature: base64UrlEncode(signature),
    },
    context: {
      nodeId,
      sessionId,
      clientId,
      clientKey: options.identity.bundle,
      nodeKey: options.nodeKey,
      clientBundleHash,
      nodeBundleHash,
      clientEphemeralPub: ephemeralPub,
      ephemeralPriv,
      ikDhPriv: privateKeys.ikDhPriv,
      pinnedNodeHash: options.pinnedNodeHash,
    },
  }
}

export function acceptHandshakeInit(options: AcceptHandshakeInitOptions): AcceptHandshakeResult {
  const nodeId = assertIdentifier(options.nodeId, 'nodeId')
  const init = options.init as HandshakeInit | undefined
  const initSessionId = readString(init?.sessionId)
  const initClientId = readString(init?.clientId)
  const sessionId = initSessionId ?? ''
  const fail = (code: HandshakeErrorCode, message: string, peerKey?: DeviceKeyBundle) =>
    failure(nodeId, sessionId, code, message, peerKey)

  if (!init || (init as { t?: unknown }).t !== 'handshake.init') {
    return fail('UNSUPPORTED_VERSION', 'expected handshake.init')
  }
  const { privateKeys } = decodeLocalIdentity(options.identity)
  if ((init as { v?: unknown }).v !== PROTOCOL_VERSION) {
    return fail('UNSUPPORTED_VERSION', `unsupported handshake version ${String((init as { v?: unknown }).v)}`)
  }
  if (init.nodeId !== nodeId) return fail('INVALID_SIGNATURE', 'handshake nodeId does not match this node')
  if (!initSessionId || !initClientId || initSessionId.includes('|') || initClientId.includes('|')) {
    return fail('INVALID_SIGNATURE', 'missing or invalid sessionId/clientId')
  }
  if (!verifyDeviceBundle(init.clientKey)) return fail('INVALID_SIGNATURE', 'invalid client key bundle')

  let ephemeralPub: Uint8Array
  let signature: Uint8Array
  try {
    ephemeralPub = decodeBase64Url(init.ephemeralPub, 'ephemeralPub', DH_KEY_LENGTH)
    signature = decodeBase64Url(init.signature, 'signature', SIGNATURE_LENGTH)
  } catch (error) {
    return fail('INVALID_SIGNATURE', (error as Error).message)
  }

  const clientBundle = decodeDeviceBundle(init.clientKey)
  const clientBundleHash = bundleHash(init.clientKey)
  const nodeBundleHash = bundleHash(options.identity.bundle)
  const signed = initSignaturePayload({
    nodeId,
    sessionId: initSessionId,
    clientId: initClientId,
    clientBundleHash,
    nodeBundleHash,
    ephemeralPub: init.ephemeralPub,
  })
  if (!verifySignature(signature, signed, clientBundle.ikSignPub)) {
    return fail('INVALID_SIGNATURE', 'invalid handshake signature')
  }
  if (options.pinnedClientHash !== undefined && options.pinnedClientHash !== clientBundleHash) {
    return fail('IDENTITY_KEY_CHANGED', 'client identity key changed', init.clientKey)
  }

  const nodeEphemeralPriv = randomKey(options.rng, 'acceptHandshakeInit ephemeralPriv')
  const nodeEphemeralPub = x25519.getPublicKey(nodeEphemeralPriv)
  let dh1: Uint8Array
  let dh2: Uint8Array
  let dh3: Uint8Array
  let dh4: Uint8Array
  try {
    dh1 = x25519.getSharedSecret(privateKeys.spkPriv, clientBundle.ikDhPub)
    dh2 = x25519.getSharedSecret(privateKeys.ikDhPriv, ephemeralPub)
    dh3 = x25519.getSharedSecret(privateKeys.spkPriv, ephemeralPub)
    dh4 = x25519.getSharedSecret(nodeEphemeralPriv, ephemeralPub)
  } catch {
    return fail('INVALID_SIGNATURE', 'invalid X25519 public key')
  }

  const chains = deriveChains(
    concatBytes(dh1, dh2, dh3, dh4),
    sessionSalt(clientBundleHash, nodeBundleHash),
    nodeId,
    initSessionId,
  )
  const session = buildSession({
    nodeId,
    sessionId: initSessionId,
    clientId: initClientId,
    role: 'node',
    clientBundleHash,
    nodeBundleHash,
    chains,
  })
  const signatureAck = ed25519.sign(
    ackSignaturePayload({
      nodeId,
      sessionId: initSessionId,
      clientId: initClientId,
      nodeBundleHash,
      clientBundleHash,
      nodeEphemeralPub: base64UrlEncode(nodeEphemeralPub),
      clientEphemeralPub: init.ephemeralPub,
    }),
    privateKeys.ikSignPriv,
  )
  const ack: HandshakeAck = {
    t: 'handshake.ack',
    v: PROTOCOL_VERSION,
    nodeId,
    sessionId: initSessionId,
    clientId: initClientId,
    nodeKey: options.identity.bundle,
    ephemeralPub: base64UrlEncode(nodeEphemeralPub),
    signature: base64UrlEncode(signatureAck),
    safetyNumber: session.safetyNumber,
  }
  return { ok: true, ack, session, peerBundleHash: clientBundleHash }
}

export function completeHandshake(
  context: ClientHandshakeContext,
  ack: HandshakeAck,
): CompleteHandshakeResult {
  const fail = (code: HandshakeErrorCode, message: string, peerKey?: DeviceKeyBundle) =>
    failure(context.nodeId, context.sessionId, code, message, peerKey)

  if (!context || !(context.ikDhPriv instanceof Uint8Array) || context.ikDhPriv.length !== DH_KEY_LENGTH) {
    throw new HandshakeError('INVALID_SIGNATURE', 'handshake context is missing the client identity DH key')
  }
  assertBytes(context.ephemeralPriv, 'context.ephemeralPriv', DH_KEY_LENGTH)
  if (bundleHash(context.clientKey) !== context.clientBundleHash) {
    throw new HandshakeError('INVALID_SIGNATURE', 'handshake context bundle hash does not match client key')
  }

  if (!ack || (ack as { t?: unknown }).t !== 'handshake.ack') {
    return fail('UNSUPPORTED_VERSION', 'expected handshake.ack')
  }
  if ((ack as { v?: unknown }).v !== PROTOCOL_VERSION) {
    return fail('UNSUPPORTED_VERSION', `unsupported handshake version ${String((ack as { v?: unknown }).v)}`)
  }
  if (ack.nodeId !== context.nodeId || ack.sessionId !== context.sessionId || ack.clientId !== context.clientId) {
    return fail('INVALID_SIGNATURE', 'handshake ack transcript does not match this session')
  }
  if (!verifyDeviceBundle(ack.nodeKey)) return fail('INVALID_SIGNATURE', 'invalid node key bundle')
  if (ack.nodeKey.keyId !== context.nodeId) {
    return fail('INVALID_SIGNATURE', 'node key bundle does not match node id')
  }

  const nodeBundleHash = bundleHash(ack.nodeKey)
  if (nodeBundleHash !== context.nodeBundleHash) {
    return fail('INVALID_SIGNATURE', 'node key bundle changed during handshake')
  }
  let nodeEphemeralPub: Uint8Array
  let signature: Uint8Array
  try {
    nodeEphemeralPub = decodeBase64Url(ack.ephemeralPub, 'ack.ephemeralPub', DH_KEY_LENGTH)
    signature = decodeBase64Url(ack.signature, 'ack.signature', SIGNATURE_LENGTH)
  } catch (error) {
    return fail('INVALID_SIGNATURE', (error as Error).message)
  }
  const nodeBundle = decodeDeviceBundle(ack.nodeKey)
  const signed = ackSignaturePayload({
    nodeId: context.nodeId,
    sessionId: context.sessionId,
    clientId: context.clientId,
    nodeBundleHash,
    clientBundleHash: context.clientBundleHash,
    nodeEphemeralPub: ack.ephemeralPub,
    clientEphemeralPub: context.clientEphemeralPub,
  })
  if (!verifySignature(signature, signed, nodeBundle.ikSignPub)) {
    return fail('INVALID_SIGNATURE', 'invalid handshake ack signature')
  }
  if (context.pinnedNodeHash !== undefined && context.pinnedNodeHash !== nodeBundleHash) {
    return fail('IDENTITY_KEY_CHANGED', 'node identity key changed', ack.nodeKey)
  }

  let dh1: Uint8Array
  let dh2: Uint8Array
  let dh3: Uint8Array
  let dh4: Uint8Array
  try {
    dh1 = x25519.getSharedSecret(context.ikDhPriv, nodeBundle.spkPub)
    dh2 = x25519.getSharedSecret(context.ephemeralPriv, nodeBundle.ikDhPub)
    dh3 = x25519.getSharedSecret(context.ephemeralPriv, nodeBundle.spkPub)
    dh4 = x25519.getSharedSecret(context.ephemeralPriv, nodeEphemeralPub)
  } catch {
    return fail('INVALID_SIGNATURE', 'invalid X25519 public key')
  }

  const chains = deriveChains(
    concatBytes(dh1, dh2, dh3, dh4),
    sessionSalt(context.clientBundleHash, nodeBundleHash),
    context.nodeId,
    context.sessionId,
  )
  const session = buildSession({
    nodeId: context.nodeId,
    sessionId: context.sessionId,
    clientId: context.clientId,
    role: 'client',
    clientBundleHash: context.clientBundleHash,
    nodeBundleHash,
    chains,
  })
  if (ack.safetyNumber !== session.safetyNumber) {
    return fail('INVALID_SIGNATURE', 'safety number mismatch')
  }
  return { ok: true, session, peerBundleHash: nodeBundleHash }
}
