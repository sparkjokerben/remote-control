import { describe, expect, it } from 'vitest'

import { utf8Decode } from '../../src/crypto/encoding'
import {
  acceptHandshakeInit,
  completeHandshake,
  createHandshakeInit,
  HandshakeError,
  type AcceptHandshakeResult,
  type HandshakeAck,
  type HandshakeInit,
} from '../../src/crypto/handshake'
import { bundleHash, generateDeviceKeys, type DeviceKeyMaterial } from '../../src/crypto/keys'
import { createSeededRng } from '../../src/crypto/random'
import { createRatchet } from '../../src/crypto/ratchet'
import { safetyNumber } from '../../src/crypto/safety'

function seed(value: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (value * 29 + index * 13) & 0xff)
}

function material(value: number): DeviceKeyMaterial {
  return generateDeviceKeys(createSeededRng(seed(value)))
}

function flipBase64(value: string): string {
  return (value[0] === 'A' ? 'B' : 'A') + value.slice(1)
}

function setup(pins: { clientPin?: string; nodePin?: string } = {}) {
  const node = material(1)
  const client = material(2)
  const nodeId = node.bundle.keyId
  const created = createHandshakeInit({
    nodeId,
    sessionId: 'session-1',
    clientId: 'client-1',
    identity: client,
    nodeKey: node.bundle,
    rng: createSeededRng(seed(3)),
    pinnedNodeHash: pins.nodePin,
  })
  const accepted = acceptHandshakeInit({
    nodeId,
    init: created.init,
    identity: node,
    rng: createSeededRng(seed(4)),
    pinnedClientHash: pins.clientPin,
  })
  return { node, client, nodeId, created, accepted }
}

function successful(result: AcceptHandshakeResult) {
  expect(result.ok).toBe(true)
  if (!result.ok) throw new Error(`handshake rejected: ${result.error.code} ${result.error.message}`)
  return result
}

describe('X3DH handshake', () => {
  it('completes on both sides with identical safety numbers and mirrored chains', () => {
    const { node, client, nodeId, created, accepted } = setup()
    const result = successful(accepted)
    expect(result.ack.t).toBe('handshake.ack')
    expect(result.peerBundleHash).toBe(bundleHash(client.bundle))

    const completed = completeHandshake(created.context, result.ack)
    expect(completed.ok).toBe(true)
    if (!completed.ok) throw new Error(`handshake completion rejected: ${completed.error.code}`)

    const expectedSafety = safetyNumber(bundleHash(node.bundle), bundleHash(client.bundle))
    expect(result.session.safetyNumber).toBe(expectedSafety)
    expect(completed.session.safetyNumber).toBe(expectedSafety)
    expect(completed.session.peerBundleHash).toBe(bundleHash(node.bundle))
    expect(completed.session.sendChainKey).toEqual(result.session.recvChainKey)
    expect(completed.session.recvChainKey).toEqual(result.session.sendChainKey)
    expect(completed.session.sendSenderId).toBe('client-1')
    expect(result.session.sendSenderId).toBe(nodeId)
  })

  it('derives usable ratchets on both directions', () => {
    const { created, accepted } = setup()
    const result = successful(accepted)
    const nodeSession = result.session
    const completed = completeHandshake(created.context, result.ack)
    if (!completed.ok) throw new Error(completed.error.code)
    const clientSession = completed.session

    const client = createRatchet({
      nodeId: clientSession.nodeId,
      sessionId: clientSession.sessionId,
      senderId: clientSession.sendSenderId,
      peerSenderId: clientSession.recvSenderId,
      sendChainKey: clientSession.sendChainKey,
      recvChainKey: clientSession.recvChainKey,
    })
    const node = createRatchet({
      nodeId: nodeSession.nodeId,
      sessionId: nodeSession.sessionId,
      senderId: nodeSession.sendSenderId,
      peerSenderId: nodeSession.recvSenderId,
      sendChainKey: nodeSession.sendChainKey,
      recvChainKey: nodeSession.recvChainKey,
    })

    expect(utf8Decode(node.decrypt(client.encrypt('ping')))).toBe('ping')
    expect(utf8Decode(client.decrypt(node.encrypt('pong')))).toBe('pong')
  })

  it('rejects a tampered init signature', () => {
    const { node, created } = setup()
    const tampered = { ...created.init, signature: flipBase64(created.init.signature) }
    const accepted = acceptHandshakeInit({
      nodeId: node.bundle.keyId,
      init: tampered,
      identity: node,
      rng: createSeededRng(seed(5)),
    })
    expect(accepted.ok).toBe(false)
    if (accepted.ok) return
    expect(accepted.error.code).toBe('INVALID_SIGNATURE')
    expect(accepted.error.t).toBe('handshake.err')
  })

  it('rejects a tampered ack signature', () => {
    const { created, accepted } = setup()
    const ack = successful(accepted).ack
    const tampered: HandshakeAck = { ...ack, signature: flipBase64(ack.signature) }
    const completed = completeHandshake(created.context, tampered)
    expect(completed.ok).toBe(false)
    if (completed.ok) return
    expect(completed.error.code).toBe('INVALID_SIGNATURE')
  })

  it('rejects a tampered ack ephemeral key', () => {
    const { created, accepted } = setup()
    const ack = successful(accepted).ack
    const tampered: HandshakeAck = { ...ack, ephemeralPub: flipBase64(ack.ephemeralPub) }
    const completed = completeHandshake(created.context, tampered)
    expect(completed.ok).toBe(false)
    if (completed.ok) return
    expect(completed.error.code).toBe('INVALID_SIGNATURE')
  })

  it('rejects an ack carrying a different node bundle', () => {
    const { created, accepted } = setup()
    const ack = successful(accepted).ack
    const completed = completeHandshake(created.context, { ...ack, nodeKey: material(42).bundle })
    expect(completed.ok).toBe(false)
    if (!completed.ok) expect(completed.error.code).toBe('INVALID_SIGNATURE')
  })

  it('rejects transcript mismatch and unsupported versions', () => {
    const { node, created, accepted } = setup()
    const ack = successful(accepted).ack

    const wrongClient = completeHandshake(created.context, { ...ack, clientId: 'other-client' })
    expect(wrongClient.ok).toBe(false)
    if (!wrongClient.ok) expect(wrongClient.error.code).toBe('INVALID_SIGNATURE')

    const wrongVersion = completeHandshake(created.context, { ...ack, v: 2 } as unknown as HandshakeAck)
    expect(wrongVersion.ok).toBe(false)
    if (!wrongVersion.ok) expect(wrongVersion.error.code).toBe('UNSUPPORTED_VERSION')

    const oldVersion = acceptHandshakeInit({
      nodeId: node.bundle.keyId,
      init: { ...created.init, v: 2 } as unknown as HandshakeInit,
      identity: node,
      rng: createSeededRng(seed(6)),
    })
    expect(oldVersion.ok).toBe(false)
    if (!oldVersion.ok) expect(oldVersion.error.code).toBe('UNSUPPORTED_VERSION')
  })

  it('rejects a foreign nodeId on the accepting side', () => {
    const { node, created } = setup()
    const accepted = acceptHandshakeInit({
      nodeId: 'node-2',
      init: created.init,
      identity: node,
      rng: createSeededRng(seed(7)),
    })
    expect(accepted.ok).toBe(false)
    if (!accepted.ok) expect(accepted.error.code).toBe('INVALID_SIGNATURE')
  })

  it('rejects a substituted client bundle', () => {
    const { node, created, client } = setup()
    const replacement = material(8)
    expect(replacement.bundle).not.toEqual(client.bundle)
    const accepted = acceptHandshakeInit({
      nodeId: node.bundle.keyId,
      init: { ...created.init, clientKey: replacement.bundle },
      identity: node,
      rng: createSeededRng(seed(9)),
    })
    expect(accepted.ok).toBe(false)
    if (!accepted.ok) expect(accepted.error.code).toBe('INVALID_SIGNATURE')
  })

  it('rejects a nodeId that does not match the node key bundle keyId', () => {
    const node = material(25)
    const client = material(26)
    try {
      createHandshakeInit({
        nodeId: 'relay-chosen-node',
        sessionId: 'session-1',
        clientId: 'client-1',
        identity: client,
        nodeKey: node.bundle,
        rng: createSeededRng(seed(27)),
      })
      throw new Error('expected HandshakeError')
    } catch (error) {
      expect(error).toBeInstanceOf(HandshakeError)
      expect((error as HandshakeError).code).toBe('INVALID_SIGNATURE')
    }
  })
})

describe('TOFU pinning', () => {
  it('accepts a matching client pin and reports the peer hash', () => {
    const node = material(10)
    const client = material(11)
    const init = createHandshakeInit({
      nodeId: node.bundle.keyId,
      sessionId: 'session-1',
      clientId: 'client-1',
      identity: client,
      nodeKey: node.bundle,
      rng: createSeededRng(seed(12)),
    })
    const result = acceptHandshakeInit({
      nodeId: node.bundle.keyId,
      init: init.init,
      identity: node,
      rng: createSeededRng(seed(13)),
      pinnedClientHash: bundleHash(client.bundle),
    })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.peerBundleHash).toBe(bundleHash(client.bundle))
  })

  it('blocks a changed client identity key with IDENTITY_KEY_CHANGED and peerKey', () => {
    const node = material(14)
    const oldClient = material(15)
    const newClient = material(16)
    const first = acceptHandshakeInit({
      nodeId: node.bundle.keyId,
      init: createHandshakeInit({
        nodeId: node.bundle.keyId,
        sessionId: 'session-1',
        clientId: 'client-1',
        identity: oldClient,
        nodeKey: node.bundle,
        rng: createSeededRng(seed(17)),
      }).init,
      identity: node,
      rng: createSeededRng(seed(18)),
    })
    const pinned = successful(first).peerBundleHash
    const second = acceptHandshakeInit({
      nodeId: node.bundle.keyId,
      init: createHandshakeInit({
        nodeId: node.bundle.keyId,
        sessionId: 'session-1',
        clientId: 'client-1',
        identity: newClient,
        nodeKey: node.bundle,
        rng: createSeededRng(seed(19)),
      }).init,
      identity: node,
      rng: createSeededRng(seed(20)),
      pinnedClientHash: pinned,
    })
    expect(second.ok).toBe(false)
    if (second.ok) return
    expect(second.error.code).toBe('IDENTITY_KEY_CHANGED')
    expect(second.error.peerKey).toEqual(newClient.bundle)
  })

  it('blocks a changed node identity key before sending the init', () => {
    const node = material(21)
    const client = material(22)
    try {
      createHandshakeInit({
        nodeId: node.bundle.keyId,
        sessionId: 'session-1',
        clientId: 'client-1',
        identity: client,
        nodeKey: node.bundle,
        rng: createSeededRng(seed(23)),
        pinnedNodeHash: bundleHash(material(24).bundle),
      })
      throw new Error('expected HandshakeError')
    } catch (error) {
      expect(error).toBeInstanceOf(HandshakeError)
      expect((error as HandshakeError).code).toBe('IDENTITY_KEY_CHANGED')
      expect((error as HandshakeError).peerKey).toEqual(node.bundle)
    }
  })

  it('rechecks the node pin when completing the handshake', () => {
    const { created, accepted } = setup()
    const ack = successful(accepted).ack
    created.context.pinnedNodeHash = 'stale-pin'
    const completed = completeHandshake(created.context, ack)
    expect(completed.ok).toBe(false)
    if (completed.ok) return
    expect(completed.error.code).toBe('IDENTITY_KEY_CHANGED')
    expect(completed.error.peerKey).toEqual(ack.nodeKey)
  })
})
