import type { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'

import type { Logger, ResolvedConfig } from './config'
import type { CredentialStore, DeviceIdentity } from './credentials'
import {
  bundleHash,
  completeHandshake,
  createHandshakeInit,
  createRatchet,
  createSeededRng,
  generateDeviceKeys,
  type HandshakeAck,
  type RatchetSession,
} from './crypto/index'
import { createSessionBridge, type BridgeDeps, type SessionBridge } from './session-bridge'
import type { Tunnel } from './tunnel'
import type { TunnelFrame } from './tunnel-protocol'

const LOG: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
}

const CONFIG: ResolvedConfig = {
  issuerUrl: 'https://www.example.com',
  relayUrl: 'wss://mp.example.com',
  clientId: 'dsh-remote',
  nodeName: 'test-node',
  notifyOnTurnEnd: true,
  notifyOnApproval: true,
}

const SESSION_ID = 'session-1'
const OTHER_SESSION_ID = 'session-2'
const CLIENT_ID = 'mp-device-1'

interface SessionStub {
  id: string
  header: { cwd: string }
  deriveMessages(): Array<Record<string, unknown>>
  snapshotEvents(): Array<Record<string, unknown>>
}

function createSessionStub(id: string): SessionStub {
  return {
    id,
    header: { cwd: '/tmp/work' },
    deriveMessages: () => [
      { id: 'm-1', role: 'user', content: [{ type: 'text', text: 'hello' }] },
      { id: 'm-2', role: 'assistant', content: [{ type: 'text', text: 'hi there' }] },
      {
        id: 'm-3',
        role: 'tool',
        content: [{ type: 'text', text: 'ok' }],
        source: { kind: 'tool', callId: 'call-1' },
        toolCallId: 'call-1',
      },
    ],
    snapshotEvents: () => [
      { type: 'user/message', seq: 0, time: 1_700_000_000_000, data: { id: 'm-1' } },
      { type: 'assistant/message', seq: 1, time: 1_700_000_000_100, data: { message: { id: 'm-2' } } },
      {
        type: 'tool/call',
        seq: 2,
        time: 1_700_000_000_200,
        data: { callId: 'call-1', name: 'bash', arguments: '{}' },
      },
      { type: 'tool/result', seq: 3, time: 1_700_000_000_300, data: { message: { id: 'm-3', toolCallId: 'call-1' } } },
    ],
  }
}

interface Harness {
  bridge: SessionBridge
  deps: BridgeDeps
  ctx: Context
  listeners: Map<string, (...args: any[]) => any>
  tunnelText: TunnelFrame[]
  tunnelBinary: Array<{ kind: number; streamId: number; payload: Uint8Array }>
  pins: Record<string, string>
  nodeIdentity: DeviceIdentity
  clientIdentity: DeviceIdentity
  clientId: string
  nodeRng: (length: number) => Uint8Array
  clientRng: (length: number) => Uint8Array
  session: SessionStub
  agent: Record<string, unknown>
  onStateChanged: ReturnType<typeof vi.fn>
  onNotify: ReturnType<typeof vi.fn>
  onNotifyCancel: ReturnType<typeof vi.fn>
}

function createHarness(): Harness {
  const nodeRng = createSeededRng(new Uint8Array(32).fill(3))
  const clientRng = createSeededRng(new Uint8Array(32).fill(7))
  const nodeIdentity: DeviceIdentity = generateDeviceKeys(nodeRng)
  const clientIdentity: DeviceIdentity = generateDeviceKeys(clientRng)
  const clientId = `mp-${clientIdentity.bundle.keyId}`
  const session = createSessionStub(SESSION_ID)
  const pins: Record<string, string> = {}
  const store: CredentialStore = {
    async load() {
      return { identity: nodeIdentity, pins: { ...pins } }
    },
    async saveGrant() {},
    async saveIdentity() {},
    async setPin(peerId, hash) {
      pins[peerId] = hash
    },
    async clearPin(peerId) {
      delete pins[peerId]
    },
    async clear() {},
  }
  const tunnelText: TunnelFrame[] = []
  const tunnelBinary: Array<{ kind: number; streamId: number; payload: Uint8Array }> = []
  const tunnel = {
    status: 'online',
    async connect() {},
    disconnect() {},
    sendText(frame: TunnelFrame) {
      tunnelText.push(frame)
    },
    sendBinary(kind: number, streamId: number, payload: Uint8Array) {
      tunnelBinary.push({ kind, streamId, payload })
    },
    onText() {
      return () => true
    },
    onBinary() {
      return () => true
    },
    onStatus() {
      return () => true
    },
    dispose() {},
  } as unknown as Tunnel
  const agent: Record<string, unknown> = {
    id: SESSION_ID,
    session,
    status: 'idle',
    model: {
      current: () => ({ provider: 'deepseek', model: 'chat' }),
      select: vi.fn(),
    },
    followup: vi.fn(),
    steer: vi.fn(),
    cancel: vi.fn(),
  }
  const services: Record<string, unknown> = {
    sessions: { get: (id: string) => (id === SESSION_ID ? session : undefined) },
    agents: {
      get: (id: string) => (id === SESSION_ID ? agent : undefined),
      list: () => [agent],
      turnBoundaryOf: () => ({ openTurnStartSeq: null }),
      resume: vi.fn(async () => ({ agent, dispose: vi.fn() })),
    },
    permissionPresets: {
      current: () => 'workspace-write',
      set: vi.fn(),
    },
    sessionTitle: { get: () => ({ title: '测试会话' }) },
  }
  const listeners = new Map<string, (...args: any[]) => any>()
  const ctx = {
    get(name: string) {
      return services[name]
    },
    on(name: string, listener: (...args: any[]) => any) {
      listeners.set(name, listener)
      return () => {
        if (listeners.get(name) === listener) listeners.delete(name)
      }
    },
  } as unknown as Context
  const onStateChanged = vi.fn()
  const onNotify = vi.fn((event: { kind: string }) => `evt-${event.kind}`)
  const onNotifyCancel = vi.fn()
  const deps: BridgeDeps = {
    config: CONFIG,
    store,
    tunnel,
    rng: nodeRng,
    log: LOG,
    onStateChanged,
    onNotify,
    onNotifyCancel,
  }
  return {
    bridge: createSessionBridge(ctx, deps),
    deps,
    ctx,
    listeners,
    tunnelText,
    tunnelBinary,
    pins,
    nodeIdentity,
    clientIdentity,
    clientId,
    nodeRng,
    clientRng,
    session,
    agent,
    onStateChanged,
    onNotify,
    onNotifyCancel,
  }
}

interface ClientReader {
  next(): any
  drain(): any[]
  pending(): number
}

function createReader(harness: Harness, ratchet: RatchetSession): ClientReader {
  let consumed = 0
  const frames = (): TunnelFrame[] => harness.tunnelText.filter((frame) => frame.t === 'e2ee.env')
  const next = (): any => {
    const frame = frames()[consumed]
    if (!frame) throw new Error('no more node frames')
    consumed += 1
    return ratchet.decryptJson(frame.frame as { v: 1; seq: number; nonce: string; ct: string })
  }
  return {
    next,
    drain() {
      const out: any[] = []
      while (consumed < frames().length) out.push(next())
      return out
    },
    pending() {
      return frames().length - consumed
    },
  }
}

async function connectClient(harness: Harness): Promise<{ ratchet: RatchetSession; reader: ClientReader }> {
  const created = createHandshakeInit({
    nodeId: harness.nodeIdentity.bundle.keyId,
    sessionId: SESSION_ID,
    clientId: harness.clientId,
    identity: harness.clientIdentity,
    nodeKey: harness.nodeIdentity.bundle,
    rng: harness.clientRng,
  })
  harness.bridge.handleText({
    t: 'e2ee.msg',
    nodeId: harness.nodeIdentity.bundle.keyId,
    sessionId: SESSION_ID,
    from: 'mp',
    msg: created.init,
  })
  // 首次连接需要主机显式批准安全码后节点才应答 ack。
  await vi.waitFor(() => {
    expect(harness.bridge.pendingApprovals()).toHaveLength(1)
  })
  const pending = harness.bridge.pendingApprovals()[0]
  const approved = await harness.bridge.approve(pending.safetyNumber)
  if (!approved.ok) throw new Error(`client approval failed: ${approved.error ?? 'unknown error'}`)
  await vi.waitFor(() => {
    expect(
      harness.tunnelText.some(
        (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.ack',
      ),
    ).toBe(true)
  })
  const ackFrame = harness.tunnelText.find(
    (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.ack',
  )
  const completed = completeHandshake(created.context, ackFrame?.msg as HandshakeAck)
  if (!completed.ok) throw new Error(`client handshake failed: ${completed.error.code}`)
  const ratchet = createRatchet({
    nodeId: harness.nodeIdentity.bundle.keyId,
    sessionId: SESSION_ID,
    senderId: completed.session.sendSenderId,
    peerSenderId: completed.session.recvSenderId,
    sendChainKey: completed.session.sendChainKey,
    recvChainKey: completed.session.recvChainKey,
  })
  await vi.waitFor(() => {
    expect(harness.tunnelText.some((frame) => frame.t === 'e2ee.env')).toBe(true)
  })
  return { ratchet, reader: createReader(harness, ratchet) }
}

async function flush(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
  await new Promise((resolve) => setTimeout(resolve, 0))
}

describe('session bridge', () => {
  it('completes the X3DH handshake and carries encrypted frames end to end', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const { ratchet, reader } = await connectClient(harness)

    expect(harness.pins[harness.clientId]).toBe(bundleHash(harness.clientIdentity.bundle))
    expect(harness.bridge.status(SESSION_ID).safetyNumber).toBeDefined()

    const snapshot = reader.drain()[0]
    expect(snapshot).toMatchObject({
      t: 'snapshot',
      sessionId: SESSION_ID,
      title: '测试会话',
      cwd: '/tmp/work',
      status: 'idle',
      model: { provider: 'deepseek', model: 'chat' },
      preset: 'workspace-write',
    })
    expect(snapshot.messages).toEqual([
      { id: 'm-1', role: 'user', text: 'hello', ts: 1_700_000_000_000 },
      { id: 'm-2', role: 'assistant', text: 'hi there', ts: 1_700_000_000_100 },
      { id: 'm-3', role: 'tool', text: 'ok', ts: 1_700_000_000_300, toolName: 'bash' },
    ])

    harness.bridge.handleText({
      t: 'e2ee.env',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      frame: ratchet.encryptJson({ t: 'prompt', text: 'continue', mode: 'followup' }),
    })
    await flush()
    expect(harness.agent.followup).toHaveBeenCalledTimes(1)

    harness.bridge.handleText({
      t: 'e2ee.env',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      frame: ratchet.encryptJson({ t: 'ping', ts: 42 }),
    })
    await flush()
    expect(reader.next()).toEqual({ t: 'pong', ts: 42 })

    harness.bridge.dispose()
  })

  it('rejects a client identity change with handshake.err and keeps the TOFU pin', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    await connectClient(harness)

    const pinned = harness.pins[harness.clientId]
    const rogueRng = createSeededRng(new Uint8Array(32).fill(11))
    const rogueIdentity = generateDeviceKeys(rogueRng)
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: harness.clientId,
      identity: rogueIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: rogueRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await vi.waitFor(() => {
      expect(
        harness.tunnelText.some(
          (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.err',
        ),
      ).toBe(true)
    })
    const err = harness.tunnelText
      .filter((frame) => frame.t === 'e2ee.msg')
      .map((frame) => frame.msg as { t?: string; code?: string })
      .find((msg) => msg.t === 'handshake.err')
    expect(err?.code).toBe('IDENTITY_KEY_CHANGED')
    expect(harness.pins[harness.clientId]).toBe(pinned)

    harness.bridge.dispose()
  })

  it('holds a first-time client until the host approves its safety number', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: harness.clientId,
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })

    await vi.waitFor(() => {
      expect(harness.bridge.pendingApprovals()).toHaveLength(1)
    })
    // 批准前不得回 ack，也不得推送快照或钉死身份。
    expect(harness.tunnelText).toHaveLength(0)
    expect(harness.pins[harness.clientId]).toBeUndefined()
    const pending = harness.bridge.pendingApprovals()[0]
    expect(pending).toMatchObject({ sessionId: SESSION_ID, clientId: harness.clientId })

    const wrong = await harness.bridge.approve('00000 00000 00000 00000')
    expect(wrong.ok).toBe(false)
    expect(harness.tunnelText).toHaveLength(0)

    // 接受无分隔的 20 位数字，主机输入习惯不必严格匹配分组。
    const approved = await harness.bridge.approve(pending.safetyNumber.replace(/\s/g, ''))
    expect(approved).toEqual({ ok: true, approved: 1 })
    expect(harness.bridge.pendingApprovals()).toHaveLength(0)
    await vi.waitFor(() => {
      expect(
        harness.tunnelText.some(
          (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.ack',
        ),
      ).toBe(true)
    })
    expect(harness.tunnelText.some((frame) => frame.t === 'e2ee.env')).toBe(true)
    expect(harness.pins[harness.clientId]).toBe(bundleHash(harness.clientIdentity.bundle))

    harness.bridge.dispose()
  })

  it('accepts a previously approved client without another approval', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    await connectClient(harness)
    const ackCount = (): number =>
      harness.tunnelText.filter(
        (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.ack',
      ).length
    const before = ackCount()

    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: harness.clientId,
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await vi.waitFor(() => {
      expect(ackCount()).toBe(before + 1)
    })
    expect(harness.bridge.pendingApprovals()).toHaveLength(0)

    harness.bridge.dispose()
  })

  it('rejects a client id that is not bound to its device key', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: 'mp-attacker-chosen',
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await vi.waitFor(() => {
      expect(
        harness.tunnelText.some(
          (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.err',
        ),
      ).toBe(true)
    })
    expect(harness.bridge.pendingApprovals()).toHaveLength(0)
    expect(harness.pins[harness.clientId]).toBeUndefined()
    expect(harness.tunnelText.some((frame) => frame.t === 'e2ee.env')).toBe(false)

    harness.bridge.dispose()
  })

  it('does not trust a legacy pin for an unbound client id', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    harness.pins['legacy-client'] = bundleHash(harness.clientIdentity.bundle)
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: 'legacy-client',
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await vi.waitFor(() => {
      expect(
        harness.tunnelText.some(
          (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.err',
        ),
      ).toBe(true)
    })
    expect(harness.tunnelText.some((frame) => frame.t === 'e2ee.env')).toBe(false)

    harness.bridge.dispose()
  })

  it('caps pending approvals per session', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    for (let index = 0; index < 5; index += 1) {
      const rng = createSeededRng(new Uint8Array(32).fill(20 + index))
      const identity = generateDeviceKeys(rng)
      const created = createHandshakeInit({
        nodeId: harness.nodeIdentity.bundle.keyId,
        sessionId: SESSION_ID,
        clientId: `mp-${identity.bundle.keyId}`,
        identity,
        nodeKey: harness.nodeIdentity.bundle,
        rng,
      })
      harness.bridge.handleText({
        t: 'e2ee.msg',
        nodeId: harness.nodeIdentity.bundle.keyId,
        sessionId: SESSION_ID,
        from: 'mp',
        msg: created.init,
      })
      if (index < 4) {
        await vi.waitFor(() => {
          expect(harness.bridge.pendingApprovals()).toHaveLength(index + 1)
        })
      } else {
        await flush()
      }
    }
    expect(harness.bridge.pendingApprovals()).toHaveLength(4)
    expect(harness.bridge.pendingApprovals().every((entry) => entry.safetyNumber.length === 23)).toBe(true)

    harness.bridge.dispose()
  })

  it('rejects a handshake whose outer sessionId differs from init.sessionId', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    await harness.bridge.toggle(OTHER_SESSION_ID, true)
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: CLIENT_ID,
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: OTHER_SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await flush()
    expect(
      harness.tunnelText.some(
        (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.ack',
      ),
    ).toBe(false)
    expect(harness.tunnelText.some((frame) => frame.t === 'e2ee.env')).toBe(false)
    expect(harness.bridge.status(SESSION_ID).safetyNumber).toBeUndefined()
    expect(harness.bridge.status(OTHER_SESSION_ID).safetyNumber).toBeUndefined()
    expect(harness.pins[CLIENT_ID]).toBeUndefined()
    harness.bridge.dispose()
  })

  it('rejects a handshake for a session that is not shared', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: OTHER_SESSION_ID,
      clientId: CLIENT_ID,
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: OTHER_SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await flush()
    expect(
      harness.tunnelText.some(
        (frame) => frame.t === 'e2ee.msg' && (frame.msg as { t?: string } | undefined)?.t === 'handshake.ack',
      ),
    ).toBe(false)
    expect(harness.pins[CLIENT_ID]).toBeUndefined()
    harness.bridge.dispose()
  })

  it('lets the local approval answer win and settles the remote copy idempotently', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const { ratchet, reader } = await connectClient(harness)
    reader.drain()

    const handler = harness.listeners.get('approval/request')
    expect(handler).toBeDefined()
    const result = await handler!(
      {
        agent: harness.agent,
        toolName: 'bash',
        callId: 'call-1',
        reason: 'run a command',
        signal: new AbortController().signal,
      },
      async () => 'rejected',
    )
    expect(result).toBe('rejected')

    const frames = reader.drain()
    const open = frames.find((frame) => frame.t === 'interaction.open')
    expect(open?.interaction).toMatchObject({ kind: 'approval', toolName: 'bash', callId: 'call-1' })
    expect(frames.filter((frame) => frame.t === 'interaction.settled')).toHaveLength(1)

    harness.bridge.handleText({
      t: 'e2ee.env',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      frame: ratchet.encryptJson({
        t: 'approval.resolve',
        interactionId: open?.interaction.id,
        outcome: 'allowed-once',
      }),
    })
    await flush()
    expect(reader.drain()).toHaveLength(0)

    harness.bridge.dispose()
  })

  it('lets the remote approval answer win the race and settles only once', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const { ratchet, reader } = await connectClient(harness)
    reader.drain()

    const handler = harness.listeners.get('approval/request')!
    let releaseLocal!: (outcome: 'rejected') => void
    const local = new Promise<'rejected'>((resolve) => {
      releaseLocal = resolve
    })
    const pending = handler(
      {
        agent: harness.agent,
        toolName: 'bash',
        callId: 'call-2',
        signal: new AbortController().signal,
      },
      () => local,
    )

    const frames = reader.drain()
    const open = frames.find((frame) => frame.t === 'interaction.open')
    expect(open).toBeDefined()

    harness.bridge.handleText({
      t: 'e2ee.env',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      frame: ratchet.encryptJson({
        t: 'approval.resolve',
        interactionId: open?.interaction.id,
        outcome: 'allowed-once',
      }),
    })
    expect(await pending).toBe('allowed-once')
    const settled = reader.drain().filter((frame) => frame.t === 'interaction.settled')
    expect(settled).toHaveLength(1)
    expect(settled[0]).toMatchObject({ interactionId: open?.interaction.id })

    releaseLocal('rejected')
    await flush()
    expect(reader.drain()).toHaveLength(0)

    harness.bridge.dispose()
  })

  it('answers question requests from the remote client', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const { ratchet, reader } = await connectClient(harness)
    reader.drain()

    const handler = harness.listeners.get('user-questions/request')!
    const pending = handler(
      {
        agent: harness.agent,
        questions: [
          {
            id: 'q1',
            question: 'Pick one',
            multiSelect: false,
            options: [{ label: 'Alpha' }, { label: 'Beta' }],
          },
        ],
        signal: new AbortController().signal,
      },
      () => new Promise(() => undefined),
    )

    const open = reader.drain().find((frame) => frame.t === 'interaction.open')
    expect(open?.interaction.questions[0]).toMatchObject({
      id: 'q1',
      question: 'Pick one',
      multiSelect: false,
      options: [
        { id: 'q1:0', label: 'Alpha' },
        { id: 'q1:1', label: 'Beta' },
      ],
    })

    harness.bridge.handleText({
      t: 'e2ee.env',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      frame: ratchet.encryptJson({
        t: 'question.answer',
        interactionId: open?.interaction.id,
        answers: [{ id: 'q1', selected: ['q1:1'] }],
      }),
    })
    await expect(pending).resolves.toEqual({ answers: [{ id: 'q1', selected: ['Beta'] }] })

    harness.bridge.dispose()
  })

  it('notifies sanitized turn events and settles pending interactions on turn end', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const { reader } = await connectClient(harness)
    reader.drain()

    const handler = harness.listeners.get('approval/request')!
    const pending = handler(
      { agent: harness.agent, toolName: 'bash', signal: new AbortController().signal },
      () => new Promise(() => undefined),
    )
    reader.drain()

    const onSessionEvent = harness.listeners.get('session/event')!
    onSessionEvent(harness.session, {
      type: 'turn/end',
      seq: 9,
      time: Date.now(),
      data: { turn: 1, reason: { kind: 'completed' } },
    })
    expect(await pending).toBe('cancelled')
    const settled = reader.drain().filter((frame) => frame.t === 'interaction.settled')
    expect(settled).toHaveLength(1)
    expect(harness.onNotify).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'turn_end', sessionId: SESSION_ID }),
    )

    onSessionEvent(harness.session, {
      type: 'turn/end',
      seq: 10,
      time: Date.now(),
      data: { turn: 2, reason: { kind: 'error', error: { message: 'secret /path' } } },
    })
    expect(harness.onNotify).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: 'turn_error', sessionId: SESSION_ID }),
    )
    for (const call of harness.onNotify.mock.calls) {
      expect(JSON.stringify(call[0])).not.toContain('/path')
    }

    harness.bridge.dispose()
  })

  it('ignores sessions that were never toggled', async () => {
    const harness = createHarness()
    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: CLIENT_ID,
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await flush()
    expect(harness.tunnelText).toHaveLength(0)
    expect(harness.bridge.shared).toEqual([])

    harness.bridge.dispose()
  })

  it('marks sessions shared and requests a state sync on toggle', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    expect(harness.bridge.shared).toEqual([SESSION_ID])
    expect(harness.onStateChanged).toHaveBeenCalled()
    await harness.bridge.toggle(SESSION_ID, false)
    expect(harness.bridge.shared).toEqual([])
    expect(harness.bridge.status(SESSION_ID)).toEqual({ shared: false })

    harness.bridge.dispose()
  })

  it('cancels the pending subscribe-message when an approval settles', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    const { ratchet, reader } = await connectClient(harness)
    reader.drain()

    const approvalListener = harness.listeners.get('approval/request')
    expect(approvalListener).toBeTypeOf('function')
    const pendingApproval = approvalListener!(
      {
        agent: { session: { id: SESSION_ID } },
        toolName: 'bash',
        callId: 'call-1',
        reason: '需要执行命令',
      },
      () => new Promise(() => undefined),
    )
    await flush()
    const opened = reader.next()
    expect(opened.t).toBe('interaction.open')
    expect(harness.onNotify).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'approval', sessionId: SESSION_ID }),
    )

    harness.bridge.handleText({
      t: 'e2ee.env',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      frame: ratchet.encryptJson({
        t: 'approval.resolve',
        interactionId: opened.interaction.id,
        outcome: 'allowed-once',
      }),
    })
    await flush()

    expect(harness.onNotifyCancel).toHaveBeenCalledWith('evt-approval')
    await expect(pendingApproval).resolves.toBe('allowed-once')

    harness.bridge.dispose()
  })

  it('resets a pinned client key so the client can pair again', async () => {
    const harness = createHarness()
    await harness.bridge.toggle(SESSION_ID, true)
    await connectClient(harness)
    expect(harness.pins[harness.clientId]).toBe(bundleHash(harness.clientIdentity.bundle))

    const reset = await harness.bridge.reset(harness.clientId)
    expect(reset.ok).toBe(true)
    expect(reset.reset).toBeGreaterThanOrEqual(1)
    expect(harness.pins[harness.clientId]).toBeUndefined()

    const created = createHandshakeInit({
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      clientId: harness.clientId,
      identity: harness.clientIdentity,
      nodeKey: harness.nodeIdentity.bundle,
      rng: harness.clientRng,
    })
    harness.bridge.handleText({
      t: 'e2ee.msg',
      nodeId: harness.nodeIdentity.bundle.keyId,
      sessionId: SESSION_ID,
      from: 'mp',
      msg: created.init,
    })
    await vi.waitFor(() => {
      expect(harness.bridge.pendingApprovals()).toHaveLength(1)
    })

    harness.bridge.dispose()
  })
})
