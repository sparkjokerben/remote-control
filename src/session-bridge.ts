/**
 * 会话远控桥（契约 §2、§2.6、§6.1）：仅对 `/remote session` 显式开启的会话生效。
 * 节点侧完成 X3DH 握手与对称棘轮，把 Session 事件转成 E2EE 消息；审批/提问
 * 与本地 answerer 的 `next()` 竞速，任一来源先结算即生效且只结算一次。
 * 首次出现的客户端必须由主机比对安全码并显式批准后才发送 ack/快照。
 */
import { randomUUID } from 'node:crypto'

import type { Context } from '@deepseek-ai/cordis'

import type { Logger, ResolvedConfig } from './config.js'
import type { CredentialStore, DeviceIdentity, PersistedState } from './credentials.js'
import {
  acceptHandshakeInit,
  createRatchet,
  generateDeviceKeys,
  RatchetError,
  verifyDeviceBundle,
  type AcceptHandshakeSuccess,
  type DeviceKeyBundle,
  type EncryptedFrame,
  type HandshakeAck,
  type HandshakeInit,
  type HandshakeSession,
  type Rng,
  type RatchetSession,
} from './crypto/index.js'
import type { Tunnel } from './tunnel.js'
import type { TunnelFrame } from './tunnel-protocol.js'

export interface BridgeDeps {
  config: ResolvedConfig
  store: CredentialStore
  tunnel: Tunnel
  rng: Rng
  log: Logger
  onStateChanged(): void
  onNotify(event: {
    kind: 'approval' | 'question' | 'turn_end' | 'turn_error'
    sessionId?: string
    title: string
    summary: string
  }): string | void
  /** 交互在 3 秒宽限内已结算时撤销订阅消息投递。 */
  onNotifyCancel(eventId: string): void
}

/** 等待主机显式批准的客户端（契约 §2.5）。 */
export interface PendingApproval {
  sessionId: string
  clientId: string
  safetyNumber: string
  receivedAt: number
}

export interface ApproveResult {
  ok: boolean
  approved: number
  error?: string
}

/** 已连接或待批准的小程序客户端。 */
export interface ClientInfo {
  sessionId: string
  clientId: string
  safetyNumber: string
  pending: boolean
}

export interface ResetResult {
  ok: boolean
  reset: number
  error?: string
}

export interface SessionBridge {
  readonly shared: string[]
  status(sessionId?: string): { shared: boolean; safetyNumber?: string }
  /** 未批准的客户端握手；主机对比安全码后用 approve() 放行。 */
  pendingApprovals(): PendingApproval[]
  approve(safetyNumber: string): Promise<ApproveResult>
  clients(): ClientInfo[]
  /** 按 clientId 或安全码清理客户端密钥钉死与待批准握手，用于小程序重装后重新配对。 */
  reset(raw: string): Promise<ResetResult>
  toggle(sessionId: string, enabled: boolean): Promise<{ ok: boolean; error?: string }>
  stopAll(): Promise<void>
  handleText(frame: TunnelFrame): void
  dispose(): void
}

export type SessionBridgeErrorCode =
  | 'REMOTE_SESSION_UNAVAILABLE'
  | 'REMOTE_SESSION_RESUME_FAILED'
  | 'REMOTE_SESSION_BAD_MESSAGE'
  | 'REMOTE_SESSION_PROMPT_FAILED'
  | 'REMOTE_SESSION_CANCEL_FAILED'
  | 'REMOTE_SESSION_INTERACTION_UNKNOWN'
  | 'REMOTE_SESSION_MODEL_FAILED'
  | 'REMOTE_SESSION_PRESET_FAILED'
  | 'REMOTE_SESSION_SNAPSHOT_FAILED'

export class SessionBridgeError extends Error {
  readonly code: SessionBridgeErrorCode

  constructor(code: SessionBridgeErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'SessionBridgeError'
    this.code = code
  }
}

/** 契约 §2.6 的加密载荷视图。 */
export interface MessageView {
  id: string
  role: 'user' | 'assistant' | 'system' | 'tool'
  text: string
  ts: number
  toolName?: string
}

export interface PendingInteraction {
  id: string
  kind: 'approval' | 'question'
  toolName?: string
  callId?: string
  reason?: string
  questions?: Array<{
    id: string
    header?: string
    question: string
    multiSelect: boolean
    options: Array<{ id: string; label: string }>
  }>
}

interface SnapshotView {
  t: 'snapshot'
  sessionId: string
  title: string
  cwd: string
  status: 'running' | 'idle'
  model?: { provider: string; model: string }
  preset?: string
  seq: number
  messages: MessageView[]
  pending: PendingInteraction[]
}

// ---- 宿主服务的最小结构类型（不引入 dsh 包类型） ---------------------------

interface HostContentBlock {
  type?: string
  text?: string
}

interface HostMessage {
  id: string
  role: string
  content?: readonly HostContentBlock[]
  source?: { kind?: string; callId?: string }
  toolCallId?: string
  isError?: boolean
}

interface HostSessionEvent {
  type: string
  seq?: number
  time?: number
  data?: Record<string, any>
}

interface HostSessionHeader {
  cwd?: string
  createdAt?: number
}

interface HostSession {
  id: string
  header?: HostSessionHeader
  deriveMessages(): HostMessage[]
  snapshotEvents?(): readonly HostSessionEvent[]
}

interface HostModelSelection {
  provider: string
  model: string
  reasoningEffort?: string
}

interface HostAgent {
  id: string
  session: HostSession
  status?: 'running' | 'idle'
  model?: {
    current?: () => HostModelSelection | undefined
    select?: (selection: HostModelSelection) => void
  }
  followup?: (message: unknown) => void
  steer?: (message: unknown) => void
  cancel?: (cause: { kind: 'user' }, options?: { keepInbox?: boolean }) => void
}

interface AgentHandleLike {
  agent: HostAgent
  dispose(): Promise<void> | void
}

interface AgentsLike {
  get?(id: string): HostAgent | undefined
  resume?(options: { resumeSessionId: string }): Promise<AgentHandleLike>
  turnBoundaryOf?(session: HostSession): { openTurnStartSeq?: number | null } | undefined
}

interface SessionsLike {
  get?(id: string): HostSession | undefined
}

interface SessionTitleLike {
  get?(session: HostSession): { title?: string } | undefined
}

interface PermissionPresetsLike {
  current?(session: HostSession): string | undefined
  set?(session: HostSession, name: string): void
}

interface HostApprovalRequest {
  agent?: HostAgent
  toolName?: string
  callId?: string
  reason?: string
  signal?: AbortSignal
}

interface HostQuestionItem {
  id: string
  header?: string
  question: string
  multiSelect?: boolean
  options?: Array<{ label: string; description?: string }>
}

interface HostQuestionRequest {
  questions?: HostQuestionItem[]
  agent?: HostAgent
  signal?: AbortSignal
  wait?: { callId?: string; timed?: boolean }
}

interface HostQuestionAnswer {
  answers: Array<{ id: string; selected: string[]; custom?: string }>
}

interface HostContextLike {
  get?(name: string): unknown
  on?(name: string, listener: (...args: any[]) => any): () => unknown
}

type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'

interface RatchetEntry {
  sessionId: string
  clientId: string
  nodeId: string
  ratchet: RatchetSession
  safetyNumber: string
}

/** 未批准客户端：握手已验签但链密钥只留在内存，批准后才发送 ack/快照。 */
interface PendingHandshake {
  sessionId: string
  clientId: string
  peerBundleHash: string
  safetyNumber: string
  receivedAt: number
  result: AcceptHandshakeSuccess
}

interface InteractionEntry {
  id: string
  sessionId: string
  kind: 'approval' | 'question'
  pending: PendingInteraction
  promise: Promise<unknown>
  resolve(value: unknown): void
  settled: boolean
  /** 已发送的订阅消息事件 ID；结算时撤销，避免用户收到过期提醒。 */
  notifyId?: string
}

interface DeltaState {
  text: string
  timer: NodeJS.Timeout | null
  seq: number
}

const DELTA_INTERVAL_MS = 40
const SETTLED_INTERACTION_TTL_MS = 5 * 60_000
const SETTLED_INTERACTION_LIMIT = 128
// E2EE 授权上限：阻止中继用大量伪造客户端耗尽内存或放大推送。
const MAX_CLIENTS_PER_SESSION = 4
const MAX_RATCHETS_TOTAL = 32
const MAX_PENDING_PER_SESSION = 4
const MAX_PENDING_TOTAL = 32
const PENDING_APPROVAL_TTL_MS = 5 * 60_000

function serviceOf<T>(ctx: Context, name: string): T | undefined {
  try {
    const read = (ctx as unknown as HostContextLike).get
    return typeof read === 'function' ? (read.call(ctx, name) as T | undefined) : undefined
  } catch {
    return undefined
  }
}

function messageOf(value: unknown): string {
  return value instanceof Error ? value.message : String(value)
}

function textOf(content: readonly HostContentBlock[] | undefined): string {
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const block of content) {
    if (block?.type === 'text' && typeof block.text === 'string') parts.push(block.text)
  }
  return parts.join('')
}

function ratchetKey(sessionId: string, clientId: string): string {
  return `${sessionId}\u0000${clientId}`
}

/** 主机输入的安全码可能丢空格或多空格；统一成 4×5 位分组。 */
function normalizeSafetyNumber(value: string): string {
  const digits = value.replace(/\D/g, '')
  if (digits.length === 20) {
    return [digits.slice(0, 5), digits.slice(5, 10), digits.slice(10, 15), digits.slice(15, 20)].join(' ')
  }
  return value.trim().replace(/\s+/g, ' ')
}

/** 客户端 id 必须是设备密钥 id 的确定性绑定（小程序为 mp-<keyId>）。 */
function clientIdBindsBundle(clientId: string, bundle: DeviceKeyBundle): boolean {
  return clientId === bundle.keyId || clientId === `mp-${bundle.keyId}`
}

/** 只读取自有属性，避免 clientId=constructor/__proto__ 命中原型链。 */
function pinOf(state: PersistedState, clientId: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(state.pins, clientId) ? state.pins[clientId] : undefined
}

/**
 * 创建会话远控桥。事件监听在创建时挂到 ctx；dispose() 负责全部清理。
 */
export function createSessionBridge(ctx: Context, deps: BridgeDeps): SessionBridge {
  const sharedIds: string[] = []
  const ratchets = new Map<string, RatchetEntry>()
  const pendingHandshakes = new Map<string, PendingHandshake>()
  const interactions = new Map<string, InteractionEntry>()
  const settledInteractions = new Map<string, number>()
  const deltaStates = new Map<string, DeltaState>()
  const callNames = new Map<string, Map<string, string>>()
  const liveSessions = new Map<string, HostSession>()
  const snapshotSeq = new Map<string, number>()
  const resumeHandles = new Map<string, AgentHandleLike>()
  const resuming = new Map<string, Promise<AgentHandleLike>>()
  const disposers: Array<() => unknown> = []
  let identityPromise: Promise<DeviceIdentity> | null = null
  let disposed = false

  const host = ctx as unknown as HostContextLike

  function onHostEvent(name: string, listener: (...args: any[]) => any): void {
    try {
      const off = host.on?.(name, listener)
      if (typeof off === 'function') disposers.push(off)
    } catch (err) {
      deps.log.warn(`session-bridge: 订阅 ${name} 失败: ${messageOf(err)}`)
    }
  }

  function isShared(sessionId: string): boolean {
    return sharedIds.includes(sessionId)
  }

  function requestStateSync(): void {
    if (disposed) return
    try {
      deps.onStateChanged()
    } catch (err) {
      deps.log.warn(`session-bridge: onStateChanged 失败: ${messageOf(err)}`)
    }
  }

  function notify(event: Parameters<BridgeDeps['onNotify']>[0]): string | void {
    try {
      return deps.onNotify(event)
    } catch (err) {
      deps.log.warn(`session-bridge: onNotify 失败: ${messageOf(err)}`)
      return undefined
    }
  }

  async function ensureIdentity(): Promise<DeviceIdentity> {
    if (!identityPromise) {
      identityPromise = (async () => {
        const state = await deps.store.load()
        if (state.identity) return state.identity
        const generated = generateDeviceKeys(deps.rng)
        await deps.store.saveIdentity(generated)
        deps.log.info(`session-bridge: 已生成 E2EE 设备密钥 ${generated.bundle.keyId}`)
        return generated
      })().catch((err: unknown) => {
        identityPromise = null
        throw err
      })
    }
    return identityPromise
  }

  async function ensureAgent(sessionId: string): Promise<HostAgent> {
    const agents = serviceOf<AgentsLike>(ctx, 'agents')
    const existing = agents?.get?.(sessionId)
    if (existing) return existing
    if (!agents?.resume) {
      throw new SessionBridgeError('REMOTE_SESSION_UNAVAILABLE', 'agent service is unavailable for this session')
    }
    const cached = resumeHandles.get(sessionId)
    if (cached) return cached.agent
    let pending = resuming.get(sessionId)
    if (!pending) {
      pending = agents.resume({ resumeSessionId: sessionId })
      resuming.set(sessionId, pending)
      void pending.finally(() => resuming.delete(sessionId)).catch(() => undefined)
    }
    let handle: AgentHandleLike
    try {
      handle = await pending
    } catch (err) {
      throw new SessionBridgeError('REMOTE_SESSION_RESUME_FAILED', `cannot resume session ${sessionId}`, err)
    }
    resumeHandles.set(sessionId, handle)
    liveSessions.set(sessionId, handle.agent.session)
    return handle.agent
  }

  function sessionOf(sessionId: string): HostSession | undefined {
    const live = serviceOf<SessionsLike>(ctx, 'sessions')?.get?.(sessionId)
    if (live) {
      liveSessions.set(sessionId, live)
      return live
    }
    return liveSessions.get(sessionId)
  }

  function ratchetsFor(sessionId: string): RatchetEntry[] {
    const out: RatchetEntry[] = []
    for (const entry of ratchets.values()) if (entry.sessionId === sessionId) out.push(entry)
    return out
  }

  function prunePendingHandshakes(): void {
    const now = Date.now()
    for (const [key, pending] of pendingHandshakes) {
      if (now - pending.receivedAt > PENDING_APPROVAL_TTL_MS) pendingHandshakes.delete(key)
    }
    while (pendingHandshakes.size > MAX_PENDING_TOTAL) {
      const oldest = pendingHandshakes.keys().next().value
      if (oldest === undefined) break
      pendingHandshakes.delete(oldest)
    }
  }

  function pendingForSession(sessionId: string): number {
    let count = 0
    for (const pending of pendingHandshakes.values()) if (pending.sessionId === sessionId) count += 1
    return count
  }

  function hasRatchetCapacity(sessionId: string, clientId: string): boolean {
    if (ratchets.has(ratchetKey(sessionId, clientId))) return true
    if (ratchetsFor(sessionId).length >= MAX_CLIENTS_PER_SESSION) return false
    return ratchets.size < MAX_RATCHETS_TOTAL
  }

  function sendHandshakeError(nodeId: string, sessionId: string, message: string): void {
    deps.tunnel.sendText({
      t: 'e2ee.msg',
      nodeId,
      sessionId,
      msg: { t: 'handshake.err', v: 1, nodeId, sessionId, code: 'INVALID_SIGNATURE', message },
    })
  }

  function installRatchet(
    sessionId: string,
    clientId: string,
    nodeId: string,
    result: AcceptHandshakeSuccess,
  ): RatchetEntry {
    const handshake: HandshakeSession = result.session
    const ratchet = createRatchet({
      nodeId,
      sessionId,
      senderId: handshake.sendSenderId,
      peerSenderId: handshake.recvSenderId,
      sendChainKey: handshake.sendChainKey,
      recvChainKey: handshake.recvChainKey,
    })
    const entry: RatchetEntry = {
      sessionId,
      clientId,
      nodeId,
      ratchet,
      safetyNumber: handshake.safetyNumber,
    }
    ratchets.set(ratchetKey(sessionId, clientId), entry)
    return entry
  }

  /** 批准只发生在主机显式比对安全码之后；批准前不发送 ack/快照。 */
  async function activatePendingHandshake(pending: PendingHandshake, identity: DeviceIdentity): Promise<boolean> {
    const nodeId = identity.bundle.keyId
    if (!isShared(pending.sessionId)) return false
    if (!hasRatchetCapacity(pending.sessionId, pending.clientId)) {
      deps.log.warn(`session-bridge: 会话 ${pending.sessionId} 的 E2EE 客户端数量已达上限，丢弃待批准客户端`)
      return false
    }
    let state: PersistedState
    try {
      state = await deps.store.load()
    } catch (err) {
      deps.log.warn(`session-bridge: 读取 TOFU 钉失败: ${messageOf(err)}`)
      return false
    }
    const pinned = pinOf(state, pending.clientId)
    // 待批准期间若该 clientId 已被钉到另一份密钥，视为身份变更并拒绝。
    if (pinned !== undefined && pinned !== pending.peerBundleHash) {
      deps.log.warn(`session-bridge: 客户端 ${pending.clientId} 的密钥在批准前发生变化，拒绝握手`)
      return false
    }
    const entry = installRatchet(pending.sessionId, pending.clientId, nodeId, pending.result)
    if (pinned === undefined) {
      try {
        await deps.store.setPin(pending.clientId, pending.peerBundleHash)
      } catch (err) {
        deps.log.warn(`session-bridge: 保存 TOFU 公钥钉失败: ${messageOf(err)}`)
      }
    }
    deps.tunnel.sendText({
      t: 'e2ee.msg',
      nodeId,
      sessionId: pending.sessionId,
      msg: pending.result.ack,
    })
    deps.log.info(`session-bridge: 会话 ${pending.sessionId} 已建立 E2EE（客户端 ${pending.clientId}，安全码 ${pending.safetyNumber}）`)
    await sendSnapshot(pending.sessionId, entry)
    return true
  }

  function emitToEntry(entry: RatchetEntry, message: unknown): void {
    let frame: EncryptedFrame
    try {
      frame = entry.ratchet.encryptJson(message)
    } catch (err) {
      deps.log.warn(`session-bridge: 加密消息失败: ${messageOf(err)}`)
      return
    }
    deps.tunnel.sendText({
      t: 'e2ee.env',
      nodeId: entry.nodeId,
      sessionId: entry.sessionId,
      frame,
    })
  }

  function emitToSession(sessionId: string, message: unknown): void {
    for (const entry of ratchetsFor(sessionId)) emitToEntry(entry, message)
  }

  function reportError(sessionId: string, code: SessionBridgeErrorCode, message: string): void {
    deps.log.warn(`session-bridge: ${code}: ${message}`)
    emitToSession(sessionId, { t: 'error', code, message })
  }

  function pruneSettled(): void {
    const now = Date.now()
    for (const [id, at] of settledInteractions) {
      if (now - at > SETTLED_INTERACTION_TTL_MS) settledInteractions.delete(id)
    }
    while (settledInteractions.size > SETTLED_INTERACTION_LIMIT) {
      const oldest = settledInteractions.keys().next().value
      if (oldest === undefined) break
      settledInteractions.delete(oldest)
    }
  }

  function settleInteraction(entry: InteractionEntry, value: unknown): boolean {
    if (entry.settled) return false
    entry.settled = true
    interactions.delete(entry.id)
    settledInteractions.set(entry.id, Date.now())
    pruneSettled()
    if (entry.notifyId) {
      try {
        deps.onNotifyCancel(entry.notifyId)
      } catch (err) {
        deps.log.warn(`session-bridge: onNotifyCancel 失败: ${messageOf(err)}`)
      }
      entry.notifyId = undefined
    }
    entry.resolve(value)
    emitToSession(entry.sessionId, { t: 'interaction.settled', interactionId: entry.id })
    return true
  }

  function openInteraction(
    sessionId: string,
    kind: 'approval' | 'question',
    pending: PendingInteraction,
  ): InteractionEntry {
    let resolve!: (value: unknown) => void
    const promise = new Promise<unknown>((accept) => {
      resolve = accept
    })
    const entry: InteractionEntry = { id: pending.id, sessionId, kind, pending, promise, resolve, settled: false }
    interactions.set(entry.id, entry)
    emitToSession(sessionId, { t: 'interaction.open', interaction: pending })
    return entry
  }

  function buildMessageViews(session: HostSession): MessageView[] {
    const names = callNames.get(session.id) ?? new Map<string, string>()
    const times = new Map<string, number>()
    let messages: HostMessage[] = []
    try {
      messages = session.deriveMessages()
    } catch (err) {
      throw new SessionBridgeError('REMOTE_SESSION_SNAPSHOT_FAILED', 'cannot derive session messages', err)
    }
    try {
      // 快照需要每条消息的原始时间与工具名；同步读取只发生在显式快照请求上。
      const events = session.snapshotEvents?.() ?? []
      for (const event of events) {
        const data = event.data
        if (event.type === 'tool/call' && typeof data?.callId === 'string') {
          names.set(data.callId, typeof data.name === 'string' ? data.name : '')
        }
        const projected = event.type === 'user/message' ? data : data?.message
        if (projected && typeof projected.id === 'string' && typeof event.time === 'number') {
          times.set(projected.id, event.time)
        }
      }
    } catch {
      // 事件扫描失败时退回 0 时间戳，不阻断快照。
    }
    const views: MessageView[] = []
    for (const message of messages) {
      if (!message || typeof message.id !== 'string') continue
      const role = message.role
      if (role === 'system' || role === 'developer') continue
      const text = textOf(message.content)
      const ts = times.get(message.id) ?? 0
      if (role === 'tool') {
        const callId = message.toolCallId ?? message.source?.callId
        const name = callId === undefined ? undefined : names.get(callId)
        const view: MessageView = { id: message.id, role: 'tool', text, ts }
        if (name) view.toolName = name
        views.push(view)
      } else if (role === 'user' || role === 'assistant') {
        views.push({ id: message.id, role, text, ts })
      }
    }
    return views
  }

  async function buildSnapshot(sessionId: string): Promise<SnapshotView> {
    let agent = serviceOf<AgentsLike>(ctx, 'agents')?.get?.(sessionId)
    let session = agent?.session ?? sessionOf(sessionId)
    if (!session) {
      agent = await ensureAgent(sessionId)
      session = agent.session
    }
    liveSessions.set(sessionId, session)

    let status: 'running' | 'idle' = agent?.status === 'running' ? 'running' : 'idle'
    try {
      const boundary = serviceOf<AgentsLike>(ctx, 'agents')?.turnBoundaryOf?.(session)
      if (boundary?.openTurnStartSeq !== null && boundary?.openTurnStartSeq !== undefined) status = 'running'
    } catch {
      // 缺少投影服务时按 Agent 状态处理。
    }

    let title = sessionId
    try {
      const snapshot = serviceOf<SessionTitleLike>(ctx, 'sessionTitle')?.get?.(session)
      if (typeof snapshot?.title === 'string' && snapshot.title) title = snapshot.title
    } catch {
      // 标题服务不可用时退回会话 id。
    }

    const view: SnapshotView = {
      t: 'snapshot',
      sessionId,
      title,
      cwd: typeof session.header?.cwd === 'string' ? session.header.cwd : process.cwd(),
      status,
      seq: (snapshotSeq.get(sessionId) ?? 0) + 1,
      messages: buildMessageViews(session),
      pending: [...interactions.values()]
        .filter((entry) => entry.sessionId === sessionId && !entry.settled)
        .map((entry) => entry.pending),
    }
    snapshotSeq.set(sessionId, view.seq)

    const selection = agent?.model?.current?.()
    if (selection && typeof selection.provider === 'string' && typeof selection.model === 'string') {
      view.model = { provider: selection.provider, model: selection.model }
    }
    try {
      const presets = serviceOf<PermissionPresetsLike>(ctx, 'permissionPresets')
      const preset = presets?.current?.(session)
      if (typeof preset === 'string' && preset) view.preset = preset
    } catch {
      // 权限预设服务不可用时省略字段。
    }
    return view
  }

  async function sendSnapshot(sessionId: string, entry?: RatchetEntry): Promise<void> {
    let view: SnapshotView
    try {
      view = await buildSnapshot(sessionId)
    } catch (err) {
      const code = err instanceof SessionBridgeError ? err.code : 'REMOTE_SESSION_SNAPSHOT_FAILED'
      reportError(sessionId, code, messageOf(err))
      return
    }
    if (entry) emitToEntry(entry, view)
    else emitToSession(sessionId, view)
  }

  function pushMessage(sessionId: string, message: MessageView): void {
    emitToSession(sessionId, { t: 'message', message })
  }

  function flushDelta(sessionId: string): void {
    const state = deltaStates.get(sessionId)
    if (!state) return
    if (state.timer) {
      clearTimeout(state.timer)
      state.timer = null
    }
    if (!state.text) return
    state.seq += 1
    const text = state.text
    state.text = ''
    emitToSession(sessionId, { t: 'delta', seq: state.seq, text })
  }

  function pushDelta(sessionId: string, text: string): void {
    let state = deltaStates.get(sessionId)
    if (!state) {
      state = { text: '', timer: null, seq: 0 }
      deltaStates.set(sessionId, state)
    }
    state.text += text
    if (state.timer === null) {
      state.timer = setTimeout(() => {
        state!.timer = null
        flushDelta(sessionId)
      }, DELTA_INTERVAL_MS)
      state.timer.unref?.()
    }
  }

  function resetDelta(sessionId: string): void {
    const state = deltaStates.get(sessionId)
    if (!state) return
    if (state.timer) clearTimeout(state.timer)
    state.timer = null
    state.text = ''
  }

  function onAssistantStream(payload: { agent?: HostAgent; frame?: { type?: string; chunk?: { type?: string; text?: string } } }): void {
    try {
      const sessionId = payload?.agent?.session?.id
      if (typeof sessionId !== 'string' || !isShared(sessionId)) return
      const frame = payload.frame
      if (!frame) return
      if (frame.type === 'start') {
        resetDelta(sessionId)
        return
      }
      if (frame.type === 'chunk') {
        if (frame.chunk?.type === 'text-delta' && typeof frame.chunk.text === 'string' && frame.chunk.text) {
          pushDelta(sessionId, frame.chunk.text)
        }
        return
      }
      if (frame.type === 'end') flushDelta(sessionId)
    } catch (err) {
      deps.log.warn(`session-bridge: 处理 assistant-stream 失败: ${messageOf(err)}`)
    }
  }

  function settleSessionInteractions(sessionId: string, approval: ApprovalOutcome): void {
    for (const entry of [...interactions.values()]) {
      if (entry.sessionId !== sessionId) continue
      settleInteraction(entry, entry.kind === 'approval' ? approval : { answers: [] })
    }
  }

  function onSessionEvent(session: HostSession, event: HostSessionEvent): void {
    try {
      if (!session || typeof session.id !== 'string' || !event || typeof event.type !== 'string') return
      liveSessions.set(session.id, session)
      const sessionId = session.id
      if (!isShared(sessionId)) return
      const data = event.data ?? {}
      const ts = typeof event.time === 'number' ? event.time : Date.now()

      switch (event.type) {
        case 'user/message': {
          pushMessage(sessionId, {
            id: typeof data.id === 'string' ? data.id : `${sessionId}:${event.seq ?? ts}`,
            role: 'user',
            text: textOf(data.content),
            ts,
          })
          return
        }
        case 'assistant/message': {
          const message = data.message
          if (!message || typeof message.id !== 'string') return
          const text = textOf(message.content)
          // 最终消息已包含完整文本，丢弃尚未 flush 的增量避免重复。
          resetDelta(sessionId)
          if (!text) return
          pushMessage(sessionId, { id: message.id, role: 'assistant', text, ts })
          return
        }
        case 'tool/call': {
          const callId = typeof data.callId === 'string' ? data.callId : ''
          if (!callId) return
          let names = callNames.get(sessionId)
          if (!names) {
            names = new Map()
            callNames.set(sessionId, names)
          }
          const name = typeof data.name === 'string' ? data.name : ''
          names.set(callId, name)
          emitToSession(sessionId, {
            t: 'tool',
            phase: 'call',
            callId,
            name,
            ...(typeof data.arguments === 'string' ? { args: data.arguments } : {}),
          })
          return
        }
        case 'tool/result': {
          const message = data.message
          const callId =
            typeof message?.toolCallId === 'string'
              ? message.toolCallId
              : typeof data.callId === 'string'
                ? data.callId
                : ''
          if (!callId) return
          const name = callNames.get(sessionId)?.get(callId) ?? ''
          emitToSession(sessionId, {
            t: 'tool',
            phase: 'result',
            callId,
            name,
            result: textOf(message?.content),
            ok: message?.isError !== true,
          })
          return
        }
        case 'turn/start': {
          resetDelta(sessionId)
          emitToSession(sessionId, { t: 'status', status: 'running' })
          requestStateSync()
          return
        }
        case 'turn/end': {
          resetDelta(sessionId)
          emitToSession(sessionId, { t: 'status', status: 'idle' })
          settleSessionInteractions(sessionId, 'cancelled')
          const reason = data.reason
          const kind = typeof reason?.kind === 'string' ? reason.kind : 'completed'
          if (kind === 'error') {
            notify({
              kind: 'turn_error',
              sessionId,
              title: '远控会话回合失败',
              summary: `会话 ${sessionId} 的回合出错，请打开远控查看`,
            })
          } else if (kind !== 'aborted') {
            notify({
              kind: 'turn_end',
              sessionId,
              title: '远控会话回合结束',
              summary: `会话 ${sessionId} 已完成一个回合`,
            })
          }
          requestStateSync()
          return
        }
        default:
          return
      }
    } catch (err) {
      deps.log.warn(`session-bridge: 处理 session/event 失败: ${messageOf(err)}`)
    }
  }

  function onApprovalRequest(request: HostApprovalRequest, next: () => Promise<ApprovalOutcome>): Promise<ApprovalOutcome> {
    const sessionId = request?.agent?.session?.id
    if (typeof sessionId !== 'string' || !isShared(sessionId)) return next()
    const pending: PendingInteraction = {
      id: randomUUID(),
      kind: 'approval',
      ...(typeof request.toolName === 'string' ? { toolName: request.toolName } : {}),
      ...(typeof request.callId === 'string' ? { callId: request.callId } : {}),
      ...(typeof request.reason === 'string' ? { reason: request.reason } : {}),
    }
    const entry = openInteraction(sessionId, 'approval', pending)
    const notifyId = notify({
      kind: 'approval',
      sessionId,
      title: '远控会话请求审批',
      summary: typeof request.toolName === 'string' && request.toolName
        ? `工具 ${request.toolName} 等待审批`
        : '有工具调用等待审批',
    })
    if (typeof notifyId === 'string') entry.notifyId = notifyId
    if (request.signal) {
      const onAbort = (): void => {
        settleInteraction(entry, 'cancelled')
      }
      if (request.signal.aborted) onAbort()
      else request.signal.addEventListener('abort', onAbort, { once: true })
    }
    const local = Promise.resolve().then(() => next())
    const settleLocal = (outcome: ApprovalOutcome): ApprovalOutcome => {
      settleInteraction(entry, outcome)
      return outcome
    }
    return Promise.race([
      local.then(settleLocal, (err: unknown) => {
        settleInteraction(entry, 'unavailable')
        throw err
      }),
      entry.promise as Promise<ApprovalOutcome>,
    ])
  }

  function questionView(request: HostQuestionRequest): {
    pending: PendingInteraction
    items: HostQuestionItem[]
  } {
    const items = Array.isArray(request.questions) ? request.questions : []
    const questions = items.map((item) => ({
      id: item.id,
      ...(typeof item.header === 'string' ? { header: item.header } : {}),
      question: item.question,
      multiSelect: item.multiSelect === true,
      options: (item.options ?? []).map((option, index) => ({
        id: `${item.id}:${index}`,
        label: option.label,
      })),
    }))
    const pending: PendingInteraction = {
      id: randomUUID(),
      kind: 'question',
      questions,
      ...(typeof request.wait?.callId === 'string' ? { callId: request.wait.callId } : {}),
    }
    return { pending, items }
  }

  function onQuestionRequest(
    request: HostQuestionRequest,
    next: () => Promise<HostQuestionAnswer>,
  ): Promise<HostQuestionAnswer> {
    const sessionId = request?.agent?.session?.id
    if (typeof sessionId !== 'string' || !isShared(sessionId)) return next()
    const { pending } = questionView(request)
    const entry = openInteraction(sessionId, 'question', pending)
    const notifyId = notify({
      kind: 'question',
      sessionId,
      title: '远控会话等待回答',
      summary: `有 ${pending.questions?.length ?? 0} 个问题等待回答`,
    })
    if (typeof notifyId === 'string') entry.notifyId = notifyId
    if (request.signal) {
      const onAbort = (): void => {
        settleInteraction(entry, { answers: [] })
      }
      if (request.signal.aborted) onAbort()
      else request.signal.addEventListener('abort', onAbort, { once: true })
    }
    const local = Promise.resolve().then(() => next())
    return Promise.race([
      local.then(
        (answer) => {
          settleInteraction(entry, answer)
          return answer
        },
        (err: unknown) => {
          settleInteraction(entry, { answers: [] })
          throw err
        },
      ),
      entry.promise as Promise<HostQuestionAnswer>,
    ])
  }

  async function handleHandshakeFrame(frame: TunnelFrame): Promise<void> {
    const outerSessionId = typeof frame.sessionId === 'string' ? frame.sessionId : ''
    const init = frame.msg as HandshakeInit | undefined
    if (!outerSessionId || !init || init.t !== 'handshake.init') {
      deps.log.debug('session-bridge: 忽略无效的握手帧')
      return
    }
    // 外层路由与 init 内的绑定字段必须一致，防止中继改写 sessionId 造成会话错绑。
    const sessionId = typeof init.sessionId === 'string' ? init.sessionId : ''
    const initNodeId = typeof init.nodeId === 'string' ? init.nodeId : ''
    const initClientId = typeof init.clientId === 'string' ? init.clientId : ''
    if (!sessionId || !initClientId) {
      deps.log.debug('session-bridge: 握手帧缺少 sessionId/clientId')
      return
    }
    if (sessionId !== outerSessionId) {
      deps.log.warn('session-bridge: 握手帧外层 sessionId 与 init.sessionId 不一致，拒绝握手')
      return
    }
    if (typeof frame.nodeId === 'string' && frame.nodeId !== initNodeId) {
      deps.log.warn('session-bridge: 握手帧外层 nodeId 与 init.nodeId 不一致，拒绝握手')
      return
    }
    if (!isShared(sessionId)) {
      deps.log.debug(`session-bridge: 会话 ${sessionId} 未开启远控，拒绝握手`)
      return
    }
    let identity: DeviceIdentity
    try {
      identity = await ensureIdentity()
    } catch (err) {
      deps.log.warn(`session-bridge: 本机 E2EE 身份不可用: ${messageOf(err)}`)
      deps.tunnel.sendText({
        t: 'e2ee.msg',
        nodeId: initNodeId,
        sessionId,
        msg: {
          t: 'handshake.err',
          v: 1,
          nodeId: initNodeId,
          sessionId,
          code: 'INVALID_SIGNATURE',
          message: 'node identity is unavailable',
        },
      })
      return
    }
    const nodeId = identity.bundle.keyId
    if (initNodeId !== nodeId) {
      deps.log.warn('session-bridge: 握手帧的 nodeId 与本机身份不一致')
      return
    }
    let state: PersistedState
    try {
      state = await deps.store.load()
    } catch (err) {
      deps.log.warn(`session-bridge: 读取 TOFU 钉失败: ${messageOf(err)}`)
      deps.tunnel.sendText({
        t: 'e2ee.msg',
        nodeId,
        sessionId,
        msg: {
          t: 'handshake.err',
          v: 1,
          nodeId,
          sessionId,
          code: 'INVALID_SIGNATURE',
          message: 'credential store is unavailable',
        },
      })
      return
    }
    const pinnedClientHash = pinOf(state, initClientId)
    if (pinnedClientHash === undefined) {
      // 首次使用的客户端不得自动 TOFU：先校验 clientId 与设备密钥的绑定，
      // 再由主机对比安全码显式批准；批准前不发送 ack，也不推送快照。
      if (!verifyDeviceBundle(init.clientKey) || !clientIdBindsBundle(initClientId, init.clientKey)) {
        deps.log.warn(`session-bridge: 客户端 ${initClientId} 的设备密钥未绑定到 clientId，拒绝握手`)
        sendHandshakeError(nodeId, sessionId, 'client identity is not authorized')
        return
      }
      if (!hasRatchetCapacity(sessionId, initClientId)) {
        deps.log.warn(`session-bridge: 会话 ${sessionId} 的 E2EE 客户端数量已达上限，拒绝握手`)
        sendHandshakeError(nodeId, sessionId, 'too many E2EE clients for this session')
        return
      }
      prunePendingHandshakes()
      const pendingKey = ratchetKey(sessionId, initClientId)
      if (!pendingHandshakes.has(pendingKey) && pendingForSession(sessionId) >= MAX_PENDING_PER_SESSION) {
        deps.log.warn(`session-bridge: 会话 ${sessionId} 的待批准客户端数量已达上限，丢弃握手`)
        return
      }
      if (!pendingHandshakes.has(pendingKey) && pendingHandshakes.size >= MAX_PENDING_TOTAL) {
        deps.log.warn('session-bridge: 待批准客户端数量已达上限，丢弃握手')
        return
      }
      const probe = acceptHandshakeInit({ nodeId, init, identity, rng: deps.rng })
      if (!probe.ok) {
        deps.log.warn(`session-bridge: 握手失败 ${probe.error.code}`)
        deps.tunnel.sendText({ t: 'e2ee.msg', nodeId, sessionId, msg: probe.error })
        return
      }
      const pending: PendingHandshake = {
        sessionId,
        clientId: initClientId,
        peerBundleHash: probe.peerBundleHash,
        safetyNumber: probe.session.safetyNumber,
        receivedAt: Date.now(),
        result: probe,
      }
      pendingHandshakes.set(pendingKey, pending)
      deps.log.warn(
        `session-bridge: 客户端 ${initClientId} 首次连接会话 ${sessionId}；` +
          `请核对安全码 ${pending.safetyNumber} 后运行 /remote approve ${pending.safetyNumber}`,
      )
      return
    }

    const result = acceptHandshakeInit({
      nodeId,
      init,
      identity,
      rng: deps.rng,
      pinnedClientHash,
    })
    if (!result.ok) {
      deps.log.warn(`session-bridge: 握手失败 ${result.error.code}`)
      deps.tunnel.sendText({ t: 'e2ee.msg', nodeId, sessionId, msg: result.error })
      return
    }
    const handshake: HandshakeSession = result.session
    // ratchet/AAD/ack/索引统一取自握手会话的绑定值，不信任外层路由字段。
    const boundSessionId = handshake.sessionId
    const boundClientId = handshake.clientId
    if (boundSessionId !== sessionId || boundClientId !== initClientId) {
      deps.log.warn('session-bridge: 握手会话的 sessionId/clientId 与 init 不一致，拒绝握手')
      return
    }
    // 旧版本可能钉过任意的 clientId；升级后仍要求 clientId 与设备密钥绑定。
    if (!clientIdBindsBundle(boundClientId, init.clientKey)) {
      deps.log.warn(`session-bridge: 已钉死客户端 ${boundClientId} 的 clientId 未绑定设备密钥，拒绝握手`)
      sendHandshakeError(nodeId, boundSessionId, 'client identity is not authorized')
      return
    }
    if (!hasRatchetCapacity(boundSessionId, boundClientId)) {
      deps.log.warn(`session-bridge: 会话 ${boundSessionId} 的 E2EE 客户端数量已达上限，拒绝握手`)
      sendHandshakeError(nodeId, boundSessionId, 'too many E2EE clients for this session')
      return
    }
    const entry = installRatchet(boundSessionId, boundClientId, nodeId, result)
    pendingHandshakes.delete(ratchetKey(boundSessionId, boundClientId))
    const ack: HandshakeAck = result.ack
    deps.tunnel.sendText({ t: 'e2ee.msg', nodeId, sessionId: boundSessionId, msg: ack })
    deps.log.info(`session-bridge: 会话 ${boundSessionId} 已建立 E2EE（客户端 ${boundClientId}）`)
    await sendSnapshot(boundSessionId, entry)
  }

  function listPendingApprovals(): PendingApproval[] {
    prunePendingHandshakes()
    const out: PendingApproval[] = []
    for (const pending of pendingHandshakes.values()) {
      if (!isShared(pending.sessionId)) continue
      out.push({
        sessionId: pending.sessionId,
        clientId: pending.clientId,
        safetyNumber: pending.safetyNumber,
        receivedAt: pending.receivedAt,
      })
    }
    return out
  }

  function listClients(): ClientInfo[] {
    prunePendingHandshakes()
    const out: ClientInfo[] = []
    for (const entry of ratchets.values()) {
      out.push({
        sessionId: entry.sessionId,
        clientId: entry.clientId,
        safetyNumber: entry.safetyNumber,
        pending: false,
      })
    }
    for (const pending of pendingHandshakes.values()) {
      if (!isShared(pending.sessionId)) continue
      out.push({
        sessionId: pending.sessionId,
        clientId: pending.clientId,
        safetyNumber: pending.safetyNumber,
        pending: true,
      })
    }
    return out
  }

  /** 显式重置：清理待批准握手或已钉死的客户端公钥，不触碰其它客户端。 */
  async function resetClient(raw: string): Promise<ResetResult> {
    if (disposed) return { ok: false, reset: 0, error: 'session bridge is disposed' }
    const value = typeof raw === 'string' ? raw.trim() : ''
    if (!value) return { ok: false, reset: 0, error: 'client id or safety number is required' }
    const digits = value.replace(/\D/g, '')
    const normalized = digits.length === 20 ? normalizeSafetyNumber(value) : ''
    let reset = 0
    prunePendingHandshakes()
    if (normalized) {
      for (const [key, pending] of [...pendingHandshakes]) {
        if (pending.safetyNumber !== normalized) continue
        pendingHandshakes.delete(key)
        reset += 1
      }
    } else {
      for (const [key, entry] of [...ratchets]) {
        if (entry.clientId !== value) continue
        ratchets.delete(key)
        reset += 1
      }
      for (const [key, pending] of [...pendingHandshakes]) {
        if (pending.clientId !== value) continue
        pendingHandshakes.delete(key)
        reset += 1
      }
      try {
        const state = await deps.store.load()
        if (state && Object.prototype.hasOwnProperty.call(state.pins, value)) {
          await deps.store.clearPin(value)
          reset += 1
        }
      } catch (err) {
        return { ok: false, reset, error: `credential store is unavailable: ${messageOf(err)}` }
      }
    }
    if (reset === 0) return { ok: false, reset: 0, error: 'no client matched the given id or safety number' }
    return { ok: true, reset }
  }

  async function approveClients(rawSafetyNumber: string): Promise<ApproveResult> {
    if (disposed) return { ok: false, approved: 0, error: 'session bridge is disposed' }
    const requested = typeof rawSafetyNumber === 'string' ? normalizeSafetyNumber(rawSafetyNumber) : ''
    if (!requested) return { ok: false, approved: 0, error: 'safety number is required' }
    let identity: DeviceIdentity
    try {
      identity = await ensureIdentity()
    } catch (err) {
      return { ok: false, approved: 0, error: `node identity is unavailable: ${messageOf(err)}` }
    }
    prunePendingHandshakes()
    // 先摘下匹配项，避免两个并发的 approve 重复建立同一客户端。
    const matches: PendingHandshake[] = []
    for (const [key, pending] of pendingHandshakes) {
      if (pending.safetyNumber !== requested) continue
      pendingHandshakes.delete(key)
      matches.push(pending)
    }
    if (matches.length === 0) {
      return { ok: false, approved: 0, error: 'no pending client matches this safety number' }
    }
    let approved = 0
    for (const pending of matches) {
      try {
        if (await activatePendingHandshake(pending, identity)) approved += 1
      } catch (err) {
        deps.log.warn(`session-bridge: 批准客户端失败: ${messageOf(err)}`)
      }
    }
    if (approved === 0) {
      return { ok: false, approved: 0, error: 'pending client is no longer valid; ask the client to retry the handshake' }
    }
    return { ok: true, approved }
  }

  async function handleEnvFrame(frame: TunnelFrame): Promise<void> {
    const sessionId = typeof frame.sessionId === 'string' ? frame.sessionId : ''
    if (!sessionId || !isShared(sessionId)) return
    const encrypted = frame.frame as EncryptedFrame | undefined
    if (!encrypted || typeof encrypted !== 'object') {
      deps.log.debug('session-bridge: 忽略无效的 e2ee.env')
      return
    }
    const candidates = ratchetsFor(sessionId)
    if (candidates.length === 0) {
      deps.log.debug(`session-bridge: 会话 ${sessionId} 尚未握手，丢弃密文帧`)
      return
    }
    for (const entry of candidates) {
      let value: TunnelFrame
      try {
        value = entry.ratchet.decryptJson<TunnelFrame>(encrypted)
      } catch (err) {
        if (err instanceof RatchetError && err.code === 'INVALID_INPUT') {
          reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', 'decrypted payload is not valid JSON')
          return
        }
        if (err instanceof RatchetError) continue
        throw err
      }
      await handleClientMessage(sessionId, entry, value)
      return
    }
    deps.log.warn(`session-bridge: 会话 ${sessionId} 的密文帧无法用任何棘轮解密`)
  }

  function answerQuestion(
    entry: InteractionEntry,
    answers: unknown,
  ): HostQuestionAnswer {
    const list = Array.isArray(answers) ? answers : []
    const view = entry.pending.questions ?? []
    return {
      answers: list.map((raw) => {
        const record = (raw ?? {}) as { id?: unknown; selected?: unknown; custom?: unknown }
        const id = String(record.id ?? '')
        const question = view.find((item) => item.id === id)
        const selected = (Array.isArray(record.selected) ? record.selected : []).map((value) => {
          const text = String(value)
          const option = question?.options.find((candidate) => candidate.id === text || candidate.label === text)
          return option?.label ?? text
        })
        return {
          id,
          selected,
          ...(typeof record.custom === 'string' ? { custom: record.custom } : {}),
        }
      }),
    }
  }

  async function handleClientMessage(sessionId: string, entry: RatchetEntry, message: TunnelFrame): Promise<void> {
    switch (message.t) {
      case 'snapshot.request': {
        await sendSnapshot(sessionId, entry)
        return
      }
      case 'prompt': {
        const text = typeof message.text === 'string' ? message.text : ''
        const mode = message.mode
        if (!text.trim() || (mode !== 'followup' && mode !== 'steer')) {
          reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', 'prompt requires non-empty text and followup|steer mode')
          return
        }
        try {
          const agent = await ensureAgent(sessionId)
          const userMessage = {
            id: randomUUID(),
            role: 'user',
            content: [{ type: 'text', text }],
            source: { kind: 'user' },
          }
          if (mode === 'steer') {
            if (!agent.steer) throw new Error('agent does not accept steering')
            agent.steer(userMessage)
          } else {
            if (!agent.followup) throw new Error('agent does not accept follow-ups')
            agent.followup(userMessage)
          }
          requestStateSync()
        } catch (err) {
          reportError(sessionId, 'REMOTE_SESSION_PROMPT_FAILED', messageOf(err))
        }
        return
      }
      case 'cancel': {
        const agent = serviceOf<AgentsLike>(ctx, 'agents')?.get?.(sessionId)
        if (!agent) {
          reportError(sessionId, 'REMOTE_SESSION_CANCEL_FAILED', `session ${sessionId} has no live agent to cancel`)
          return
        }
        try {
          agent.cancel?.({ kind: 'user' })
          requestStateSync()
        } catch (err) {
          reportError(sessionId, 'REMOTE_SESSION_CANCEL_FAILED', messageOf(err))
        }
        return
      }
      case 'approval.resolve': {
        const interactionId = typeof message.interactionId === 'string' ? message.interactionId : ''
        const outcome = message.outcome
        if (!interactionId || (outcome !== 'allowed-once' && outcome !== 'rejected')) {
          reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', 'approval.resolve requires interactionId and allowed-once|rejected outcome')
          return
        }
        const target = interactions.get(interactionId)
        if (!target || target.kind !== 'approval' || target.sessionId !== sessionId) {
          if (!settledInteractions.has(interactionId)) {
            reportError(sessionId, 'REMOTE_SESSION_INTERACTION_UNKNOWN', `unknown approval interaction ${interactionId}`)
          }
          return
        }
        settleInteraction(target, outcome)
        return
      }
      case 'question.answer': {
        const interactionId = typeof message.interactionId === 'string' ? message.interactionId : ''
        if (!interactionId) {
          reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', 'question.answer requires interactionId')
          return
        }
        const target = interactions.get(interactionId)
        if (!target || target.kind !== 'question' || target.sessionId !== sessionId) {
          if (!settledInteractions.has(interactionId)) {
            reportError(sessionId, 'REMOTE_SESSION_INTERACTION_UNKNOWN', `unknown question interaction ${interactionId}`)
          }
          return
        }
        settleInteraction(target, answerQuestion(target, message.answers))
        return
      }
      case 'model.set': {
        const provider = typeof message.provider === 'string' ? message.provider : ''
        const model = typeof message.model === 'string' ? message.model : ''
        const reasoningEffort = typeof message.reasoningEffort === 'string' ? message.reasoningEffort : ''
        if (!provider || !model) {
          reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', 'model.set requires provider and model')
          return
        }
        try {
          const agent = await ensureAgent(sessionId)
          if (!agent.model?.select) throw new Error('agent has no model selection API')
          agent.model.select({
            provider,
            model,
            ...(reasoningEffort ? { reasoningEffort } : {}),
          })
          await sendSnapshot(sessionId, entry)
        } catch (err) {
          reportError(sessionId, 'REMOTE_SESSION_MODEL_FAILED', messageOf(err))
        }
        return
      }
      case 'preset.set': {
        const preset = typeof message.preset === 'string' ? message.preset.trim() : ''
        if (!preset) {
          reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', 'preset.set requires a preset name')
          return
        }
        try {
          const agent = await ensureAgent(sessionId)
          const presets = serviceOf<PermissionPresetsLike>(ctx, 'permissionPresets')
          if (!presets?.set) throw new Error('permissionPresets service is unavailable')
          presets.set(agent.session, preset)
          await sendSnapshot(sessionId, entry)
        } catch (err) {
          reportError(sessionId, 'REMOTE_SESSION_PRESET_FAILED', messageOf(err))
        }
        return
      }
      case 'ping': {
        emitToEntry(entry, { t: 'pong', ts: typeof message.ts === 'number' ? message.ts : Date.now() })
        return
      }
      default:
        reportError(sessionId, 'REMOTE_SESSION_BAD_MESSAGE', `unsupported client message type ${String(message.t)}`)
    }
  }

  function dropSession(sessionId: string, settle: boolean): void {
    if (settle) {
      settleSessionInteractions(sessionId, 'cancelled')
    } else {
      for (const entry of [...interactions.values()]) {
        if (entry.sessionId === sessionId) interactions.delete(entry.id)
      }
    }
    for (const [key, entry] of ratchets) {
      if (entry.sessionId === sessionId) ratchets.delete(key)
    }
    for (const [key, pending] of pendingHandshakes) {
      if (pending.sessionId === sessionId) pendingHandshakes.delete(key)
    }
    resetDelta(sessionId)
    deltaStates.delete(sessionId)
    callNames.delete(sessionId)
    snapshotSeq.delete(sessionId)
    liveSessions.delete(sessionId)
    const handle = resumeHandles.get(sessionId)
    resumeHandles.delete(sessionId)
    if (handle) void Promise.resolve(handle.dispose()).catch(() => undefined)
  }

  async function disableAll(): Promise<void> {
    for (const sessionId of [...sharedIds]) {
      sharedIds.splice(sharedIds.indexOf(sessionId), 1)
      dropSession(sessionId, true)
    }
    requestStateSync()
  }

  onHostEvent('session/event', onSessionEvent)
  onHostEvent('agent/assistant-stream', onAssistantStream)
  onHostEvent('approval/request', onApprovalRequest)
  onHostEvent('user-questions/request', onQuestionRequest)

  return {
    get shared() {
      return [...sharedIds]
    },
    status(sessionId) {
      const id = typeof sessionId === 'string' ? sessionId.trim() : ''
      if (!id) return { shared: sharedIds.length > 0 }
      const entry = ratchetsFor(id)[0]
      return entry ? { shared: isShared(id), safetyNumber: entry.safetyNumber } : { shared: isShared(id) }
    },
    pendingApprovals() {
      return listPendingApprovals()
    },
    approve(rawSafetyNumber) {
      return approveClients(rawSafetyNumber)
    },
    clients() {
      return listClients()
    },
    reset(raw) {
      return resetClient(raw)
    },
    async toggle(sessionId, enabled) {
      const id = typeof sessionId === 'string' ? sessionId.trim() : ''
      if (!id) return { ok: false, error: 'REMOTE_SESSION_BAD_MESSAGE: sessionId is required' }
      if (enabled) {
        if (!sharedIds.includes(id)) {
          sharedIds.push(id)
          requestStateSync()
        }
        return { ok: true }
      }
      const index = sharedIds.indexOf(id)
      if (index >= 0) {
        sharedIds.splice(index, 1)
        dropSession(id, true)
        requestStateSync()
      }
      return { ok: true }
    },
    async stopAll() {
      if (disposed) return
      await disableAll()
    },
    handleText(frame) {
      if (disposed || !frame || typeof frame.t !== 'string') return
      if (frame.t === 'e2ee.msg') {
        void handleHandshakeFrame(frame).catch((err: unknown) => {
          deps.log.warn(`session-bridge: 处理握手帧失败: ${messageOf(err)}`)
        })
        return
      }
      if (frame.t === 'e2ee.env') {
        void handleEnvFrame(frame).catch((err: unknown) => {
          deps.log.warn(`session-bridge: 处理密文帧失败: ${messageOf(err)}`)
        })
      }
    },
    dispose() {
      if (disposed) return
      disposed = true
      for (const off of disposers.splice(0)) {
        try {
          off()
        } catch {
          // 监听已随插件卸载时忽略。
        }
      }
      for (const state of deltaStates.values()) {
        if (state.timer) clearTimeout(state.timer)
        state.timer = null
      }
      deltaStates.clear()
      interactions.clear()
      ratchets.clear()
      pendingHandshakes.clear()
      sharedIds.length = 0
      for (const handle of resumeHandles.values()) void Promise.resolve(handle.dispose()).catch(() => undefined)
      resumeHandles.clear()
    },
  }
}
