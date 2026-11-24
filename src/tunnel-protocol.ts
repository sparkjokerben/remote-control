/**
 * 隧道协议类型与编解码（契约 §3）：文本帧 JSON + 6 字节二进制头
 * `kind:u8 | flags:u8 | streamId:u32be`，单帧负载 ≤ 64 KiB。
 */
import type {
  DeviceKeyBundle,
  EncryptedFrame,
  HandshakeAck,
  HandshakeErr,
  HandshakeInit,
} from './crypto/index.js'

export type SessionStatus = 'running' | 'idle'

export interface SessionSummary {
  sessionId: string
  title: string
  cwd: string
  status: SessionStatus
}

/** 通用帧外形；所有具名帧都扩展它，便于统一收发。 */
export interface TunnelFrame {
  t: string
  [key: string]: unknown
}

export interface HelloFrame extends TunnelFrame {
  t: 'hello'
  proto: 1
  nodeId: string
  hostname: string
  platform: string
  dshVersion: string
  pluginVersion: string
  webUiEnabled: boolean
  sessions: SessionSummary[]
  publicKey: DeviceKeyBundle
}

export interface HelloAckFrame extends TunnelFrame {
  t: 'hello.ack'
  proto: 1
  nodeId: string
  userId: number
  tierCode: string
  maxNodes: number
}

export interface StateSyncFrame extends TunnelFrame {
  t: 'state.sync'
  webUiEnabled: boolean
  sessions: SessionSummary[]
  publicKey: DeviceKeyBundle
}

export interface PingFrame extends TunnelFrame {
  t: 'ping'
  ts: number
}

export interface PongFrame extends TunnelFrame {
  t: 'pong'
  ts: number
}

export type NotifyKind = 'approval' | 'question' | 'turn_end' | 'turn_error'

export interface NotifyTriggerFrame extends TunnelFrame {
  t: 'notify.trigger'
  eventId: string
  sessionId?: string
  kind: NotifyKind
  title: string
  summary: string
  ts: number
}

export interface NotifyCancelFrame extends TunnelFrame {
  t: 'notify.cancel'
  eventId: string
}

/** 插件→BFF 的握手消息。 */
export interface E2eeMsgFromNodeFrame extends TunnelFrame {
  t: 'e2ee.msg'
  nodeId: string
  sessionId: string
  msg: HandshakeInit | HandshakeErr
}

/** BFF→插件的握手消息。 */
export interface E2eeMsgFromBffFrame extends TunnelFrame {
  t: 'e2ee.msg'
  nodeId: string
  sessionId: string
  from: 'mp'
  msg: HandshakeInit
}

/** BFF→小程序的握手消息（插件不发送，用于契约完整性）。 */
export interface E2eeMsgToClientFrame extends TunnelFrame {
  t: 'e2ee.msg'
  nodeId: string
  sessionId: string
  from: 'node'
  msg: HandshakeAck | HandshakeErr
}

export interface E2eeEnvFrame extends TunnelFrame {
  t: 'e2ee.env'
  nodeId: string
  sessionId: string
  frame: EncryptedFrame
}

export interface HttpReqFrame extends TunnelFrame {
  t: 'http.req'
  streamId: number
  method: string
  path: string
  query: string
  headers: Record<string, string[]>
  hasBody: boolean
}

export interface HttpResFrame extends TunnelFrame {
  t: 'http.res'
  streamId: number
  status: number
  headers: Record<string, string[]>
  hasBody: boolean
}

export interface HttpAbortFrame extends TunnelFrame {
  t: 'http.abort'
  streamId: number
}

export interface WsOpenFrame extends TunnelFrame {
  t: 'ws.open'
  streamId: number
  path: string
  query: string
  headers: Record<string, string[]>
}

export interface WsAckFrame extends TunnelFrame {
  t: 'ws.ack'
  streamId: number
  ok: boolean
  protocol?: string
  error?: string
}

export interface WsCloseFrame extends TunnelFrame {
  t: 'ws.close'
  streamId: number
  code: number
  reason: string
}

export interface TunnelFrameMap {
  hello: HelloFrame
  'hello.ack': HelloAckFrame
  'state.sync': StateSyncFrame
  ping: PingFrame
  pong: PongFrame
  'notify.trigger': NotifyTriggerFrame
  'notify.cancel': NotifyCancelFrame
  'e2ee.msg': E2eeMsgFromNodeFrame | E2eeMsgFromBffFrame | E2eeMsgToClientFrame
  'e2ee.env': E2eeEnvFrame
  'http.req': HttpReqFrame
  'http.res': HttpResFrame
  'http.abort': HttpAbortFrame
  'ws.open': WsOpenFrame
  'ws.ack': WsAckFrame
  'ws.close': WsCloseFrame
}

export type AnyTunnelFrame = TunnelFrameMap[keyof TunnelFrameMap]
export type TunnelTextFrame = AnyTunnelFrame

export const TUNNEL_SUBPROTOCOL = 'gt-remote-tunnel.v1'
export const TUNNEL_CONNECT_PATH = '/dsh-tunnel/connect'
export const BINARY_HEADER_BYTES = 6
export const MAX_BINARY_PAYLOAD_BYTES = 64 * 1024

export const BINARY_KIND_HTTP_BODY = 0x01
export const BINARY_KIND_HTTP_END = 0x02
export const BINARY_KIND_WS_TEXT = 0x11
export const BINARY_KIND_WS_BINARY = 0x12

export type BinaryKind =
  | typeof BINARY_KIND_HTTP_BODY
  | typeof BINARY_KIND_HTTP_END
  | typeof BINARY_KIND_WS_TEXT
  | typeof BINARY_KIND_WS_BINARY

export interface BinaryFrame {
  kind: BinaryKind
  streamId: number
  payload: Uint8Array
}

export type TunnelProtocolErrorCode =
  | 'REMOTE_TUNNEL_BAD_TEXT_FRAME'
  | 'REMOTE_TUNNEL_BAD_BINARY_FRAME'
  | 'REMOTE_TUNNEL_UNKNOWN_FRAME_KIND'
  | 'REMOTE_TUNNEL_FRAME_TOO_LARGE'

export class TunnelProtocolError extends Error {
  readonly code: TunnelProtocolErrorCode

  constructor(code: TunnelProtocolErrorCode, message: string) {
    super(message)
    this.name = 'TunnelProtocolError'
    this.code = code
  }
}

export function isKnownBinaryKind(kind: number): kind is BinaryKind {
  return (
    kind === BINARY_KIND_HTTP_BODY ||
    kind === BINARY_KIND_HTTP_END ||
    kind === BINARY_KIND_WS_TEXT ||
    kind === BINARY_KIND_WS_BINARY
  )
}

export function encodeTextFrame(frame: TunnelFrame): string {
  return JSON.stringify(frame)
}

export function decodeTextFrame(text: string): TunnelFrame {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_TEXT_FRAME', 'tunnel text frame is not valid JSON')
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_TEXT_FRAME', 'tunnel text frame must be a JSON object')
  }
  const frame = value as TunnelFrame
  if (typeof frame.t !== 'string' || frame.t.length === 0) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_TEXT_FRAME', 'tunnel text frame is missing a non-empty "t" field')
  }
  return frame
}

export function encodeBinaryFrame(kind: BinaryKind, streamId: number, payload: Uint8Array): Uint8Array {
  if (!isKnownBinaryKind(kind)) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_UNKNOWN_FRAME_KIND', `unknown tunnel binary kind: ${kind}`)
  }
  if (!Number.isInteger(streamId) || streamId <= 0 || streamId > 0xffffffff) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_BINARY_FRAME', `tunnel streamId is out of range: ${streamId}`)
  }
  if (!(payload instanceof Uint8Array)) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_BINARY_FRAME', 'tunnel binary payload must be a Uint8Array')
  }
  if (payload.byteLength > MAX_BINARY_PAYLOAD_BYTES) {
    throw new TunnelProtocolError(
      'REMOTE_TUNNEL_FRAME_TOO_LARGE',
      `tunnel binary payload exceeds ${MAX_BINARY_PAYLOAD_BYTES} bytes`,
    )
  }
  const frame = new Uint8Array(BINARY_HEADER_BYTES + payload.byteLength)
  frame[0] = kind
  frame[1] = 0
  new DataView(frame.buffer, frame.byteOffset, frame.byteLength).setUint32(2, streamId, false)
  frame.set(payload, BINARY_HEADER_BYTES)
  return frame
}

export function decodeBinaryFrame(data: Uint8Array): BinaryFrame {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data as ArrayBuffer)
  if (bytes.byteLength < BINARY_HEADER_BYTES) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_BINARY_FRAME', 'tunnel binary frame is shorter than the 6-byte header')
  }
  const kind = bytes[0]
  if (!isKnownBinaryKind(kind)) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_UNKNOWN_FRAME_KIND', `unknown tunnel binary kind: ${kind}`)
  }
  if (bytes[1] !== 0) {
    throw new TunnelProtocolError('REMOTE_TUNNEL_BAD_BINARY_FRAME', `tunnel binary flags must be zero, got ${bytes[1]}`)
  }
  const payload = bytes.subarray(BINARY_HEADER_BYTES)
  if (payload.byteLength > MAX_BINARY_PAYLOAD_BYTES) {
    throw new TunnelProtocolError(
      'REMOTE_TUNNEL_FRAME_TOO_LARGE',
      `tunnel binary payload exceeds ${MAX_BINARY_PAYLOAD_BYTES} bytes`,
    )
  }
  const streamId = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(2, false)
  return { kind, streamId, payload }
}
