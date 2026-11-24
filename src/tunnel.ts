/**
 * 中继隧道客户端（契约 §3）：单条出站 WSS，子协议 `gt-remote-tunnel.v1`，
 * 指数退避重连（1s..30s 抖动），401 时调用 refreshToken 后重试一次。
 */
import WebSocket from 'ws'

import type { ClientRequest, IncomingMessage } from 'node:http'

import type { ResolvedConfig, Logger } from './config.js'
import type { CredentialStore, Grant } from './credentials.js'
import {
  decodeBinaryFrame,
  decodeTextFrame,
  encodeBinaryFrame,
  encodeTextFrame,
  isKnownBinaryKind,
  MAX_BINARY_PAYLOAD_BYTES,
  TUNNEL_CONNECT_PATH,
  TUNNEL_SUBPROTOCOL,
  type TunnelFrame,
} from './tunnel-protocol.js'

export type { TunnelFrame } from './tunnel-protocol.js'

export type TunnelStatus = 'offline' | 'connecting' | 'online' | 'error'

export interface Tunnel {
  connect(): Promise<void>
  disconnect(): void
  readonly status: TunnelStatus
  sendText(frame: TunnelFrame): void
  sendBinary(kind: number, streamId: number, payload: Uint8Array): void
  onText(handler: (frame: TunnelFrame) => void): () => void
  onBinary(handler: (kind: number, streamId: number, payload: Uint8Array) => void): () => void
  /** 状态变化订阅；连接重新建立时宿主借此重发 hello。 */
  onStatus(handler: (status: TunnelStatus) => void): () => void
  /** 取消重连并释放全部句柄与监听。 */
  dispose(): void
}

export interface TunnelDeps {
  config: ResolvedConfig
  store: CredentialStore
  refreshToken(): Promise<Grant | null>
  log: Logger
}

export type TunnelErrorCode =
  | 'REMOTE_TUNNEL_NO_GRANT'
  | 'REMOTE_TUNNEL_UNAUTHORIZED'
  | 'REMOTE_TUNNEL_CONNECT_FAILED'
  | 'REMOTE_TUNNEL_DISPOSED'

export class TunnelError extends Error {
  readonly code: TunnelErrorCode

  constructor(code: TunnelErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'TunnelError'
    this.code = code
  }
}

class UnauthorizedError extends Error {
  readonly status: number

  constructor(status: number) {
    super(`relay rejected the tunnel handshake with HTTP ${status}`)
    this.name = 'UnauthorizedError'
    this.status = status
  }
}

const MIN_RECONNECT_MS = 1_000
const MAX_RECONNECT_MS = 30_000
const HANDSHAKE_TIMEOUT_MS = 15_000

function tunnelUrl(config: ResolvedConfig): string {
  return `${config.relayUrl.replace(/\/+$/, '')}${TUNNEL_CONNECT_PATH}`
}

function toBytes(data: Buffer | ArrayBuffer | Buffer[]): Uint8Array {
  if (Array.isArray(data)) return Buffer.concat(data)
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  return data
}

export function createTunnel(deps: TunnelDeps): Tunnel {
  const url = tunnelUrl(deps.config)
  const textHandlers = new Set<(frame: TunnelFrame) => void>()
  const binaryHandlers = new Set<(kind: number, streamId: number, payload: Uint8Array) => void>()
  const statusHandlers = new Set<(status: TunnelStatus) => void>()

  let socket: WebSocket | null = null
  let status: TunnelStatus = 'offline'
  let wantConnected = false
  let disposed = false
  let attempt = 0
  let retryTimer: NodeJS.Timeout | null = null
  let connectPromise: Promise<void> | null = null

  function setStatus(next: TunnelStatus): void {
    if (status === next) return
    status = next
    for (const handler of [...statusHandlers]) {
      try {
        handler(next)
      } catch (err) {
        deps.log.warn(`tunnel status handler failed: ${(err as Error).message}`)
      }
    }
  }

  function clearRetry(): void {
    if (retryTimer) {
      clearTimeout(retryTimer)
      retryTimer = null
    }
  }

  function scheduleReconnect(): void {
    if (disposed || !wantConnected || retryTimer) return
    const base = Math.min(MAX_RECONNECT_MS, MIN_RECONNECT_MS * 2 ** Math.min(attempt, 5))
    const delay = Math.min(MAX_RECONNECT_MS, Math.max(MIN_RECONNECT_MS, Math.round(base * (0.8 + Math.random() * 0.4))))
    attempt += 1
    deps.log.debug(`tunnel 将在 ${delay}ms 后重连（第 ${attempt} 次）`)
    retryTimer = setTimeout(() => {
      retryTimer = null
      if (disposed || !wantConnected) return
      void connect().catch((err: unknown) => {
        deps.log.debug(`tunnel 重连失败: ${(err as Error).message}`)
      })
    }, delay)
    retryTimer.unref?.()
  }

  function attachLive(ws: WebSocket): void {
    ws.on('message', (data, isBinary) => {
      if (disposed) return
      try {
        if (isBinary) {
          const frame = decodeBinaryFrame(toBytes(data))
          for (const handler of [...binaryHandlers]) handler(frame.kind, frame.streamId, frame.payload)
        } else {
          const text = Buffer.from(toBytes(data)).toString('utf8')
          const frame = decodeTextFrame(text)
          for (const handler of [...textHandlers]) handler(frame)
        }
      } catch (err) {
        deps.log.warn(`tunnel 丢弃无效帧: ${(err as Error).message}`)
      }
    })
    ws.on('error', (err) => {
      deps.log.debug(`tunnel socket error: ${err.message}`)
    })
    ws.on('close', (code, reason) => {
      if (socket !== ws) return
      socket = null
      if (disposed) return
      deps.log.debug(`tunnel 已断开: ${code} ${reason.toString('utf8')}`)
      setStatus('offline')
      if (wantConnected) scheduleReconnect()
    })
  }

  function openOnce(override?: Grant): Promise<void> {
    const loading = override ? Promise.resolve(undefined) : deps.store.load()
    return loading.then((state) => {
      if (disposed) throw new TunnelError('REMOTE_TUNNEL_DISPOSED', 'tunnel has been disposed')
      if (!wantConnected) throw new TunnelError('REMOTE_TUNNEL_CONNECT_FAILED', 'tunnel connection is not requested')
      const grant = override ?? state?.grant
      if (!grant?.accessToken) {
        throw new TunnelError('REMOTE_TUNNEL_NO_GRANT', 'not logged in: run /remote login first')
      }
      setStatus('connecting')
      const ws = new WebSocket(url, TUNNEL_SUBPROTOCOL, {
        headers: { Authorization: `Bearer ${grant.accessToken}` },
        handshakeTimeout: HANDSHAKE_TIMEOUT_MS,
      })
      socket = ws
      return new Promise<void>((resolve, reject) => {
        let settled = false
        const finish = (error?: Error): void => {
          if (settled) return
          settled = true
          ws.off('open', onOpen)
          ws.off('error', onError)
          ws.off('unexpected-response', onUnexpected)
          ws.off('close', onClose)
          if (error) {
            if (socket === ws) socket = null
            reject(error)
          } else {
            resolve()
          }
        }
        const onOpen = (): void => {
          attempt = 0
          attachLive(ws)
          setStatus('online')
          finish()
        }
        const onError = (err: Error): void => {
          finish(new TunnelError('REMOTE_TUNNEL_CONNECT_FAILED', `cannot connect to the relay: ${err.message}`, err))
        }
        const onClose = (): void => {
          finish(new TunnelError('REMOTE_TUNNEL_CONNECT_FAILED', 'relay closed the connection before the tunnel opened'))
        }
        const onUnexpected = (_request: ClientRequest, response: IncomingMessage): void => {
          const statusCode = response.statusCode ?? 0
          deps.log.debug(`tunnel 握手被拒绝: HTTP ${statusCode}`)
          response.resume()
          finish(
            statusCode === 401
              ? new UnauthorizedError(statusCode)
              : new TunnelError('REMOTE_TUNNEL_CONNECT_FAILED', `relay rejected the tunnel handshake with HTTP ${statusCode}`),
          )
          ws.on('error', () => undefined)
          ws.terminate()
        }
        ws.once('open', onOpen)
        ws.once('error', onError)
        ws.once('unexpected-response', onUnexpected)
        ws.once('close', onClose)
      })
    })
  }

  async function attemptConnect(): Promise<void> {
    let refreshed = false
    let override: Grant | undefined
    for (;;) {
      try {
        await openOnce(override)
        return
      } catch (err) {
        if (!wantConnected) {
          setStatus('offline')
          throw err
        }
        if (err instanceof TunnelError && (err.code === 'REMOTE_TUNNEL_DISPOSED' || err.code === 'REMOTE_TUNNEL_NO_GRANT')) {
          setStatus('error')
          throw err
        }
        if (err instanceof UnauthorizedError && !refreshed) {
          refreshed = true
          deps.log.info('tunnel 收到 401，尝试刷新 OIDC access token')
          const granted = await deps.refreshToken().catch((refreshErr: unknown) => {
            deps.log.warn(`tunnel token 刷新失败: ${(refreshErr as Error).message}`)
            return null
          })
          if (granted) {
            override = granted
            continue
          }
          setStatus('error')
          const error = new TunnelError(
            'REMOTE_TUNNEL_UNAUTHORIZED',
            'relay rejected the access token and no refreshed token is available',
          )
          scheduleReconnect()
          throw error
        }
        if (err instanceof UnauthorizedError) {
          setStatus('error')
          scheduleReconnect()
          throw new TunnelError('REMOTE_TUNNEL_UNAUTHORIZED', err.message, err)
        }
        setStatus('error')
        scheduleReconnect()
        throw err
      }
    }
  }

  async function connect(): Promise<void> {
    if (disposed) throw new TunnelError('REMOTE_TUNNEL_DISPOSED', 'tunnel has been disposed')
    wantConnected = true
    if (status === 'online') return
    clearRetry()
    if (connectPromise) return connectPromise
    const promise = attemptConnect().finally(() => {
      if (connectPromise === promise) connectPromise = null
    })
    connectPromise = promise
    void promise.catch(() => undefined)
    return promise
  }

  function disconnect(): void {
    wantConnected = false
    clearRetry()
    const ws = socket
    socket = null
    if (ws) {
      if (ws.readyState === WebSocket.CONNECTING) {
        // 正在握手：保留一次性 open/close/error 监听，让 connect() 的 Promise 正常结算。
        ws.on('error', () => undefined)
        ws.terminate()
      } else {
        ws.removeAllListeners('close')
        ws.removeAllListeners('message')
        ws.removeAllListeners('error')
        ws.on('error', () => undefined)
        ws.close(1000, 'client disconnect')
      }
    }
    setStatus('offline')
  }

  return {
    connect,
    disconnect,
    get status() {
      return status
    },
    sendText(frame) {
      if (!socket || socket.readyState !== WebSocket.OPEN) {
        deps.log.debug(`tunnel offline，丢弃文本帧 ${frame.t}`)
        return
      }
      try {
        socket.send(encodeTextFrame(frame))
      } catch (err) {
        deps.log.warn(`tunnel 发送文本帧失败: ${(err as Error).message}`)
      }
    },
    sendBinary(kind, streamId, payload) {
      if (!socket || socket.readyState !== WebSocket.OPEN) {
        deps.log.debug('tunnel offline，丢弃二进制帧')
        return
      }
      if (!isKnownBinaryKind(kind)) {
        deps.log.warn(`tunnel 丢弃未知二进制帧 kind=${kind}`)
        return
      }
      if (payload.byteLength > MAX_BINARY_PAYLOAD_BYTES) {
        deps.log.warn(`tunnel 丢弃超过 ${MAX_BINARY_PAYLOAD_BYTES} 字节的二进制帧`)
        return
      }
      try {
        socket.send(encodeBinaryFrame(kind, streamId, payload))
      } catch (err) {
        deps.log.warn(`tunnel 发送二进制帧失败: ${(err as Error).message}`)
      }
    },
    onText(handler) {
      textHandlers.add(handler)
      return () => textHandlers.delete(handler)
    },
    onBinary(handler) {
      binaryHandlers.add(handler)
      return () => binaryHandlers.delete(handler)
    },
    onStatus(handler) {
      statusHandlers.add(handler)
      return () => statusHandlers.delete(handler)
    },
    dispose() {
      if (disposed) return
      disposed = true
      wantConnected = false
      clearRetry()
      const ws = socket
      socket = null
      if (ws) {
        if (ws.readyState === WebSocket.CONNECTING) {
          ws.on('error', () => undefined)
          ws.terminate()
        } else {
          ws.removeAllListeners()
          ws.on('error', () => undefined)
          ws.terminate()
        }
      }
      textHandlers.clear()
      binaryHandlers.clear()
      statusHandlers.clear()
      if (status !== 'offline') status = 'offline'
    },
  }
}
