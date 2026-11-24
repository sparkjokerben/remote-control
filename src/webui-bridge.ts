/**
 * WebUI 远控桥（契约 §3.2、§6）：仅在 `/remote webui` 开启且 webServer+connection
 * 可用时工作。HTTP/WS 转发到本机 `127.0.0.1:<port>`，改写 Host/Origin 并附上
 * 本机 owner cookie；只对 text/html 注入视口/安全区/--gt-vvh 垫片。
 */
import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type ClientRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'

import WebSocket from 'ws'

import type { Context } from '@deepseek-ai/cordis'

import type { BridgeDeps } from './session-bridge.js'
import {
  BINARY_KIND_HTTP_BODY,
  BINARY_KIND_HTTP_END,
  BINARY_KIND_WS_BINARY,
  BINARY_KIND_WS_TEXT,
  MAX_BINARY_PAYLOAD_BYTES,
  type HttpReqFrame,
  type TunnelFrame,
  type WsOpenFrame,
} from './tunnel-protocol.js'

export interface WebUiBridge {
  status(): { available: boolean; active: boolean }
  toggle(enabled: boolean): Promise<{ ok: boolean; error?: string }>
  handleText(frame: TunnelFrame): void
  handleBinary(kind: number, streamId: number, payload: Uint8Array): void
  stopAll(): void
}

export type WebUiBridgeErrorCode =
  | 'REMOTE_WEBUI_UNAVAILABLE'
  | 'REMOTE_WEBUI_COOKIE_FAILED'
  | 'REMOTE_WEBUI_BAD_FRAME'
  | 'REMOTE_WEBUI_UPSTREAM_FAILED'

export const WEBUI_VIEWPORT_CONTENT = 'width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover'
const SHIM_MARKER = 'data-gt-remote-webui'
const SHIM_CSS = [
  ':where(html,body,#root){height:100dvh;min-height:100%;-webkit-text-size-adjust:100%;box-sizing:border-box}',
  ':where(body){padding-top:env(safe-area-inset-top);padding-bottom:env(safe-area-inset-bottom)}',
  '@media (orientation:landscape) and (max-height:520px){:where(body){padding-top:0;padding-bottom:0;padding-left:env(safe-area-inset-left);padding-right:env(safe-area-inset-right)}}',
].join('')
const SHIM_JS =
  "(function(){var d=document.documentElement,v=window.visualViewport;function s(){if(v){d.style.setProperty('--gt-vvh',v.height+'px')}}if(v){s();v.addEventListener('resize',s);v.addEventListener('scroll',s)}window.addEventListener('resize',s)})()"

const SKIP_REQUEST_HEADERS = new Set([
  'host',
  'origin',
  'cookie',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'accept-encoding',
])

const COOKIE_TTL_MS = 24 * 60 * 60 * 1000

interface WebServerLike {
  getOrigin(): string
  readonly protocol?: 'http:' | 'https:'
}

interface ConnectionLike {
  authenticatedUrl(baseUrl: string): string
}

interface HostContextLike {
  get?(name: string): unknown
}

interface HttpStreamState {
  readonly frame: HttpReqFrame
  readonly chunks: Uint8Array[]
  ended: boolean
  aborted: boolean
  retried: boolean
  request?: ClientRequest
  response?: IncomingMessage
}

interface WsStreamState {
  readonly streamId: number
  readonly socket: WebSocket
  opened: boolean
  silentClose: boolean
}

interface CookieState {
  value: string
  expiresAt: number
}

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

function toBytes(data: Buffer | ArrayBuffer | Buffer[]): Uint8Array {
  if (Array.isArray(data)) return Buffer.concat(data)
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  return data
}

function headerRecord(headers: IncomingHttpHeaders): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    out[name] = Array.isArray(value) ? value.map(String) : [String(value)]
  }
  return out
}

const HOP_BY_HOP_RESPONSE = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

function responseHeaderRecord(headers: IncomingHttpHeaders): Record<string, string[]> {
  const out = headerRecord(headers)
  for (const name of HOP_BY_HOP_RESPONSE) delete out[name]
  return out
}

function isStreamId(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffffffff
}

/** 注入视图垫片（幂等）；不改动 dsh 的任何类名、主题变量或插槽。 */
export function injectWebUiShim(html: string): string {
  if (typeof html !== 'string' || html.length === 0 || html.includes(SHIM_MARKER)) return html
  const viewport = `<meta name="viewport" content="${WEBUI_VIEWPORT_CONTENT}">`
  let output = html
  const metaPattern = /<meta\b[^>]*\bname\s*=\s*(?:"viewport"|'viewport'|viewport)[^>]*>/i
  if (metaPattern.test(output)) {
    output = output.replace(metaPattern, viewport)
  } else if (/<head\b[^>]*>/i.test(output)) {
    output = output.replace(/<head\b[^>]*>/i, (match) => `${match}\n${viewport}`)
  } else {
    output = `${viewport}\n${output}`
  }
  const shim = `<style ${SHIM_MARKER}="1">${SHIM_CSS}</style><script ${SHIM_MARKER}="1">${SHIM_JS}</script>`
  if (/<\/head>/i.test(output)) {
    output = output.replace(/<\/head>/i, `${shim}</head>`)
  } else {
    output = `${output}\n${shim}`
  }
  return output
}

/** 创建 WebUI 桥；仅在 toggle(true) 且本机 webServer/connection 可用时处理流量。 */
export function createWebUiBridge(ctx: Context, deps: BridgeDeps): WebUiBridge {
  const webServer = serviceOf<WebServerLike>(ctx, 'webServer')
  const connection = serviceOf<ConnectionLike>(ctx, 'connection')
  const httpStreams = new Map<number, HttpStreamState>()
  const wsStreams = new Map<number, WsStreamState>()
  let active = false
  let cookieState: CookieState | null = null
  let cookiePromise: Promise<string> | null = null
  let offStatus: (() => void) | null = null

  function requireOrigin(): string {
    if (!webServer?.getOrigin) throw new Error('webServer service is unavailable')
    return webServer.getOrigin()
  }

  function availableNow(): boolean {
    try {
      return Boolean(requireOrigin()) && typeof connection?.authenticatedUrl === 'function'
    } catch {
      return false
    }
  }

  function unavailable(): { ok: false; error: string } {
    return { ok: false, error: 'REMOTE_WEBUI_UNAVAILABLE: dsh webServer/connection is not available' }
  }

  function localTarget(frame: { path?: unknown; query?: unknown }): URL {
    const origin = requireOrigin()
    let path = typeof frame.path === 'string' && frame.path.length > 0 ? frame.path : '/'
    if (!path.startsWith('/')) path = `/${path}`
    path = path.replace(/^\/{2,}/, '/')
    const query = typeof frame.query === 'string' ? frame.query : ''
    const url = new URL(`${path}${query ? `?${query}` : ''}`, origin)
    if (url.origin !== new URL(origin).origin) throw new Error('path escapes the local web server')
    return url
  }

  function setCookieList(headers: Headers): string[] {
    const candidate = headers as Headers & { getSetCookie?: () => string[] }
    if (typeof candidate.getSetCookie === 'function') return candidate.getSetCookie()
    const raw = headers.get('set-cookie')
    if (!raw) return []
    return [raw.split(';', 1)[0]?.trim() ?? '']
  }

  function maxAgeOf(values: readonly string[]): number | undefined {
    let seconds: number | undefined
    for (const value of values) {
      const match = /max-age=(\d+)/i.exec(value)
      if (!match) continue
      const parsed = Number(match[1])
      if (Number.isFinite(parsed) && parsed > 0) seconds = Math.min(seconds ?? parsed, parsed)
    }
    return seconds
  }

  async function fetchOwnerCookie(): Promise<string> {
    if (!connection?.authenticatedUrl) throw new Error('connection service is unavailable')
    const base = new URL('/', requireOrigin()).href
    const url = connection.authenticatedUrl(base)
    const response = await fetch(url, { redirect: 'manual', headers: { accept: 'text/html' } })
    const raw = setCookieList(response.headers)
    await response.body?.cancel().catch(() => undefined)
    const pairs = raw.map((value) => value.split(';', 1)[0]?.trim() ?? '').filter(Boolean)
    if (pairs.length === 0) throw new Error('the local web server did not issue an owner cookie')
    const seconds = maxAgeOf(raw)
    cookieState = {
      value: pairs.join('; '),
      expiresAt: Date.now() + (seconds === undefined ? COOKIE_TTL_MS : seconds * 1000),
    }
    return cookieState.value
  }

  async function getOwnerCookie(force: boolean): Promise<string> {
    if (!force && cookieState && cookieState.expiresAt > Date.now()) return cookieState.value
    if (!cookiePromise) {
      cookiePromise = fetchOwnerCookie().finally(() => {
        cookiePromise = null
      })
    }
    return cookiePromise
  }

  function buildRequestHeaders(
    incoming: Record<string, string | string[]> | undefined,
    target: URL,
    cookie: string,
  ): Record<string, string | string[]> {
    const headers: Record<string, string | string[]> = {}
    for (const [name, values] of Object.entries(incoming ?? {})) {
      const key = name.toLowerCase()
      if (SKIP_REQUEST_HEADERS.has(key)) continue
      if (Array.isArray(values)) headers[key] = values.map(String)
      else if (typeof values === 'string') headers[key] = values
    }
    headers.host = target.host
    headers.origin = target.origin
    headers.cookie = cookie
    headers['accept-encoding'] = 'identity'
    return headers
  }

  function dropHttp(streamId: number): HttpStreamState | undefined {
    const state = httpStreams.get(streamId)
    if (!state) return undefined
    httpStreams.delete(streamId)
    state.aborted = true
    try {
      state.response?.destroy()
    } catch {
      // 已结束的响应无需处理。
    }
    try {
      state.request?.destroy()
    } catch {
      // 已结束的请求无需处理。
    }
    return state
  }

  function finishHttp(streamId: number): void {
    const state = httpStreams.get(streamId)
    if (!state) return
    httpStreams.delete(streamId)
  }

  function abortHttp(streamId: number, reason: string): void {
    if (!httpStreams.has(streamId)) return
    deps.log.warn(`webui-bridge: ${reason}`)
    dropHttp(streamId)
    deps.tunnel.sendText({ t: 'http.abort', streamId })
  }

  function sendResponseHead(streamId: number, status: number, headers: Record<string, string[]>, hasBody: boolean): void {
    deps.tunnel.sendText({ t: 'http.res', streamId, status, headers, hasBody })
  }

  // 契约 §3.2：单帧负载 ≤ 64 KiB，超出必须切块，否则隧道会丢弃整帧。
  function sendBody(streamId: number, payload: Uint8Array): void {
    for (let offset = 0; offset < payload.byteLength; offset += MAX_BINARY_PAYLOAD_BYTES) {
      const end = Math.min(offset + MAX_BINARY_PAYLOAD_BYTES, payload.byteLength)
      deps.tunnel.sendBinary(BINARY_KIND_HTTP_BODY, streamId, payload.subarray(offset, end))
    }
  }

  function sendBodyEnd(streamId: number): void {
    deps.tunnel.sendBinary(BINARY_KIND_HTTP_END, streamId, new Uint8Array(0))
  }

  async function openHttpStream(state: HttpStreamState, forceCookie = false): Promise<void> {
    const streamId = state.frame.streamId
    let cookie: string
    try {
      cookie = await getOwnerCookie(forceCookie)
    } catch (err) {
      abortHttp(streamId, `REMOTE_WEBUI_COOKIE_FAILED: ${messageOf(err)}`)
      return
    }
    if (!active || state.aborted) return
    let target: URL
    try {
      target = localTarget(state.frame)
    } catch (err) {
      abortHttp(streamId, `REMOTE_WEBUI_BAD_FRAME: ${messageOf(err)}`)
      return
    }
    const headers = buildRequestHeaders(state.frame.headers, target, cookie)
    const method = typeof state.frame.method === 'string' ? state.frame.method.toUpperCase() : 'GET'
    let request: ClientRequest
    try {
      request =
        target.protocol === 'https:'
          ? httpsRequest(target, { method, headers, rejectUnauthorized: false })
          : httpRequest(target, { method, headers })
    } catch (err) {
      abortHttp(streamId, `REMOTE_WEBUI_UPSTREAM_FAILED: ${messageOf(err)}`)
      return
    }
    state.request = request
    request.on('response', (response) => {
      onHttpResponse(state, response)
    })
    request.on('error', (err) => {
      if (!state.aborted) abortHttp(streamId, `REMOTE_WEBUI_UPSTREAM_FAILED: ${err.message}`)
    })
    for (const chunk of state.chunks.splice(0)) request.write(chunk)
    if (state.ended) request.end()
  }

  function onHttpResponse(state: HttpStreamState, response: IncomingMessage): void {
    state.response = response
    const streamId = state.frame.streamId
    const status = response.statusCode ?? 502
    const method = typeof state.frame.method === 'string' ? state.frame.method.toUpperCase() : 'GET'
    if (status === 401 && !state.retried && !state.frame.hasBody) {
      state.retried = true
      response.resume()
      response.on('end', () => {
        void openHttpStream(state, true)
      })
      return
    }
    const contentType = String(response.headers['content-type'] ?? '').toLowerCase()
    if (contentType.startsWith('text/html') && method !== 'HEAD') {
      const parts: Buffer[] = []
      response.on('data', (chunk: Buffer) => {
        parts.push(chunk)
      })
      response.on('end', () => {
        if (state.aborted) return
        const body = Buffer.from(injectWebUiShim(Buffer.concat(parts).toString('utf8')), 'utf8')
        const headers = responseHeaderRecord(response.headers)
        headers['content-type'] = ['text/html; charset=utf-8']
        headers['content-length'] = [String(body.byteLength)]
        delete headers['content-encoding']
        delete headers['transfer-encoding']
        sendResponseHead(streamId, status, headers, true)
        sendBody(streamId, body)
        sendBodyEnd(streamId)
        finishHttp(streamId)
      })
      response.on('error', (err) => {
        if (!state.aborted) abortHttp(streamId, `REMOTE_WEBUI_UPSTREAM_FAILED: ${err.message}`)
      })
      return
    }
    const hasBody = method !== 'HEAD' && status !== 204 && status !== 304
    sendResponseHead(streamId, status, responseHeaderRecord(response.headers), hasBody)
    if (!hasBody) {
      response.resume()
      finishHttp(streamId)
      return
    }
    response.on('data', (chunk: Buffer) => {
      if (!state.aborted) sendBody(streamId, toBytes(chunk))
    })
    response.on('end', () => {
      if (state.aborted) return
      sendBodyEnd(streamId)
      finishHttp(streamId)
    })
    response.on('error', (err) => {
      if (!state.aborted) abortHttp(streamId, `REMOTE_WEBUI_UPSTREAM_FAILED: ${err.message}`)
    })
  }

  function handleHttpRequest(frame: HttpReqFrame): void {
    const streamId = frame.streamId
    if (!isStreamId(streamId)) {
      deps.log.warn('webui-bridge: 丢弃 streamId 非法的 http.req')
      return
    }
    dropHttp(streamId)
    const state: HttpStreamState = {
      frame,
      chunks: [],
      ended: frame.hasBody !== true,
      aborted: false,
      retried: false,
    }
    httpStreams.set(streamId, state)
    void openHttpStream(state)
  }

  function sendWsAck(streamId: number, ok: boolean, protocol?: string, error?: string): void {
    deps.tunnel.sendText({
      t: 'ws.ack',
      streamId,
      ok,
      ...(protocol ? { protocol } : {}),
      ...(error ? { error } : {}),
    })
  }

  function dropWs(streamId: number): WsStreamState | undefined {
    const state = wsStreams.get(streamId)
    if (!state) return undefined
    wsStreams.delete(streamId)
    try {
      state.socket.terminate()
    } catch {
      // 已关闭的套接字无需处理。
    }
    return state
  }

  async function openWsStream(streamId: number, frame: WsOpenFrame, retried: boolean): Promise<void> {
    let cookie: string
    try {
      cookie = await getOwnerCookie(retried)
    } catch (err) {
      sendWsAck(streamId, false, undefined, `REMOTE_WEBUI_COOKIE_FAILED: ${messageOf(err)}`)
      return
    }
    if (!active) return
    let target: URL
    try {
      target = localTarget(frame)
    } catch (err) {
      sendWsAck(streamId, false, undefined, `REMOTE_WEBUI_BAD_FRAME: ${messageOf(err)}`)
      return
    }
    const secure = target.protocol === 'https:'
    target.protocol = secure ? 'wss:' : 'ws:'
    const socket = new WebSocket(target.href, {
      headers: {
        host: target.host,
        origin: `${secure ? 'https:' : 'http:'}//${target.host}`,
        cookie,
        'accept-encoding': 'identity',
      },
      handshakeTimeout: 15_000,
      ...(secure ? { rejectUnauthorized: false } : {}),
    })
    const state: WsStreamState = { streamId, socket, opened: false, silentClose: false }
    wsStreams.set(streamId, state)
    socket.on('open', () => {
      state.opened = true
      sendWsAck(streamId, true, socket.protocol || undefined)
    })
    socket.on('message', (data, isBinary) => {
      if (!active || state.silentClose) return
      const payload = toBytes(data)
      // WS 帧即完整消息，无法分片；超限时显式关闭而不是静默丢帧。
      if (payload.byteLength > MAX_BINARY_PAYLOAD_BYTES) {
        state.silentClose = true
        wsStreams.delete(streamId)
        deps.tunnel.sendText({ t: 'ws.close', streamId, code: 1009, reason: 'message too large' })
        try {
          socket.close(1009, 'message too large')
        } catch {
          // 已关闭的套接字无需处理。
        }
        return
      }
      const kind = isBinary ? BINARY_KIND_WS_BINARY : BINARY_KIND_WS_TEXT
      deps.tunnel.sendBinary(kind, streamId, payload)
    })
    socket.on('unexpected-response', (_request, response) => {
      response.resume()
      if (response.statusCode === 401 && !retried) {
        wsStreams.delete(streamId)
        try {
          socket.terminate()
        } catch {
          // 握手阶段套接字已结束。
        }
        void openWsStream(streamId, frame, true)
        return
      }
      sendWsAck(streamId, false, undefined, `REMOTE_WEBUI_UPSTREAM_FAILED: HTTP ${response.statusCode ?? 0}`)
      dropWs(streamId)
    })
    socket.on('error', (err) => {
      if (!state.opened) sendWsAck(streamId, false, undefined, `REMOTE_WEBUI_UPSTREAM_FAILED: ${err.message}`)
      else if (!state.silentClose) {
        deps.tunnel.sendText({ t: 'ws.close', streamId, code: 1011, reason: `upstream error: ${err.message}` })
      }
      dropWs(streamId)
    })
    socket.on('close', (code, reason) => {
      wsStreams.delete(streamId)
      if (state.opened && !state.silentClose) {
        deps.tunnel.sendText({ t: 'ws.close', streamId, code, reason: reason.toString() })
      }
    })
  }

  function handleWsOpen(frame: WsOpenFrame): void {
    if (!isStreamId(frame.streamId)) {
      deps.log.warn('webui-bridge: 丢弃 streamId 非法的 ws.open')
      return
    }
    dropWs(frame.streamId)
    void openWsStream(frame.streamId, frame, false)
  }

  function closeWs(streamId: number, code: number, reason: string): void {
    const state = wsStreams.get(streamId)
    if (!state) return
    state.silentClose = true
    wsStreams.delete(streamId)
    try {
      state.socket.close(Number.isInteger(code) ? code : 1000, reason)
    } catch {
      try {
        state.socket.terminate()
      } catch {
        // 套接字已结束。
      }
    }
  }

  function cleanupStreams(): void {
    for (const streamId of [...httpStreams.keys()]) dropHttp(streamId)
    for (const streamId of [...wsStreams.keys()]) dropWs(streamId)
  }

  function subscribeStatus(): void {
    if (offStatus) return
    try {
      offStatus = deps.tunnel.onStatus((status) => {
        if (status !== 'online') cleanupStreams()
      })
    } catch (err) {
      deps.log.debug(`webui-bridge: 订阅隧道状态失败: ${messageOf(err)}`)
      offStatus = null
    }
  }

  function unsubscribeStatus(): void {
    if (!offStatus) return
    try {
      offStatus()
    } catch {
      // 插件卸载时监听可能已移除。
    }
    offStatus = null
  }

  return {
    status() {
      return { available: availableNow(), active }
    },
    async toggle(enabled) {
      if (enabled) {
        if (!availableNow()) return unavailable()
        active = true
        subscribeStatus()
        return { ok: true }
      }
      active = false
      unsubscribeStatus()
      cleanupStreams()
      return { ok: true }
    },
    handleText(frame) {
      if (!active || !frame || typeof frame.t !== 'string') return
      try {
        if (frame.t === 'http.req') handleHttpRequest(frame as HttpReqFrame)
        else if (frame.t === 'http.abort') {
          if (isStreamId(frame.streamId)) dropHttp(frame.streamId)
        } else if (frame.t === 'ws.open') handleWsOpen(frame as WsOpenFrame)
        else if (frame.t === 'ws.close') {
          if (isStreamId(frame.streamId)) {
            closeWs(frame.streamId, typeof frame.code === 'number' ? frame.code : 1000, typeof frame.reason === 'string' ? frame.reason : '')
          }
        }
      } catch (err) {
        deps.log.warn(`webui-bridge: 处理文本帧失败: ${messageOf(err)}`)
      }
    },
    handleBinary(kind, streamId, payload) {
      if (!active || !isStreamId(streamId) || !(payload instanceof Uint8Array)) return
      if (kind === BINARY_KIND_HTTP_BODY) {
        const state = httpStreams.get(streamId)
        if (!state || state.aborted || state.ended) return
        if (state.request) {
          state.request.write(payload)
        } else {
          state.chunks.push(payload.slice())
        }
        return
      }
      if (kind === BINARY_KIND_HTTP_END) {
        const state = httpStreams.get(streamId)
        if (!state || state.aborted) return
        state.ended = true
        state.request?.end()
        return
      }
      if (kind === BINARY_KIND_WS_TEXT || kind === BINARY_KIND_WS_BINARY) {
        const state = wsStreams.get(streamId)
        if (!state || state.socket.readyState !== WebSocket.OPEN) return
        state.socket.send(Buffer.from(payload), { binary: kind === BINARY_KIND_WS_BINARY })
      }
    },
    stopAll() {
      active = false
      unsubscribeStatus()
      cleanupStreams()
    },
  }
}
