/**
 * WebUI 控制路由（契约 §6.1）：在 `ctx.webServer` 注册
 * `POST /api/gooftoken-remote/control`（exact）。先用 `ctx.connection.admit`
 * 鉴权，再处理 status / session.toggle / webui.toggle；无 webServer 时静默跳过。
 */
import type { IncomingMessage, ServerResponse } from 'node:http'

import type { Context } from '@deepseek-ai/cordis'

import type { Logger } from './config.js'
import type { SessionBridge } from './session-bridge.js'
import type { WebUiBridge } from './webui-bridge.js'

export const CONTROL_ROUTE_PATH = '/api/gooftoken-remote/control'

export type ControlAction = 'status' | 'session.toggle' | 'webui.toggle'

export interface ControlRouteDeps {
  runtime: { session: SessionBridge; webui: WebUiBridge }
  log: Logger
}

export type ControlRouteErrorCode =
  | 'REMOTE_CONTROL_UNAUTHORIZED'
  | 'REMOTE_CONTROL_FORBIDDEN'
  | 'REMOTE_CONTROL_METHOD_NOT_ALLOWED'
  | 'REMOTE_CONTROL_BAD_REQUEST'
  | 'REMOTE_CONTROL_BODY_TOO_LARGE'
  | 'REMOTE_CONTROL_INTERNAL'

const MAX_BODY_BYTES = 64 * 1024

interface WebRouteLike {
  kind: 'exact'
  path: string
  handler(req: IncomingMessage, res: ServerResponse): void | Promise<void>
}

interface WebServerLike {
  register?(route: WebRouteLike): () => void
}

interface AdmissionLike {
  peer?: unknown
  rejection?: number
}

interface ConnectionLike {
  admit?(request: { headers: IncomingMessage['headers'] }): AdmissionLike
}

interface HostContextLike {
  get?(name: string): unknown
}

interface ErrorPayload {
  ok: false
  error: { code: ControlRouteErrorCode | string; message: string }
}

class BodyTooLargeError extends Error {}
class BodyInvalidError extends Error {}

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

function errorPayload(code: ControlRouteErrorCode, message: string): ErrorPayload {
  return { ok: false, error: { code, message } }
}

function writeJson(res: ServerResponse, status: number, payload: unknown, extra: Record<string, string> = {}): void {
  const body = JSON.stringify(payload)
  try {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': String(Buffer.byteLength(body)),
      ...extra,
    })
    res.end(body)
  } catch {
    // 连接已断开时无需再写响应。
  }
}

function querySessionId(rawUrl: string | undefined): string | undefined {
  try {
    const value = new URL(rawUrl ?? '/', 'http://dsh.invalid').searchParams.get('sessionId')
    return value?.trim() || undefined
  } catch {
    return undefined
  }
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer | string) => {
      const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
      size += buffer.byteLength
      if (size > MAX_BODY_BYTES) {
        reject(new BodyTooLargeError('request body is too large'))
        req.destroy()
        return
      }
      chunks.push(buffer)
    })
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({})
        return
      }
      try {
        const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          reject(new BodyInvalidError('request body must be a JSON object'))
          return
        }
        resolve(parsed as Record<string, unknown>)
      } catch {
        reject(new BodyInvalidError('request body is not valid JSON'))
      }
    })
    req.on('error', (err) => {
      reject(err)
    })
  })
}

function statusData(deps: ControlRouteDeps, sessionId?: string): Record<string, unknown> {
  const data: Record<string, unknown> = { webui: deps.runtime.webui.status() }
  if (sessionId) data.session = deps.runtime.session.status(sessionId)
  return data
}

async function handleRequest(
  ctx: Context,
  deps: ControlRouteDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const connection = serviceOf<ConnectionLike>(ctx, 'connection')
  let admission: AdmissionLike
  try {
    admission = connection?.admit?.({ headers: req.headers }) ?? { rejection: 401 }
  } catch {
    admission = { rejection: 401 }
  }
  if (admission.rejection !== undefined) {
    const forbidden = admission.rejection === 403
    writeJson(
      res,
      admission.rejection,
      errorPayload(
        forbidden ? 'REMOTE_CONTROL_FORBIDDEN' : 'REMOTE_CONTROL_UNAUTHORIZED',
        forbidden ? 'request origin or host is not trusted' : 'a valid owner browser session is required',
      ),
    )
    return
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    writeJson(res, 200, { ok: true, data: statusData(deps, querySessionId(req.url)) })
    return
  }
  if (req.method !== 'POST') {
    writeJson(res, 405, errorPayload('REMOTE_CONTROL_METHOD_NOT_ALLOWED', 'use GET or POST'), {
      allow: 'GET, POST',
    })
    return
  }

  let body: Record<string, unknown>
  try {
    body = await readJsonBody(req)
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      writeJson(res, 413, errorPayload('REMOTE_CONTROL_BODY_TOO_LARGE', err.message))
      return
    }
    writeJson(res, 400, errorPayload('REMOTE_CONTROL_BAD_REQUEST', messageOf(err)))
    return
  }

  const action = typeof body.action === 'string' ? body.action : ''
  switch (action as ControlAction | '') {
    case 'status': {
      const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : querySessionId(req.url)
      writeJson(res, 200, { ok: true, data: statusData(deps, sessionId) })
      return
    }
    case 'session.toggle': {
      const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : ''
      const enabled = body.enabled
      if (!sessionId || typeof enabled !== 'boolean') {
        writeJson(
          res,
          400,
          errorPayload('REMOTE_CONTROL_BAD_REQUEST', 'session.toggle requires sessionId and enabled'),
        )
        return
      }
      const result = await deps.runtime.session.toggle(sessionId, enabled)
      if (!result.ok) {
        writeJson(res, 200, {
          ok: false,
          error: { code: 'REMOTE_SESSION_TOGGLE_FAILED', message: result.error ?? 'session toggle failed' },
          data: { session: deps.runtime.session.status(sessionId) },
        })
        return
      }
      writeJson(res, 200, { ok: true, data: { session: deps.runtime.session.status(sessionId) } })
      return
    }
    case 'webui.toggle': {
      const enabled = body.enabled
      if (typeof enabled !== 'boolean') {
        writeJson(res, 400, errorPayload('REMOTE_CONTROL_BAD_REQUEST', 'webui.toggle requires enabled'))
        return
      }
      const result = await deps.runtime.webui.toggle(enabled)
      if (!result.ok) {
        writeJson(res, 200, {
          ok: false,
          error: { code: 'REMOTE_WEBUI_TOGGLE_FAILED', message: result.error ?? 'webui toggle failed' },
          data: { webui: deps.runtime.webui.status() },
        })
        return
      }
      writeJson(res, 200, { ok: true, data: { webui: deps.runtime.webui.status() } })
      return
    }
    default:
      writeJson(res, 400, errorPayload('REMOTE_CONTROL_BAD_REQUEST', `unknown control action ${JSON.stringify(action)}`))
  }
}

/**
 * 注册控制路由；返回注销函数。没有 webServer 时返回空操作。
 */
export function registerControlRoute(ctx: Context, deps: ControlRouteDeps): () => void {
  const webServer = serviceOf<WebServerLike>(ctx, 'webServer')
  if (!webServer?.register) {
    deps.log.debug('control-route: webServer 不可用，跳过控制路由')
    return () => undefined
  }
  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    void handleRequest(ctx, deps, req, res).catch((err: unknown) => {
      deps.log.warn(`control-route: 处理请求失败: ${messageOf(err)}`)
      if (!res.headersSent) writeJson(res, 500, errorPayload('REMOTE_CONTROL_INTERNAL', 'internal control error'))
      else {
        try {
          res.end()
        } catch {
          // 响应已断开。
        }
      }
    })
  }
  try {
    const dispose = webServer.register({ kind: 'exact', path: CONTROL_ROUTE_PATH, handler })
    return () => {
      try {
        dispose()
      } catch {
        // 已卸载的 webServer 无需重复注销。
      }
    }
  } catch (err) {
    deps.log.warn(`control-route: 注册控制路由失败: ${messageOf(err)}`)
    return () => undefined
  }
}
