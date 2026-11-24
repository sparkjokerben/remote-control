import type { IncomingMessage, ServerResponse } from 'node:http'
import { Readable } from 'node:stream'

import type { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'

import type { Logger } from './config'
import { CONTROL_ROUTE_PATH, registerControlRoute, type ControlRouteDeps } from './control-route'
import type { SessionBridge } from './session-bridge'
import type { WebUiBridge } from './webui-bridge'

const LOG: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
}

interface FakeResponse {
  headersSent: boolean
  statusCode: number
  body: string
  headers: Record<string, string>
  writeHead(code: number, headers?: Record<string, string>): FakeResponse
  end(chunk?: string): void
}

function createResponse(): FakeResponse {
  const res: FakeResponse = {
    headersSent: false,
    statusCode: 0,
    body: '',
    headers: {},
    writeHead(code, headers) {
      this.statusCode = code
      this.headers = { ...(headers ?? {}) }
      this.headersSent = true
      return this
    },
    end(chunk) {
      if (typeof chunk === 'string') this.body = chunk
    },
  }
  return res
}

function createRequest(method: string, url: string, body?: unknown): IncomingMessage {
  const payload = body === undefined ? '' : JSON.stringify(body)
  const stream = Readable.from(payload ? [payload] : [])
  return Object.assign(stream, {
    method,
    url,
    headers: { host: '127.0.0.1:3080' },
  }) as unknown as IncomingMessage
}

interface RouteLike {
  kind: string
  path: string
  handler(req: IncomingMessage, res: ServerResponse): void | Promise<void>
}

function setup(options: { admission?: () => unknown } = {}) {
  const routes: RouteLike[] = []
  const dispose = vi.fn()
  const services: Record<string, unknown> = {
    webServer: {
      register(route: RouteLike) {
        routes.push(route)
        return dispose
      },
    },
    connection: {
      admit: vi.fn(options.admission ?? (() => ({ peer: {} }))),
    },
  }
  const ctx = {
    get(name: string) {
      return services[name]
    },
  } as unknown as Context
  const session = {
    shared: ['session-1'],
    status: vi.fn(() => ({ shared: true, safetyNumber: '12345 67890 12345 67890' })),
    pendingApprovals: vi.fn(() => []),
    approve: vi.fn(async () => ({ ok: true, approved: 0 })),
    clients: vi.fn(() => []),
    reset: vi.fn(async () => ({ ok: true, reset: 0 })),
    toggle: vi.fn(async (): Promise<{ ok: boolean; error?: string }> => ({ ok: true })),
    stopAll: vi.fn(async () => undefined),
    handleText: vi.fn(),
    dispose: vi.fn(),
  } satisfies SessionBridge
  const webui = {
    status: vi.fn(() => ({ available: true, active: false })),
    toggle: vi.fn(async (): Promise<{ ok: boolean; error?: string }> => ({ ok: true })),
    handleText: vi.fn(),
    handleBinary: vi.fn(),
    stopAll: vi.fn(),
  } satisfies WebUiBridge
  const deps: ControlRouteDeps = { runtime: { session, webui }, log: LOG }
  const unregister = registerControlRoute(ctx, deps)
  return { routes, dispose, unregister, session, webui, ctx, deps }
}

async function run(route: RouteLike, req: IncomingMessage, res: FakeResponse): Promise<void> {
  await route.handler(req, res as unknown as ServerResponse)
  await new Promise((resolve) => setTimeout(resolve, 0))
}

function jsonOf(res: FakeResponse): any {
  return JSON.parse(res.body)
}

describe('control route', () => {
  it('registers one exact POST route and skips silently without a webServer', () => {
    const harness = setup()
    expect(harness.routes).toHaveLength(1)
    expect(harness.routes[0]).toMatchObject({ kind: 'exact', path: CONTROL_ROUTE_PATH })
    expect(CONTROL_ROUTE_PATH).toBe('/api/gooftoken-remote/control')

    const skip = registerControlRoute({ get: () => undefined } as unknown as Context, harness.deps)
    expect(typeof skip).toBe('function')
    expect(() => skip()).not.toThrow()
  })

  it('rejects requests without a live owner browser session', async () => {
    const harness = setup({ admission: () => ({ rejection: 401 }) })
    const res = createResponse()
    await run(harness.routes[0], createRequest('POST', CONTROL_ROUTE_PATH, { action: 'status' }), res)
    expect(res.statusCode).toBe(401)
    expect(jsonOf(res)).toEqual({
      ok: false,
      error: { code: 'REMOTE_CONTROL_UNAUTHORIZED', message: 'a valid owner browser session is required' },
    })
    expect(harness.session.toggle).not.toHaveBeenCalled()
    expect(harness.webui.toggle).not.toHaveBeenCalled()
  })

  it('reports forbidden for untrusted hosts', async () => {
    const harness = setup({ admission: () => ({ rejection: 403 }) })
    const res = createResponse()
    await run(harness.routes[0], createRequest('GET', CONTROL_ROUTE_PATH), res)
    expect(res.statusCode).toBe(403)
    expect(jsonOf(res).error.code).toBe('REMOTE_CONTROL_FORBIDDEN')
  })

  it('answers GET status for a session', async () => {
    const harness = setup()
    const res = createResponse()
    await run(harness.routes[0], createRequest('GET', `${CONTROL_ROUTE_PATH}?sessionId=session-1`), res)
    expect(res.statusCode).toBe(200)
    expect(res.headers['content-type']).toBe('application/json; charset=utf-8')
    expect(jsonOf(res)).toEqual({
      ok: true,
      data: {
        webui: { available: true, active: false },
        session: { shared: true, safetyNumber: '12345 67890 12345 67890' },
      },
    })
    expect(harness.session.status).toHaveBeenCalledWith('session-1')
  })

  it('handles session.toggle and webui.toggle actions', async () => {
    const harness = setup()
    const sessionRes = createResponse()
    await run(
      harness.routes[0],
      createRequest('POST', CONTROL_ROUTE_PATH, { action: 'session.toggle', sessionId: 'session-1', enabled: true }),
      sessionRes,
    )
    expect(harness.session.toggle).toHaveBeenCalledWith('session-1', true)
    expect(jsonOf(sessionRes)).toEqual({
      ok: true,
      data: { session: { shared: true, safetyNumber: '12345 67890 12345 67890' } },
    })

    const webuiRes = createResponse()
    await run(
      harness.routes[0],
      createRequest('POST', CONTROL_ROUTE_PATH, { action: 'webui.toggle', enabled: false }),
      webuiRes,
    )
    expect(harness.webui.toggle).toHaveBeenCalledWith(false)
    expect(jsonOf(webuiRes)).toEqual({ ok: true, data: { webui: { available: true, active: false } } })

    harness.webui.toggle.mockResolvedValueOnce({ ok: false, error: 'REMOTE_WEBUI_UNAVAILABLE: nope' })
    const failed = createResponse()
    await run(
      harness.routes[0],
      createRequest('POST', CONTROL_ROUTE_PATH, { action: 'webui.toggle', enabled: true }),
      failed,
    )
    expect(jsonOf(failed)).toMatchObject({
      ok: false,
      error: { code: 'REMOTE_WEBUI_TOGGLE_FAILED', message: 'REMOTE_WEBUI_UNAVAILABLE: nope' },
    })
  })

  it('rejects malformed bodies, unknown actions and wrong methods', async () => {
    const harness = setup()

    const bad = createResponse()
    await run(harness.routes[0], createRequest('POST', CONTROL_ROUTE_PATH, { action: 'nope' }), bad)
    expect(bad.statusCode).toBe(400)
    expect(jsonOf(bad).error.code).toBe('REMOTE_CONTROL_BAD_REQUEST')

    const missing = createResponse()
    await run(harness.routes[0], createRequest('POST', CONTROL_ROUTE_PATH, { action: 'session.toggle' }), missing)
    expect(missing.statusCode).toBe(400)

    const invalid = createResponse()
    const invalidReq = Object.assign(Readable.from(['{not json']), {
      method: 'POST',
      url: CONTROL_ROUTE_PATH,
      headers: { host: '127.0.0.1:3080' },
    }) as unknown as IncomingMessage
    await run(harness.routes[0], invalidReq, invalid)
    expect(invalid.statusCode).toBe(400)
    expect(jsonOf(invalid).error.code).toBe('REMOTE_CONTROL_BAD_REQUEST')

    const wrongMethod = createResponse()
    await run(harness.routes[0], createRequest('PUT', CONTROL_ROUTE_PATH), wrongMethod)
    expect(wrongMethod.statusCode).toBe(405)
    expect(jsonOf(wrongMethod).error.code).toBe('REMOTE_CONTROL_METHOD_NOT_ALLOWED')
  })

  it('unregisters the route through the returned disposer', () => {
    const harness = setup()
    harness.unregister()
    expect(harness.dispose).toHaveBeenCalledTimes(1)
  })
})
