import { createServer, type Server } from 'node:http'

import type { Context } from '@deepseek-ai/cordis'
import { WebSocketServer } from 'ws'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Logger, ResolvedConfig } from './config'
import type { CredentialStore } from './credentials'
import { createSeededRng } from './crypto/index'
import type { BridgeDeps } from './session-bridge'
import type { Tunnel } from './tunnel'
import { BINARY_KIND_HTTP_BODY, BINARY_KIND_HTTP_END, BINARY_KIND_WS_BINARY, BINARY_KIND_WS_TEXT, MAX_BINARY_PAYLOAD_BYTES, type TunnelFrame } from './tunnel-protocol'
import { createWebUiBridge, injectWebUiShim, type WebUiBridge } from './webui-bridge'

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

const PAGE_HTML =
  '<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>dsh</title></head><body><div id="root" class="dsh-root">ui</div></body></html>'

const cleanup: Array<() => Promise<void> | void> = []

afterEach(async () => {
  while (cleanup.length > 0) await cleanup.pop()!()
})

interface BridgeHarness {
  bridge: WebUiBridge
  text: TunnelFrame[]
  binary: Array<{ kind: number; streamId: number; payload: Uint8Array }>
  origin: string
  server: Server
  wss: WebSocketServer
  state: { cookie: string; method: string; wsCloseCode?: number }
  statusHandlers: Set<(status: string) => void>
}

async function createHarness(): Promise<BridgeHarness> {
  const state: { cookie: string; method: string; wsCloseCode?: number } = { cookie: '', method: '' }
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://local')
    state.cookie = req.headers.cookie ?? ''
    state.method = req.method ?? ''
    if (url.pathname === '/' && url.searchParams.get('token') === 't') {
      res.writeHead(303, {
        'set-cookie': 'dsh-auth-test=secret; Path=/; HttpOnly; Max-Age=60',
        location: './',
      })
      res.end()
      return
    }
    if (url.pathname === '/page') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(PAGE_HTML)
      return
    }
    if (url.pathname === '/big-page') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(`<html><head></head><body>${'x'.repeat(150 * 1024)}</body></html>`)
      return
    }
    if (url.pathname === '/echo') {
      const chunks: Buffer[] = []
      req.on('data', (chunk: Buffer) => chunks.push(chunk))
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'x-method': req.method ?? '' })
        res.end(Buffer.concat(chunks))
      })
      return
    }
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
  })
  const wss = new WebSocketServer({ server, path: '/ws' })
  wss.on('connection', (socket) => {
    socket.on('message', (data, isBinary) => {
      socket.send(data, { binary: isBinary })
    })
    socket.on('close', (code) => {
      state.wsCloseCode = code
    })
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : 0
  const origin = `http://127.0.0.1:${port}`

  const text: TunnelFrame[] = []
  const binary: Array<{ kind: number; streamId: number; payload: Uint8Array }> = []
  const statusHandlers = new Set<(status: string) => void>()
  const tunnel = {
    status: 'online',
    async connect() {},
    disconnect() {},
    sendText(frame: TunnelFrame) {
      text.push(frame)
    },
    sendBinary(kind: number, streamId: number, payload: Uint8Array) {
      binary.push({ kind, streamId, payload })
    },
    onText() {
      return () => true
    },
    onBinary() {
      return () => true
    },
    onStatus(handler: (status: string) => void) {
      statusHandlers.add(handler)
      return () => statusHandlers.delete(handler)
    },
    dispose() {},
  } as unknown as Tunnel
  const store: CredentialStore = {
    async load() {
      return { pins: {} }
    },
    async saveGrant() {},
    async saveIdentity() {},
    async setPin() {},
    async clearPin() {},
    async clear() {},
  }
  const services: Record<string, unknown> = {
    webServer: { getOrigin: () => origin, protocol: 'http:', host: '127.0.0.1', port },
    connection: {
      authenticatedUrl: (base: string) => `${base}?token=t`,
    },
  }
  const ctx = {
    get(name: string) {
      return services[name]
    },
  } as unknown as Context
  const deps: BridgeDeps = {
    config: CONFIG,
    store,
    tunnel,
    rng: createSeededRng(new Uint8Array(32).fill(5)),
    log: LOG,
    onStateChanged() {},
    onNotify() {},
    onNotifyCancel() {},
  }
  const harness: BridgeHarness = {
    bridge: createWebUiBridge(ctx, deps),
    text,
    binary,
    origin,
    server,
    wss,
    state,
    statusHandlers,
  }
  cleanup.push(async () => {
    harness.bridge.stopAll()
    await new Promise<void>((resolve) => wss.close(() => resolve()))
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })
  return harness
}

function bodyOf(harness: BridgeHarness, streamId: number): string {
  return Buffer.concat(
    harness.binary
      .filter((entry) => entry.streamId === streamId && entry.kind === BINARY_KIND_HTTP_BODY)
      .map((entry) => Buffer.from(entry.payload)),
  ).toString('utf8')
}

function framesFor(harness: BridgeHarness, streamId: number, kind: number) {
  return harness.binary.filter((entry) => entry.streamId === streamId && entry.kind === kind)
}

describe('webui bridge', () => {
  it('injects the viewport and safe-area shim without touching dsh markup', () => {
    const output = injectWebUiShim(PAGE_HTML)
    expect(output).toContain(
      '<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover">',
    )
    expect(output).toContain(
      ':where(html,body,#root){height:100dvh;min-height:100%;-webkit-text-size-adjust:100%;box-sizing:border-box}',
    )
    expect(output).toContain(
      ':where(body){padding-top:env(safe-area-inset-top);padding-bottom:env(safe-area-inset-bottom)}',
    )
    expect(output).toContain('@media (orientation:landscape) and (max-height:520px)')
    expect(output).toContain('env(safe-area-inset-left)')
    expect(output).toContain('--gt-vvh')
    expect(output).toContain('<div id="root" class="dsh-root">ui</div>')
    expect(output).not.toContain('content="width=device-width, initial-scale=1"')
    expect(output).toMatch(/<style data-gt-remote-webui="1">/)
    expect(output).toMatch(/<script data-gt-remote-webui="1">/)
    // 幂等：重复应用不再插入第二份垫片。
    expect(injectWebUiShim(output)).toBe(output)

    const headless = injectWebUiShim('<div>bare</div>')
    expect(headless).toContain('<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover">')
    expect(headless).toContain('<div>bare</div>')
    expect(injectWebUiShim('')).toBe('')
  })

  it('proxies HTTP requests with the owner cookie and injects HTML only', async () => {
    const harness = await createHarness()
    expect(await harness.bridge.toggle(true)).toEqual({ ok: true })
    expect(harness.bridge.status()).toEqual({ available: true, active: true })

    harness.bridge.handleText({
      t: 'http.req',
      streamId: 1,
      method: 'GET',
      path: '/page',
      query: '',
      headers: { accept: ['text/html'] },
      hasBody: false,
    })
    await vi.waitFor(
      () => {
        expect(harness.text.some((frame) => frame.t === 'http.res' && frame.streamId === 1)).toBe(true)
        expect(framesFor(harness, 1, BINARY_KIND_HTTP_END)).toHaveLength(1)
      },
      { timeout: 3000 },
    )
    const response = harness.text.find((frame) => frame.t === 'http.res' && frame.streamId === 1)
    expect(response).toMatchObject({ status: 200, hasBody: true })
    const html = bodyOf(harness, 1)
    expect(html).toContain('width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover')
    expect(html).toContain('--gt-vvh')
    expect(html).toContain('class="dsh-root"')
    expect(harness.state.cookie).toContain('dsh-auth-test=secret')

    harness.bridge.handleText({
      t: 'http.req',
      streamId: 2,
      method: 'POST',
      path: '/echo',
      query: '',
      headers: { 'content-type': ['text/plain'] },
      hasBody: true,
    })
    harness.bridge.handleBinary(BINARY_KIND_HTTP_BODY, 2, new Uint8Array(Buffer.from('hello ')))
    harness.bridge.handleBinary(BINARY_KIND_HTTP_BODY, 2, new Uint8Array(Buffer.from('world')))
    harness.bridge.handleBinary(BINARY_KIND_HTTP_END, 2, new Uint8Array(0))
    await vi.waitFor(
      () => {
        expect(harness.text.some((frame) => frame.t === 'http.res' && frame.streamId === 2)).toBe(true)
        expect(framesFor(harness, 2, BINARY_KIND_HTTP_END)).toHaveLength(1)
      },
      { timeout: 3000 },
    )
    const echoed = harness.text.find((frame) => frame.t === 'http.res' && frame.streamId === 2)
    expect(echoed).toMatchObject({ status: 200, hasBody: true })
    expect(harness.state.method).toBe('POST')
    expect(bodyOf(harness, 2)).toBe('hello world')
  })

  it('routes binary frames for HTTP bodies and WebSocket text/binary messages', async () => {
    const harness = await createHarness()
    await harness.bridge.toggle(true)

    harness.bridge.handleText({ t: 'ws.open', streamId: 7, path: '/ws', query: '', headers: {} })
    await vi.waitFor(
      () => {
        expect(
          harness.text.some(
            (frame) => frame.t === 'ws.ack' && frame.streamId === 7 && frame.ok === true,
          ),
        ).toBe(true)
      },
      { timeout: 3000 },
    )

    harness.bridge.handleBinary(BINARY_KIND_WS_TEXT, 7, new Uint8Array(Buffer.from('ping')))
    await vi.waitFor(
      () => {
        const echoed = framesFor(harness, 7, BINARY_KIND_WS_TEXT)
        expect(echoed).toHaveLength(1)
        expect(Buffer.from(echoed[0].payload).toString('utf8')).toBe('ping')
      },
      { timeout: 3000 },
    )

    harness.bridge.handleBinary(BINARY_KIND_WS_BINARY, 7, new Uint8Array([1, 2, 3, 4]))
    await vi.waitFor(
      () => {
        const echoed = framesFor(harness, 7, BINARY_KIND_WS_BINARY)
        expect(echoed).toHaveLength(1)
        expect([...echoed[0].payload]).toEqual([1, 2, 3, 4])
      },
      { timeout: 3000 },
    )

    // 未知 streamId 的二进制帧必须被静默丢弃。
    harness.bridge.handleBinary(BINARY_KIND_WS_TEXT, 999, new Uint8Array([9]))
    harness.bridge.handleText({ t: 'http.abort', streamId: 999 })

    harness.bridge.handleText({ t: 'ws.close', streamId: 7, code: 1000, reason: 'bye' })
    await vi.waitFor(() => expect(harness.state.wsCloseCode).toBe(1000), { timeout: 3000 })
  })

  it('fragments HTTP bodies larger than the 64 KiB frame limit', async () => {
    const harness = await createHarness()
    await harness.bridge.toggle(true)

    harness.bridge.handleText({
      t: 'http.req',
      streamId: 11,
      method: 'GET',
      path: '/big-page',
      query: '',
      headers: {},
      hasBody: false,
    })
    await vi.waitFor(
      () => {
        expect(harness.text.some((frame) => frame.t === 'http.res' && frame.streamId === 11)).toBe(true)
        expect(framesFor(harness, 11, BINARY_KIND_HTTP_END)).toHaveLength(1)
      },
      { timeout: 3000 },
    )

    const frames = framesFor(harness, 11, BINARY_KIND_HTTP_BODY)
    expect(frames.length).toBeGreaterThan(1)
    for (const frame of frames) {
      expect(frame.payload.byteLength).toBeLessThanOrEqual(MAX_BINARY_PAYLOAD_BYTES)
    }
    const html = bodyOf(harness, 11)
    expect(html).toContain('<body>')
    expect(html.length).toBeGreaterThan(150 * 1024)
  })

  it('closes the WebSocket with 1009 when an upstream message exceeds the frame limit', async () => {
    const harness = await createHarness()
    await harness.bridge.toggle(true)

    harness.bridge.handleText({ t: 'ws.open', streamId: 12, path: '/ws', query: '', headers: {} })
    await vi.waitFor(
      () => {
        expect(
          harness.text.some((frame) => frame.t === 'ws.ack' && frame.streamId === 12 && frame.ok === true),
        ).toBe(true)
      },
      { timeout: 3000 },
    )

    harness.bridge.handleBinary(
      BINARY_KIND_WS_TEXT,
      12,
      new Uint8Array(Buffer.alloc(MAX_BINARY_PAYLOAD_BYTES + 1, 0x61)),
    )
    await vi.waitFor(
      () => {
        expect(
          harness.text.some((frame) => frame.t === 'ws.close' && frame.streamId === 12 && frame.code === 1009),
        ).toBe(true)
      },
      { timeout: 3000 },
    )
  })

  it('stops forwarding after toggle(false) and reports unavailable without services', async () => {
    const harness = await createHarness()
    await harness.bridge.toggle(true)
    await harness.bridge.toggle(false)
    expect(harness.bridge.status()).toEqual({ available: true, active: false })
    harness.bridge.handleText({
      t: 'http.req',
      streamId: 3,
      method: 'GET',
      path: '/page',
      query: '',
      headers: {},
      hasBody: false,
    })
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(harness.text).toHaveLength(0)

    const ctx = { get: () => undefined } as unknown as Context
    const deps = {
      config: CONFIG,
      store: {
        async load() {
          return { pins: {} }
        },
        async saveGrant() {},
        async saveIdentity() {},
        async setPin() {},
        async clearPin() {},
        async clear() {},
      } as CredentialStore,
      tunnel: {
        sendText() {},
        sendBinary() {},
        onStatus() {
          return () => true
        },
      } as unknown as Tunnel,
      rng: createSeededRng(new Uint8Array(32).fill(6)),
      log: LOG,
      onStateChanged() {},
      onNotify() {},
      onNotifyCancel() {},
    } satisfies BridgeDeps
    const bridge = createWebUiBridge(ctx, deps)
    expect(bridge.status()).toEqual({ available: false, active: false })
    expect(await bridge.toggle(true)).toEqual({
      ok: false,
      error: 'REMOTE_WEBUI_UNAVAILABLE: dsh webServer/connection is not available',
    })
  })

  it('cleans streams when the tunnel goes offline', async () => {
    const harness = await createHarness()
    await harness.bridge.toggle(true)
    expect(harness.statusHandlers.size).toBe(1)

    harness.bridge.handleText({ t: 'ws.open', streamId: 8, path: '/ws', query: '', headers: {} })
    await vi.waitFor(
      () => {
        expect(harness.text.some((frame) => frame.t === 'ws.ack' && frame.streamId === 8 && frame.ok === true)).toBe(true)
      },
      { timeout: 3000 },
    )
    for (const handler of harness.statusHandlers) handler('offline')
    harness.bridge.handleBinary(BINARY_KIND_WS_TEXT, 8, new Uint8Array(Buffer.from('dropped')))
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(framesFor(harness, 8, BINARY_KIND_WS_TEXT)).toHaveLength(0)
  })
})
