import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createServer as createTcpServer, type Socket } from 'node:net'

import WebSocket, { WebSocketServer } from 'ws'
import { describe, expect, it } from 'vitest'

import type { Logger, ResolvedConfig } from './config'
import type { CredentialStore, Grant, PersistedState } from './credentials'
import { createTunnel } from './tunnel'
import { TUNNEL_CONNECT_PATH, TUNNEL_SUBPROTOCOL } from './tunnel-protocol'

const LOG: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
}

const GRANT: Grant = {
  issuer: 'https://www.example.com',
  relay: 'wss://mp.example.com',
  clientId: 'dsh-remote',
  nodeId: 'node-1',
  accessToken: 'at_1',
  refreshToken: 'ort_1',
  expiresAt: Date.now() + 3_600_000,
  domain: 'example.com',
}

function storeWith(state: PersistedState): CredentialStore {
  return {
    async load() {
      return structuredClone(state)
    },
    async saveGrant() {},
    async saveIdentity() {},
    async setPin() {},
    async clearPin() {},
    async clear() {},
  }
}

function configFor(relayUrl: string): ResolvedConfig {
  return {
    issuerUrl: 'https://www.example.com',
    relayUrl,
    clientId: 'dsh-remote',
    nodeName: 'test-node',
    notifyOnTurnEnd: true,
    notifyOnApproval: true,
  }
}

describe('tunnel client', () => {
  it('connects with bearer token and subprotocol, then exchanges frames', async () => {
    const wss = new WebSocketServer({ port: 0, path: TUNNEL_CONNECT_PATH })
    await once(wss, 'listening')
    const port = (wss.address() as AddressInfo).port
    let authorization = ''
    let protocol = ''
    let serverSocket: WebSocket | undefined
    const serverFrame = new Promise<Record<string, unknown>>((resolve) => {
      wss.on('connection', (ws, request) => {
        serverSocket = ws
        authorization = String(request.headers.authorization ?? '')
        protocol = ws.protocol
        ws.on('message', (data) => resolve(JSON.parse(String(data)) as Record<string, unknown>))
        ws.send(JSON.stringify({ t: 'ping', ts: 42 }))
      })
    })

    const tunnel = createTunnel({
      config: configFor(`ws://127.0.0.1:${port}`),
      store: storeWith({ grant: GRANT, pins: {} }),
      refreshToken: async () => null,
      log: LOG,
    })
    const statuses: string[] = []
    tunnel.onStatus((status) => statuses.push(status))
    const ping = new Promise<Record<string, unknown>>((resolve) => {
      const off = tunnel.onText((frame) => {
        if (frame.t === 'ping') {
          off()
          resolve(frame)
        }
      })
    })

    try {
      await tunnel.connect()
      expect(tunnel.status).toBe('online')
      expect(authorization).toBe('Bearer at_1')
      expect(protocol).toBe(TUNNEL_SUBPROTOCOL)
      expect(await ping).toMatchObject({ t: 'ping', ts: 42 })
      expect(statuses).toContain('online')

      tunnel.sendText({ t: 'hello', proto: 1 })
      expect(await serverFrame).toMatchObject({ t: 'hello', proto: 1 })
      expect(serverSocket?.readyState).toBe(WebSocket.OPEN)
    } finally {
      tunnel.dispose()
      await new Promise<void>((resolve) => wss.close(() => resolve()))
    }
  })

  it('refreshes once on 401 and retries with the new token', async () => {
    const server = createServer((_request, response) => {
      response.statusCode = 404
      response.end()
    })
    const authorizations: string[] = []
    server.on('upgrade', (request, socket) => {
      authorizations.push(String(request.headers.authorization ?? ''))
      socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
    const port = (server.address() as AddressInfo).port
    const refreshed: Grant = { ...GRANT, accessToken: 'at_2', refreshToken: 'ort_2' }
    let refreshes = 0

    const tunnel = createTunnel({
      config: configFor(`ws://127.0.0.1:${port}`),
      store: storeWith({ grant: GRANT, pins: {} }),
      refreshToken: async () => {
        refreshes += 1
        return refreshed
      },
      log: LOG,
    })

    try {
      await expect(tunnel.connect()).rejects.toMatchObject({ code: 'REMOTE_TUNNEL_UNAUTHORIZED' })
      expect(refreshes).toBe(1)
      expect(authorizations).toHaveLength(2)
      expect(authorizations[0]).toBe('Bearer at_1')
      expect(authorizations[1]).toBe('Bearer at_2')
    } finally {
      tunnel.dispose()
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  it('settles a connecting attempt when disconnected', async () => {
    const sockets: Socket[] = []
    const server = createTcpServer((socket) => {
      sockets.push(socket)
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
    const port = (server.address() as AddressInfo).port
    const tunnel = createTunnel({
      config: configFor(`ws://127.0.0.1:${port}`),
      store: storeWith({ grant: GRANT, pins: {} }),
      refreshToken: async () => null,
      log: LOG,
    })
    try {
      const connecting = tunnel.connect()
      await new Promise((resolve) => setTimeout(resolve, 25))
      tunnel.disconnect()
      await expect(connecting).rejects.toBeInstanceOf(Error)
      expect(tunnel.status).toBe('offline')
    } finally {
      tunnel.dispose()
      for (const socket of sockets) socket.destroy()
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  it('reports a missing grant without dialing the relay', async () => {
    const tunnel = createTunnel({
      config: configFor('ws://127.0.0.1:1'),
      store: storeWith({ pins: {} }),
      refreshToken: async () => null,
      log: LOG,
    })
    try {
      await expect(tunnel.connect()).rejects.toMatchObject({ code: 'REMOTE_TUNNEL_NO_GRANT' })
      expect(tunnel.status).toBe('error')
    } finally {
      tunnel.dispose()
    }
  })
})
