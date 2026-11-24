import { createHash } from 'node:crypto'

import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Logger, ResolvedConfig } from './config'
import type { CredentialStore, DeviceIdentity, Grant, PersistedState } from './credentials'
import { createOidcClient, createPkce, type OidcClient } from './oidc'

const CONFIG: ResolvedConfig = {
  issuerUrl: 'https://www.example.com',
  relayUrl: 'wss://mp.example.com',
  clientId: 'dsh-remote',
  nodeName: 'test-node',
  notifyOnTurnEnd: true,
  notifyOnApproval: true,
}

const LOG: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
}

function memoryStore(initial: PersistedState = { pins: {} }): CredentialStore & { state: PersistedState } {
  const store = {
    state: structuredClone(initial),
    async load() {
      return structuredClone(store.state)
    },
    async saveGrant(grant: Grant) {
      store.state.grant = structuredClone(grant)
    },
    async saveIdentity(identity: DeviceIdentity) {
      store.state.identity = structuredClone(identity)
    },
    async setPin(peerId: string, hash: string) {
      store.state.pins[peerId] = hash
    },
    async clearPin(peerId: string) {
      delete store.state.pins[peerId]
    },
    async clear() {
      store.state = { pins: {} }
    },
  }
  return store
}

function b64urlSha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('base64url')
}

function tokenFetch(payload: Record<string, unknown>, status = 200): typeof fetch {
  return vi.fn(async () =>
    new Response(JSON.stringify(payload), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  ) as unknown as typeof fetch
}

const clients: OidcClient[] = []

afterEach(() => {
  for (const client of clients.splice(0)) client.dispose()
})

function makeClient(store: CredentialStore, fetchImpl: typeof fetch): OidcClient {
  const client = createOidcClient({
    config: CONFIG,
    store,
    log: LOG,
    domain: 'example.com',
    nodeId: async () => 'node-test',
    fetch: fetchImpl,
    now: () => 1_700_000_000_000,
  })
  clients.push(client)
  return client
}

function stateOf(authorizationUrl: string): string {
  const state = new URL(authorizationUrl).searchParams.get('state')
  if (!state) throw new Error('missing state in authorization URL')
  return state
}

describe('PKCE and authorization URL', () => {
  it('derives an S256 challenge from a 43-character verifier', () => {
    const pkce = createPkce((length) => new Uint8Array(length).fill(7))
    expect(pkce.verifier).toHaveLength(43)
    expect(pkce.challenge).toBe(b64urlSha256(pkce.verifier))
    expect(pkce.verifier).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('builds the RFC 8252 loopback authorization URL', async () => {
    const client = makeClient(memoryStore(), tokenFetch({}))
    const login = await client.start()
    const url = new URL(login.authorizationUrl)
    expect(url.origin + url.pathname).toBe('https://www.example.com/oidc/oauth2/authorize')
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('client_id')).toBe('dsh-remote')
    expect(url.searchParams.get('redirect_uri')).toBe(login.redirectUri)
    expect(login.redirectUri).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/)
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('scope')).toContain('offline_access')
    login.cancel('done')
    await expect(login.wait()).rejects.toMatchObject({ code: 'REMOTE_OIDC_CANCELLED' })
  })
})

describe('authorization code exchange', () => {
  it('submits PKCE verifier and stores the grant', async () => {
    const store = memoryStore()
    const fetchMock = tokenFetch({
      access_token: 'at_123',
      refresh_token: 'ort_123',
      token_type: 'Bearer',
      expires_in: 3600,
    })
    const client = makeClient(store, fetchMock)
    const login = await client.start()
    const state = stateOf(login.authorizationUrl)
    const waiting = login.wait()

    login.submit(`http://127.0.0.1:1/callback?code=code-1&state=${state}`)
    const grant = await waiting

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [endpoint, init] = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(endpoint).toBe('https://www.example.com/oidc/oauth2/token')
    const form = new URLSearchParams(String((init as RequestInit).body))
    expect(form.get('grant_type')).toBe('authorization_code')
    expect(form.get('code')).toBe('code-1')
    expect(form.get('client_id')).toBe('dsh-remote')
    expect(form.get('redirect_uri')).toBe(login.redirectUri)
    const verifier = form.get('code_verifier') ?? ''
    expect(b64urlSha256(verifier)).toBe(new URL(login.authorizationUrl).searchParams.get('code_challenge'))

    expect(grant).toMatchObject({
      issuer: CONFIG.issuerUrl,
      relay: CONFIG.relayUrl,
      clientId: 'dsh-remote',
      nodeId: 'node-test',
      accessToken: 'at_123',
      refreshToken: 'ort_123',
      domain: 'example.com',
      expiresAt: 1_700_000_000_000 + 3_600_000,
    })
    expect(store.state.grant).toEqual(grant)
    expect(client.pending()).toBeNull()
  })

  it('rejects a mismatched state without exchanging the code', async () => {
    const fetchMock = tokenFetch({ access_token: 'at' })
    const client = makeClient(memoryStore(), fetchMock)
    const login = await client.start()
    let mismatch: unknown
    try {
      login.submit('http://127.0.0.1:1/callback?code=code-1&state=wrong')
    } catch (err) {
      mismatch = err
    }
    expect(mismatch).toMatchObject({ code: 'REMOTE_OIDC_STATE_MISMATCH' })
    expect(fetchMock).not.toHaveBeenCalled()
    login.cancel('cleanup')
    await expect(login.wait()).rejects.toMatchObject({ code: 'REMOTE_OIDC_CANCELLED' })
  })

  it('surfaces token endpoint rejections', async () => {
    const fetchMock = tokenFetch({ error: 'invalid_grant', error_description: 'bad code' }, 400)
    const client = makeClient(memoryStore(), fetchMock)
    const login = await client.start()
    const state = stateOf(login.authorizationUrl)
    login.submit(`http://127.0.0.1:1/callback?code=bad&state=${state}`)
    await expect(login.wait()).rejects.toMatchObject({
      code: 'REMOTE_OIDC_TOKEN_FAILED',
      oauthError: 'invalid_grant',
      status: 400,
    })
  })
})

describe('refresh', () => {
  it('single-flights concurrent refreshes and rotates the stored grant', async () => {
    const grant: Grant = {
      issuer: CONFIG.issuerUrl,
      relay: CONFIG.relayUrl,
      clientId: 'dsh-remote',
      nodeId: 'node-test',
      accessToken: 'at_old',
      refreshToken: 'ort_old',
      expiresAt: 1_000,
      domain: 'example.com',
    }
    const store = memoryStore({ grant, pins: {} })
    const fetchMock = tokenFetch({
      access_token: 'at_new',
      refresh_token: 'ort_new',
      token_type: 'Bearer',
      expires_in: 7200,
    })
    const client = makeClient(store, fetchMock)
    const [first, second] = await Promise.all([client.refresh(grant), client.refresh(grant)])
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(first).toBe(second)
    expect(first).toMatchObject({
      accessToken: 'at_new',
      refreshToken: 'ort_new',
      nodeId: 'node-test',
      expiresAt: 1_700_000_000_000 + 7_200_000,
    })
    expect(store.state.grant?.accessToken).toBe('at_new')
  })

  it('keeps the old refresh token when the response omits a new one', async () => {
    const grant: Grant = {
      issuer: CONFIG.issuerUrl,
      relay: CONFIG.relayUrl,
      clientId: 'dsh-remote',
      nodeId: 'node-test',
      accessToken: 'at_old',
      refreshToken: 'ort_old',
      expiresAt: 1_000,
      domain: 'example.com',
    }
    const store = memoryStore({ grant, pins: {} })
    const client = makeClient(store, tokenFetch({ access_token: 'at_new', token_type: 'Bearer', expires_in: 60 }))
    const refreshed = await client.refresh(grant)
    expect(refreshed?.refreshToken).toBe('ort_old')
  })

  it('returns null when the refresh token is rejected', async () => {
    const grant: Grant = {
      issuer: CONFIG.issuerUrl,
      relay: CONFIG.relayUrl,
      clientId: 'dsh-remote',
      nodeId: 'node-test',
      accessToken: 'at_old',
      refreshToken: 'ort_old',
      expiresAt: 1_000,
      domain: 'example.com',
    }
    const client = makeClient(memoryStore({ grant, pins: {} }), tokenFetch({ error: 'invalid_grant' }, 400))
    await expect(client.refresh(grant)).resolves.toBeNull()
  })

  it('returns null without a refresh token or network call', async () => {
    const grant: Grant = {
      issuer: CONFIG.issuerUrl,
      relay: CONFIG.relayUrl,
      clientId: 'dsh-remote',
      nodeId: 'node-test',
      accessToken: 'at_old',
      refreshToken: '',
      expiresAt: 1_000,
      domain: 'example.com',
    }
    const fetchMock = tokenFetch({})
    const client = makeClient(memoryStore({ grant, pins: {} }), fetchMock)
    await expect(client.refresh(grant)).resolves.toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
