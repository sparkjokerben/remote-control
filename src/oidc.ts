/**
 * OIDC 原生客户端（RFC 8252 回环重定向 + PKCE S256，契约 §6.1）：
 * 授权 URL 构造、本地回调、token 交换、refresh 单飞与吊销。
 * 无头环境不阻塞命令，用户可粘贴完整回调 URL 完成登录。
 */
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'

import type { Logger, ResolvedConfig } from './config.js'
import type { CredentialStore, Grant } from './credentials.js'
import { systemRng, type Rng } from './crypto/index.js'

export type OidcErrorCode =
  | 'REMOTE_OIDC_STATE_MISMATCH'
  | 'REMOTE_OIDC_CALLBACK_INVALID'
  | 'REMOTE_OIDC_AUTHORIZATION_FAILED'
  | 'REMOTE_OIDC_TOKEN_FAILED'
  | 'REMOTE_OIDC_NETWORK'
  | 'REMOTE_OIDC_TIMEOUT'
  | 'REMOTE_OIDC_CANCELLED'
  | 'REMOTE_OIDC_LISTEN_FAILED'

export class OidcError extends Error {
  readonly code: OidcErrorCode
  readonly status?: number
  readonly oauthError?: string

  constructor(
    code: OidcErrorCode,
    message: string,
    options: { cause?: unknown; status?: number; oauthError?: string } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause })
    this.name = 'OidcError'
    this.code = code
    this.status = options.status
    this.oauthError = options.oauthError
  }
}

export interface PkcePair {
  verifier: string
  challenge: string
}

export interface TokenSet {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  tokenType: string
}

export interface OidcLogin {
  readonly authorizationUrl: string
  readonly redirectUri: string
  wait(): Promise<Grant>
  submit(callbackUrl: string): void
  cancel(reason?: string): void
}

export interface OidcClient {
  start(): Promise<OidcLogin>
  pending(): OidcLogin | null
  refresh(grant: Grant): Promise<Grant | null>
  revoke(grant: Grant): Promise<void>
  dispose(): void
}

export interface OidcDeps {
  config: ResolvedConfig
  store: CredentialStore
  log: Logger
  /** 凭据记录中的部署域名。 */
  domain: string
  /** 登录成功后写入 Grant 的设备节点 id。 */
  nodeId(): Promise<string>
  fetch?: typeof fetch
  rng?: Rng
  now?: () => number
  /** 等待浏览器回调的上限；默认 10 分钟。 */
  callbackTimeoutMs?: number
  /** token 请求超时；默认 15 秒。 */
  requestTimeoutMs?: number
}

const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access']
const DEFAULT_CALLBACK_TIMEOUT_MS = 10 * 60_000
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000
const AUTHORIZE_PATH = '/oidc/oauth2/authorize'
const TOKEN_PATH = '/oidc/oauth2/token'
const REVOKE_PATH = '/oidc/oauth2/revoke'

function baseUrl(value: string): string {
  return value.replace(/\/+$/, '')
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function sha256Base64Url(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('base64url')
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value))
}

function isDict(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

export function createPkce(rng: Rng): PkcePair {
  const verifier = base64Url(rng(32))
  return { verifier, challenge: sha256Base64Url(verifier) }
}

export interface AuthorizationUrlParams {
  issuerUrl: string
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
  scopes?: readonly string[]
}

/** 构造授权码 + PKCE S256 的授权 URL。 */
export function buildAuthorizationUrl(params: AuthorizationUrlParams): string {
  const url = new URL(`${baseUrl(params.issuerUrl)}${AUTHORIZE_PATH}`)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', params.clientId)
  url.searchParams.set('redirect_uri', params.redirectUri)
  url.searchParams.set('scope', (params.scopes ?? DEFAULT_SCOPES).join(' '))
  url.searchParams.set('state', params.state)
  url.searchParams.set('code_challenge', params.codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  return url.toString()
}

export interface RequestTokenOptions {
  endpoint: string
  form: Record<string, string>
  fetchImpl: typeof fetch
  timeoutMs?: number
}

/** 表单 POST 到 token 端点并解析标准 token 响应。 */
export async function requestToken(options: RequestTokenOptions): Promise<TokenSet> {
  const body = new URLSearchParams(options.form).toString()
  let response: Response
  try {
    response = await options.fetchImpl(options.endpoint, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body,
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS),
    })
  } catch (err) {
    const error = asError(err)
    const code = error.name === 'TimeoutError' || error.name === 'AbortError' ? 'REMOTE_OIDC_TIMEOUT' : 'REMOTE_OIDC_NETWORK'
    throw new OidcError(code, `OIDC token request failed: ${error.message}`, { cause: error })
  }

  const text = await response.text()
  let payload: unknown
  try {
    payload = text ? JSON.parse(text) : undefined
  } catch {
    payload = undefined
  }

  if (!response.ok) {
    const oauthError = isDict(payload) ? readString(payload.error) : undefined
    const description = isDict(payload) ? readString(payload.error_description) : undefined
    const detail = [oauthError, description].filter(Boolean).join(': ')
    throw new OidcError(
      'REMOTE_OIDC_TOKEN_FAILED',
      `OIDC token endpoint rejected the request (HTTP ${response.status}${detail ? `, ${detail}` : ''})`,
      { status: response.status, oauthError },
    )
  }
  if (!isDict(payload)) {
    throw new OidcError('REMOTE_OIDC_TOKEN_FAILED', 'OIDC token endpoint returned a non-object body', {
      status: response.status,
    })
  }

  const accessToken = readString(payload.access_token)
  if (!accessToken) {
    throw new OidcError('REMOTE_OIDC_TOKEN_FAILED', 'OIDC token response is missing access_token', {
      status: response.status,
    })
  }
  const tokenType = readString(payload.token_type) ?? 'Bearer'
  if (tokenType.toLowerCase() !== 'bearer') {
    throw new OidcError('REMOTE_OIDC_TOKEN_FAILED', `unsupported OIDC token_type: ${tokenType}`, {
      status: response.status,
    })
  }
  const expiresIn =
    typeof payload.expires_in === 'number' && Number.isFinite(payload.expires_in) && payload.expires_in > 0
      ? payload.expires_in
      : 3600

  return {
    accessToken,
    refreshToken: readString(payload.refresh_token),
    expiresIn,
    tokenType,
  }
}

function parseCallback(input: string): URLSearchParams {
  const text = input.trim()
  if (!text) throw new OidcError('REMOTE_OIDC_CALLBACK_INVALID', 'callback URL is empty')
  let url: URL
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) url = new URL(text)
    else if (text.startsWith('?')) url = new URL(`http://127.0.0.1/${text}`)
    else if (text.includes('=')) url = new URL(`http://127.0.0.1/?${text}`)
    else throw new Error('missing query string')
  } catch {
    throw new OidcError('REMOTE_OIDC_CALLBACK_INVALID', 'callback URL is not a valid absolute or query URL')
  }
  return url.searchParams
}

const CALLBACK_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>GoofToken</title></head>
<body style="font-family:system-ui,sans-serif;padding:2rem">授权已收到，可以返回 dsh。</body></html>`

export function createOidcClient(deps: OidcDeps): OidcClient {
  const fetchImpl = deps.fetch ?? globalThis.fetch
  const rng = deps.rng ?? systemRng
  const now = deps.now ?? Date.now
  const callbackTimeoutMs = deps.callbackTimeoutMs ?? DEFAULT_CALLBACK_TIMEOUT_MS
  const requestTimeoutMs = deps.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
  const tokenEndpoint = `${baseUrl(deps.config.issuerUrl)}${TOKEN_PATH}`
  const revokeEndpoint = `${baseUrl(deps.config.issuerUrl)}${REVOKE_PATH}`

  let current: OidcLogin | null = null
  let refreshInFlight: Promise<Grant | null> | null = null
  let disposed = false

  async function makeGrant(tokens: TokenSet, previous?: Grant): Promise<Grant> {
    const nodeId = previous?.nodeId ?? (await deps.nodeId())
    return {
      issuer: deps.config.issuerUrl,
      relay: deps.config.relayUrl,
      clientId: deps.config.clientId,
      nodeId,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken ?? previous?.refreshToken ?? '',
      expiresAt: now() + tokens.expiresIn * 1000,
      domain: deps.domain,
    }
  }

  async function exchangeCode(code: string, redirectUri: string, verifier: string): Promise<Grant> {
    const tokens = await requestToken({
      endpoint: tokenEndpoint,
      fetchImpl,
      timeoutMs: requestTimeoutMs,
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: deps.config.clientId,
        code_verifier: verifier,
      },
    })
    const grant = await makeGrant(tokens)
    await deps.store.saveGrant(grant)
    return grant
  }

  async function start(): Promise<OidcLogin> {
    if (disposed) throw new OidcError('REMOTE_OIDC_CANCELLED', 'OIDC client has been disposed')
    if (current) return current

    const state = base64Url(rng(32))
    const pkce = createPkce(rng)
    let settled = false
    let exchanging = false
    let server: ReturnType<typeof createServer> | undefined
    let timeout: NodeJS.Timeout | undefined
    let resolveWait!: (grant: Grant) => void
    let rejectWait!: (error: Error) => void
    const waiting = new Promise<Grant>((resolve, reject) => {
      resolveWait = resolve
      rejectWait = reject
    })
    // 无头场景下可能没人 await；保留拒绝语义但不产生未处理拒绝。
    void waiting.catch(() => undefined)

    let login!: OidcLogin
    let redirectUri = ''

    function closeListener(): void {
      if (timeout) {
        clearTimeout(timeout)
        timeout = undefined
      }
      if (server) {
        const active = server
        server = undefined
        active.close()
        active.closeAllConnections()
      }
    }

    function settleGrant(grant: Grant): void {
      if (settled) return
      settled = true
      closeListener()
      if (current === login) current = null
      resolveWait(grant)
    }

    function settleError(error: Error): void {
      if (settled) return
      settled = true
      closeListener()
      if (current === login) current = null
      rejectWait(error)
    }

    function submit(callbackUrl: string): void {
      if (settled) throw new OidcError('REMOTE_OIDC_CANCELLED', 'OIDC login already finished')
      if (exchanging) throw new OidcError('REMOTE_OIDC_CALLBACK_INVALID', 'OIDC callback is already being exchanged')
      const params = parseCallback(callbackUrl)
      const error = readString(params.get('error'))
      if (error) {
        const description = readString(params.get('error_description'))
        // 先让 HTTP 处理器写完响应，再结束登录等待。
        queueMicrotask(() => {
          settleError(
            new OidcError(
              'REMOTE_OIDC_AUTHORIZATION_FAILED',
              `OIDC authorization failed: ${error}${description ? ` (${description})` : ''}`,
            ),
          )
        })
        return
      }
      const code = readString(params.get('code'))
      if (!code) throw new OidcError('REMOTE_OIDC_CALLBACK_INVALID', 'OIDC callback has no authorization code')
      if (params.get('state') !== state) {
        throw new OidcError('REMOTE_OIDC_STATE_MISMATCH', 'OIDC callback state does not match the authorization request')
      }
      exchanging = true
      void exchangeCode(code, redirectUri, pkce.verifier).then(settleGrant, (failure: unknown) => {
        const failureError = asError(failure)
        deps.log.warn(`OIDC 登录失败: ${failureError.message}`)
        settleError(
          failureError instanceof OidcError
            ? failureError
            : new OidcError('REMOTE_OIDC_TOKEN_FAILED', failureError.message, { cause: failureError }),
        )
      })
    }

    server = createServer((request, response) => {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1')
      if (url.pathname !== '/callback') {
        response.statusCode = 404
        response.end('not found')
        return
      }
      try {
        submit(url.toString())
      } catch (err) {
        const error = asError(err)
        deps.log.warn(`OIDC 回调无效: ${error.message}`)
        response.statusCode = 400
        response.setHeader('content-type', 'text/plain; charset=utf-8')
        response.end(error.message)
        return
      }
      response.statusCode = 200
      response.setHeader('content-type', 'text/html; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.end(CALLBACK_HTML)
    })

    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error): void => reject(err)
        server!.once('error', onError)
        server!.listen(0, '127.0.0.1', () => {
          server!.off('error', onError)
          resolve()
        })
      })
    } catch (err) {
      closeListener()
      throw new OidcError('REMOTE_OIDC_LISTEN_FAILED', `cannot listen for the OIDC callback: ${asError(err).message}`, {
        cause: err,
      })
    }

    const address = server?.address() as AddressInfo | null
    const port = address?.port
    if (!port) {
      closeListener()
      throw new OidcError('REMOTE_OIDC_LISTEN_FAILED', 'OIDC callback listener has no local port')
    }
    redirectUri = `http://127.0.0.1:${port}/callback`
    const authorizationUrl = buildAuthorizationUrl({
      issuerUrl: deps.config.issuerUrl,
      clientId: deps.config.clientId,
      redirectUri,
      state,
      codeChallenge: pkce.challenge,
    })

    login = {
      authorizationUrl,
      redirectUri,
      wait: () => waiting,
      submit,
      cancel(reason?: string) {
        settleError(new OidcError('REMOTE_OIDC_CANCELLED', reason ?? 'OIDC login cancelled'))
      },
    }
    current = login
    timeout = setTimeout(() => {
      settleError(new OidcError('REMOTE_OIDC_TIMEOUT', 'timed out waiting for the OIDC authorization callback'))
    }, callbackTimeoutMs)
    timeout.unref?.()
    deps.log.info(`OIDC 授权 URL: ${authorizationUrl}`)
    return login
  }

  async function doRefresh(grant: Grant): Promise<Grant | null> {
    const state = await deps.store.load()
    const currentGrant = state.grant ?? grant
    if (!currentGrant.refreshToken) return null
    let tokens: TokenSet
    try {
      tokens = await requestToken({
        endpoint: tokenEndpoint,
        fetchImpl,
        timeoutMs: requestTimeoutMs,
        form: {
          grant_type: 'refresh_token',
          refresh_token: currentGrant.refreshToken,
          client_id: deps.config.clientId,
        },
      })
    } catch (err) {
      if (err instanceof OidcError && err.code === 'REMOTE_OIDC_TOKEN_FAILED') {
        deps.log.warn(`OIDC refresh token 被拒绝: ${err.message}`)
        return null
      }
      throw err
    }
    const next = await makeGrant(tokens, currentGrant)
    await deps.store.saveGrant(next)
    deps.log.debug('OIDC access token 已刷新')
    return next
  }

  return {
    start,
    pending: () => current,
    refresh(grant) {
      if (refreshInFlight) return refreshInFlight
      const flight = doRefresh(grant).finally(() => {
        refreshInFlight = null
      })
      refreshInFlight = flight
      return flight
    },
    async revoke(grant) {
      const token = grant.refreshToken || grant.accessToken
      if (!token) return
      try {
        const response = await fetchImpl(revokeEndpoint, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            token,
            token_type_hint: grant.refreshToken ? 'refresh_token' : 'access_token',
          }).toString(),
          signal: AbortSignal.timeout(requestTimeoutMs),
        })
        if (!response.ok) deps.log.debug(`OIDC revoke 返回 HTTP ${response.status}`)
      } catch (err) {
        deps.log.debug(`OIDC revoke 失败: ${asError(err).message}`)
      }
    },
    dispose() {
      disposed = true
      current?.cancel('OIDC client disposed')
      current = null
    },
  }
}
