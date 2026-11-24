/**
 * 插件入口与 Host 核心组装（契约 §6.1）：配置解析、凭据、OIDC、隧道、
 * 会话桥 / WebUI 桥 / 控制路由的接线，以及 `/remote` 命令状态机。
 */
import { randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { hostname } from 'node:os'

import type { Context } from '@deepseek-ai/cordis'

import {
  registerRemoteCommand,
  type RemoteCommandController,
  type RemoteCommandResult,
} from './commands.js'
import { resolveConfig, resolveDomain, type Config as RemoteControlConfig, type Logger, type ResolvedConfig } from './config.js'
import { registerControlRoute } from './control-route.js'
import { createCredentialStore, type CredentialStore, type DeviceIdentity, type Grant } from './credentials.js'
import { generateDeviceKeys, systemRng, type Rng } from './crypto/index.js'
import { createOidcClient, type OidcClient, type OidcError, type OidcLogin } from './oidc.js'
import { createSessionBridge, type SessionBridge } from './session-bridge.js'
import { createTunnel, type Tunnel, type TunnelStatus } from './tunnel.js'
import type { HelloAckFrame, NotifyKind, SessionSummary, StateSyncFrame } from './tunnel-protocol.js'
import { createWebUiBridge, type WebUiBridge } from './webui-bridge.js'

export { Config } from './config.js'
export type { Logger } from './config.js'

export const name = 'remote-control'
export const inject = ['agents', 'sessions', 'credentials', 'commands']

const GRANT_SKEW_MS = 60_000

const requireFromHere = createRequire(import.meta.url)

function readPluginVersion(): string {
  try {
    const pkg = requireFromHere('../package.json') as { version?: unknown }
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0'
  } catch {
    return '0.0.0'
  }
}

const PLUGIN_VERSION = readPluginVersion()
const DSH_VERSION = process.env.DSH_VERSION?.trim() || 'unknown'

type ResumeAction =
  | { kind: 'session'; sessionId: string }
  | { kind: 'webui' }
  | { kind: 'connect' }

interface NotifyEvent {
  kind: NotifyKind
  sessionId?: string
  title: string
  summary: string
}

function success(text: string): RemoteCommandResult {
  return { kind: 'success', text }
}

function failure(text: string): RemoteCommandResult {
  return { kind: 'error', text }
}

function messageOf(value: unknown): string {
  return value instanceof Error ? value.message : String(value)
}

function isHeadless(): boolean {
  return Boolean(process.env.SSH_CONNECTION || process.env.SSH_CLIENT || process.env.CI) || !process.stdin.isTTY
}

function formatExpiry(ms: number): string {
  const iso = new Date(ms).toISOString()
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`
}

function loginInstruction(login: OidcLogin): string {
  const lines = [`需要登录 GoofToken，请在浏览器打开：`, login.authorizationUrl]
  if (isHeadless()) {
    lines.push('当前为无头环境：授权后复制浏览器地址栏中的完整回调 URL，然后运行：')
    lines.push('/remote login <完整回调 URL>')
  } else {
    lines.push('浏览器完成授权后会自动继续；也可粘贴回调 URL：/remote login <URL>')
  }
  return lines.join('\n')
}

export function apply(ctx: Context, config: RemoteControlConfig): void {
  const cordisLogger = ctx.logger('remote-control')
  const emit = (method: 'debug' | 'info' | 'warn' | 'error') => (...args: unknown[]) =>
    (cordisLogger[method] as (...values: unknown[]) => void)(...args)
  const log: Logger = {
    debug: emit('debug'),
    info: emit('info'),
    warn: emit('warn'),
    error: emit('error'),
  }

  if (!config.enabled) {
    log.info('remote-control 已禁用')
    return
  }

  let resolved: ResolvedConfig
  try {
    resolved = resolveConfig(config)
  } catch (err) {
    log.error(`remote-control 配置无效: ${messageOf(err)}`)
    return
  }
  const domain = resolveDomain(config, resolved.issuerUrl)

  const store: CredentialStore = createCredentialStore(ctx, log)
  const rng: Rng = systemRng

  let disposed = false
  let sessionBridge: SessionBridge | null = null
  let webuiBridge: WebUiBridge | null = null
  let helloAck: HelloAckFrame | null = null
  let pendingLogin: OidcLogin | null = null
  let pendingAction: ResumeAction | null = null
  let loginCompletion: Promise<Grant> | null = null
  let loginStart: Promise<OidcLogin> | null = null
  let announcePromise: Promise<void> | null = null

  // ---- 身份与凭据 -------------------------------------------------------

  async function ensureIdentity(): Promise<DeviceIdentity> {
    const state = await store.load()
    if (state.identity) return state.identity
    const generated = generateDeviceKeys(rng)
    await store.saveIdentity(generated)
    log.info(`已生成本机 E2EE 设备密钥：${generated.bundle.keyId}`)
    return generated
  }

  async function currentNodeId(): Promise<string> {
    const identity = await ensureIdentity()
    const state = await store.load()
    if (state.grant && state.grant.nodeId !== identity.bundle.keyId) {
      await store.saveGrant({ ...state.grant, nodeId: identity.bundle.keyId })
      log.info(`节点 id 已更新为 ${identity.bundle.keyId}`)
    }
    return identity.bundle.keyId
  }

  async function validGrant(): Promise<Grant | null> {
    const state = await store.load()
    const grant = state.grant
    if (!grant) return null
    if (grant.expiresAt - Date.now() > GRANT_SKEW_MS) return grant
    if (!grant.refreshToken) return null
    try {
      const refreshed = await oidc.refresh(grant)
      if (refreshed) log.info('OIDC access token 已刷新')
      return refreshed
    } catch (err) {
      log.warn(`刷新 OIDC access token 失败: ${messageOf(err)}`)
      return null
    }
  }

  async function refreshGrantForTunnel(): Promise<Grant | null> {
    const state = await store.load()
    if (!state.grant) return null
    try {
      return await oidc.refresh(state.grant)
    } catch (err) {
      log.warn(`隧道 token 刷新失败: ${messageOf(err)}`)
      return null
    }
  }

  // ---- 可选服务探测（webServer / connection / approval / questions / presets）

  const optionalServices = ['webServer', 'connection', 'approval', 'userQuestions', 'permissionPresets'].filter(
    (serviceName) => {
      try {
        return Boolean(ctx.get(serviceName))
      } catch {
        return false
      }
    },
  )
  log.debug(`可选服务：${optionalServices.length > 0 ? optionalServices.join(', ') : '无'}`)

  // ---- OIDC / 隧道 ------------------------------------------------------

  const oidc: OidcClient = createOidcClient({
    config: resolved,
    store,
    log,
    domain,
    nodeId: currentNodeId,
    rng,
  })

  const tunnel: Tunnel = createTunnel({
    config: resolved,
    store,
    log,
    refreshToken: refreshGrantForTunnel,
  })

  // ---- 状态帧 -----------------------------------------------------------

  function listSessions(): unknown[] {
    try {
      const service = ctx.get('sessions') as { list?: () => unknown[] } | undefined
      const sessions = service?.list?.()
      return Array.isArray(sessions) ? sessions : []
    } catch {
      return []
    }
  }

  function webUiEnabled(): boolean {
    if (!webuiBridge) return false
    try {
      const state = webuiBridge.status()
      return Boolean(state.available && state.active)
    } catch {
      return false
    }
  }

  function sessionSummaries(): SessionSummary[] {
    if (!sessionBridge) return []
    const sessions = listSessions()
    let agents: { turnBoundaryOf?: (session: unknown) => { openTurnStartSeq?: unknown } | undefined } | undefined
    let titles: { get?: (session: unknown) => { title?: unknown } | undefined } | undefined
    try {
      agents = ctx.get('agents') as typeof agents
      titles = ctx.get('sessionTitle') as typeof titles
    } catch {
      agents = undefined
      titles = undefined
    }

    return sessionBridge.shared.map((sessionId) => {
      const session = sessions.find((candidate) => {
        const record = candidate as { id?: unknown } | undefined
        return record?.id !== undefined && String(record.id) === sessionId
      }) as
        | { header?: { cwd?: unknown } }
        | undefined
      let title = sessionId
      try {
        const snapshot = titles?.get?.(session)
        if (typeof snapshot?.title === 'string' && snapshot.title) title = snapshot.title
      } catch {
        // 标题服务不可用时退回会话 id。
      }
      let status: 'running' | 'idle' = 'idle'
      try {
        const boundary = agents?.turnBoundaryOf?.(session)
        if (boundary?.openTurnStartSeq !== null && boundary?.openTurnStartSeq !== undefined) status = 'running'
      } catch {
        // 会话不在 agent 注册表中时按 idle 处理。
      }
      const cwd = typeof session?.header?.cwd === 'string' ? session.header.cwd : process.cwd()
      return { sessionId, title, cwd, status }
    })
  }

  async function sendHello(): Promise<void> {
    if (!sessionBridge || !webuiBridge) return
    const identity = await ensureIdentity()
    const state = await store.load()
    if (state.grant && state.grant.nodeId !== identity.bundle.keyId) {
      await store.saveGrant({ ...state.grant, nodeId: identity.bundle.keyId })
    }
    tunnel.sendText({
      t: 'hello',
      proto: 1,
      nodeId: identity.bundle.keyId,
      hostname: hostname(),
      platform: process.platform,
      dshVersion: DSH_VERSION,
      pluginVersion: PLUGIN_VERSION,
      webUiEnabled: webUiEnabled(),
      sessions: sessionSummaries(),
      publicKey: identity.bundle,
    })
  }

  async function sendStateSyncNow(): Promise<void> {
    if (!sessionBridge || !webuiBridge || tunnel.status !== 'online') return
    const identity = await ensureIdentity()
    const frame: StateSyncFrame = {
      t: 'state.sync',
      webUiEnabled: webUiEnabled(),
      sessions: sessionSummaries(),
      publicKey: identity.bundle,
    }
    tunnel.sendText(frame)
  }

  function handleTunnelStatus(next: TunnelStatus): void {
    if (next === 'online') {
      helloAck = null
      const announce = (async () => {
        await sendHello()
        await sendStateSyncNow()
      })()
      announcePromise = announce
      void announce
        .catch((err: unknown) => log.warn(`发送隧道 hello 失败: ${messageOf(err)}`))
        .finally(() => {
          if (announcePromise === announce) announcePromise = null
        })
      return
    }
    announcePromise = null
    if (next === 'error' || next === 'offline') {
      helloAck = null
      log.debug(`tunnel 状态：${next}`)
    }
  }

  function handleNotify(event: NotifyEvent): string | undefined {
    if (event.kind === 'turn_end' || event.kind === 'turn_error') {
      if (!resolved.notifyOnTurnEnd) return undefined
    } else if (!resolved.notifyOnApproval) {
      return undefined
    }
    if (tunnel.status !== 'online') return undefined
    const eventId = randomUUID()
    tunnel.sendText({
      t: 'notify.trigger',
      eventId,
      sessionId: event.sessionId,
      kind: event.kind,
      title: event.title,
      summary: event.summary,
      ts: Date.now(),
    })
    return eventId
  }

  /** 交互在宽限窗口内已结算：让中继撤销本次订阅消息投递。 */
  function handleNotifyCancel(eventId: string): void {
    if (typeof eventId !== 'string' || !eventId) return
    if (tunnel.status !== 'online') return
    tunnel.sendText({ t: 'notify.cancel', eventId })
  }

  // ---- 隧道生命周期 -----------------------------------------------------

  async function syncTunnel(): Promise<void> {
    if (disposed) return
    const shared = sessionBridge?.shared.length ?? 0
    const needsTunnel = shared > 0 || webUiEnabled()
    if (!needsTunnel) {
      tunnel.disconnect()
      return
    }
    const grant = await validGrant()
    if (!grant) {
      await startLogin(pendingLogin || loginStart ? null : { kind: 'connect' })
      return
    }
    if (tunnel.status === 'online') {
      if (announcePromise) {
        await announcePromise.catch(() => undefined)
        return
      }
      await sendStateSyncNow()
      return
    }
    try {
      await tunnel.connect()
    } catch (err) {
      log.warn(`连接远控隧道失败: ${messageOf(err)}`)
    }
  }

  function requestSync(): void {
    if (disposed) return
    void syncTunnel().catch((err: unknown) => log.warn(`同步远控状态失败: ${messageOf(err)}`))
  }

  // ---- 登录状态机 -------------------------------------------------------

  async function resumeAction(action: ResumeAction | null): Promise<void> {
    if (!action) {
      await syncTunnel()
      return
    }
    if (action.kind === 'session') {
      if (sessionBridge) {
        const result = await sessionBridge.toggle(action.sessionId, true)
        if (!result.ok) log.warn(`登录后开启会话远控失败: ${result.error ?? 'unknown error'}`)
      }
    } else if (action.kind === 'webui') {
      if (webuiBridge) {
        const result = await webuiBridge.toggle(true)
        if (!result.ok) log.warn(`登录后开启 WebUI 远控失败: ${result.error ?? 'unknown error'}`)
      }
    }
    await syncTunnel()
  }

  async function startLogin(action: ResumeAction | null): Promise<OidcLogin> {
    if (disposed) throw new Error('remote-control 已卸载')
    if (action) pendingAction = action
    if (pendingLogin) return pendingLogin
    if (loginStart) return loginStart

    const starting = oidc.start().then((login) => {
      pendingLogin = login
      const completion = login.wait().then(
        async (grant) => {
          pendingLogin = null
          loginCompletion = null
          const resume = pendingAction
          pendingAction = null
          log.info('OIDC 登录成功')
          try {
            await resumeAction(resume)
          } catch (err) {
            log.warn(`登录后恢复远控失败: ${messageOf(err)}`)
          }
          return grant
        },
        (err: unknown) => {
          pendingLogin = null
          loginCompletion = null
          pendingAction = null
          const code = (err as Partial<OidcError> | undefined)?.code
          if (code !== 'REMOTE_OIDC_CANCELLED' && code !== 'REMOTE_OIDC_TIMEOUT') {
            log.warn(`OIDC 登录失败: ${messageOf(err)}`)
          }
          throw err
        },
      )
      loginCompletion = completion
      void completion.catch(() => undefined)
      return login
    })
    loginStart = starting.finally(() => {
      loginStart = null
    })
    return loginStart
  }

  async function waitForLogin(login: OidcLogin): Promise<Grant> {
    if (loginCompletion) return loginCompletion
    return login.wait()
  }

  // ---- 命令控制器 -------------------------------------------------------

  async function enableSession(sessionId: string, enabled: boolean): Promise<RemoteCommandResult> {
    if (!sessionBridge) return failure('会话桥尚未初始化，请稍后重试。')
    if (!enabled) {
      const result = await sessionBridge.toggle(sessionId, false)
      await syncTunnel()
      return result.ok ? success('已关闭当前会话的远控。') : failure(`关闭会话远控失败：${result.error ?? 'unknown error'}`)
    }
    const grant = await validGrant()
    if (!grant) {
      const login = await startLogin({ kind: 'session', sessionId })
      return success(loginInstruction(login))
    }
    const result = await sessionBridge.toggle(sessionId, true)
    if (!result.ok) return failure(`开启会话远控失败：${result.error ?? 'unknown error'}`)
    await syncTunnel()
    const status = sessionBridge.status(sessionId)
    return success(
      status.safetyNumber ? `已开启会话远控。\n安全码：${status.safetyNumber}` : '已开启会话远控。',
    )
  }

  async function enableWebUi(enabled: boolean): Promise<RemoteCommandResult> {
    if (!webuiBridge) return failure('WebUI 桥尚未初始化，请稍后重试。')
    if (enabled) {
      const status = webuiBridge.status()
      if (!status.available) return failure('当前 dsh 未启用 WebUI，无法开启 WebUI 远控。')
      const grant = await validGrant()
      if (!grant) {
        const login = await startLogin({ kind: 'webui' })
        return success(loginInstruction(login))
      }
    }
    const result = await webuiBridge.toggle(enabled)
    if (!result.ok) return failure(`${enabled ? '开启' : '关闭'} WebUI 远控失败：${result.error ?? 'unknown error'}`)
    await syncTunnel()
    return success(enabled ? '已开启整机 WebUI 远控。' : '已关闭整机 WebUI 远控。')
  }

  async function stopAll(): Promise<RemoteCommandResult> {
    if (sessionBridge) await sessionBridge.stopAll()
    webuiBridge?.stopAll()
    tunnel.disconnect()
    return success('已关闭全部远控并断开隧道。')
  }

  async function approveClient(safetyNumber: string): Promise<RemoteCommandResult> {
    if (!sessionBridge) return failure('会话桥尚未初始化，请稍后重试。')
    const value = typeof safetyNumber === 'string' ? safetyNumber.trim() : ''
    if (!value) return failure('用法：/remote approve <安全码>')
    const result = await sessionBridge.approve(value)
    if (!result.ok) return failure(`批准客户端失败：${result.error ?? 'unknown error'}`)
    return success(`已批准 ${result.approved} 个客户端，正在发送会话快照。`)
  }

  async function resetClient(value: string): Promise<RemoteCommandResult> {
    if (!sessionBridge) return failure('会话桥尚未初始化，请稍后重试。')
    const target = typeof value === 'string' ? value.trim() : ''
    if (!target) return failure('用法：/remote reset <clientId|安全码>')
    const result = await sessionBridge.reset(target)
    if (!result.ok) return failure(`重置客户端失败：${result.error ?? 'unknown error'}`)
    return success(`已清理 ${result.reset} 条客户端密钥/待批准记录。`)
  }

  async function statusReport(): Promise<RemoteCommandResult> {
    const state = await store.load()
    const lines: string[] = []
    if (state.grant) {
      const expired = state.grant.expiresAt <= Date.now()
      lines.push(
        `登录：已登录（节点 ${state.grant.nodeId}，令牌${expired ? '已过期' : `至 ${formatExpiry(state.grant.expiresAt)}`}）`,
      )
    } else {
      lines.push('登录：未登录（运行 /remote login）')
    }
    lines.push(`隧道：${tunnel.status}`)
    if (helloAck) lines.push(`配额：档位 ${helloAck.tierCode}，最多 ${helloAck.maxNodes} 个节点`)
    const shared = sessionBridge?.shared ?? []
    lines.push(`共享会话：${shared.length}`)
    const webState = webuiBridge?.status()
    if (webState) {
      lines.push(`WebUI：${webState.available ? (webState.active ? '已开启' : '已关闭') : '不可用'}`)
    }
    const safety = shared
      .map((sessionId) => sessionBridge?.status(sessionId).safetyNumber)
      .filter((value): value is string => Boolean(value))
    if (safety.length === 1) lines.push(`安全码：${safety[0]}`)
    else safety.forEach((value, index) => lines.push(`安全码（会话 ${index + 1}）：${value}`))
    const pending = sessionBridge?.pendingApprovals() ?? []
    if (pending.length > 0) {
      lines.push(`待批准客户端：${pending.length}（对比小程序安全码后运行 /remote approve <安全码>）`)
      for (const entry of pending.slice(0, 5)) {
        lines.push(`  安全码 ${entry.safetyNumber}（会话 ${entry.sessionId}）`)
      }
      if (pending.length > 5) lines.push(`  另有 ${pending.length - 5} 个待批准客户端`)
    }
    const clients = sessionBridge?.clients() ?? []
    if (clients.length > 0) {
      lines.push(`远控客户端：${clients.length}（如需重新配对：/remote reset <clientId>）`)
      for (const entry of clients.slice(0, 5)) {
        const label = entry.pending ? '待批准' : '已连接'
        lines.push(`  ${label} ${entry.clientId.slice(0, 12)}… 安全码 ${entry.safetyNumber}`)
      }
      if (clients.length > 5) lines.push(`  另有 ${clients.length - 5} 个客户端`)
    }
    if (pendingLogin) lines.push(`待完成登录：${pendingLogin.authorizationUrl}`)
    return success(lines.join('\n'))
  }

  async function loginCommand(callbackUrl?: string): Promise<RemoteCommandResult> {
    if (callbackUrl) {
      const login = pendingLogin
      if (!login) return failure('没有待完成的登录，请先运行 /remote login 获取授权 URL。')
      try {
        login.submit(callbackUrl)
      } catch (err) {
        return failure(`回调 URL 无效：${messageOf(err)}`)
      }
      try {
        await waitForLogin(login)
        return success('登录成功。')
      } catch (err) {
        return failure(`登录失败：${messageOf(err)}`)
      }
    }
    if (pendingLogin) return success(loginInstruction(pendingLogin))
    const login = await startLogin(null)
    return success(loginInstruction(login))
  }

  async function logoutCommand(): Promise<RemoteCommandResult> {
    const state = await store.load()
    pendingLogin?.cancel('logout')
    pendingLogin = null
    loginCompletion = null
    pendingAction = null
    if (state.grant) await oidc.revoke(state.grant)
    if (sessionBridge) await sessionBridge.stopAll()
    webuiBridge?.stopAll()
    tunnel.disconnect()
    await store.clear()
    helloAck = null
    return success('已退出登录并清理本机远控凭据。')
  }

  const controller: RemoteCommandController = {
    session: enableSession,
    webui: enableWebUi,
    stop: stopAll,
    status: statusReport,
    approve: approveClient,
    reset: resetClient,
    login: loginCommand,
    logout: logoutCommand,
  }

  // ---- 桥接与消息路由 ---------------------------------------------------

  const bridgeDeps = {
    config: resolved,
    store,
    tunnel,
    rng,
    log,
    onStateChanged: requestSync,
    onNotify: handleNotify,
    onNotifyCancel: handleNotifyCancel,
  }

  sessionBridge = createSessionBridge(ctx, bridgeDeps)
  webuiBridge = createWebUiBridge(ctx, bridgeDeps)

  tunnel.onText((frame) => {
    try {
      if (frame.t === 'ping') {
        tunnel.sendText({ t: 'pong', ts: typeof frame.ts === 'number' ? frame.ts : Date.now() })
        return
      }
      if (frame.t === 'pong') return
      if (frame.t === 'hello.ack') {
        helloAck = frame as HelloAckFrame
        log.info(`隧道已就绪：档位 ${String(frame.tierCode ?? '?')}，最多 ${String(frame.maxNodes ?? '?')} 个节点`)
        return
      }
      sessionBridge?.handleText(frame)
      webuiBridge?.handleText(frame)
    } catch (err) {
      log.error(`处理隧道文本帧失败: ${messageOf(err)}`)
    }
  })

  tunnel.onBinary((kind, streamId, payload) => {
    try {
      webuiBridge?.handleBinary(kind, streamId, payload)
    } catch (err) {
      log.error(`处理隧道二进制帧失败: ${messageOf(err)}`)
    }
  })

  tunnel.onStatus(handleTunnelStatus)

  ctx.effect(() => () => {
    if (disposed) return
    disposed = true
    pendingLogin?.cancel('remote-control 卸载')
    pendingLogin = null
    loginCompletion = null
    pendingAction = null
    try {
      oidc.dispose()
    } catch (err) {
      log.warn(`关闭 OIDC 客户端失败: ${messageOf(err)}`)
    }
    try {
      sessionBridge?.dispose()
    } catch (err) {
      log.warn(`关闭会话桥失败: ${messageOf(err)}`)
    }
    try {
      webuiBridge?.stopAll()
    } catch (err) {
      log.warn(`关闭 WebUI 桥失败: ${messageOf(err)}`)
    }
    try {
      tunnel.dispose()
    } catch (err) {
      log.warn(`关闭隧道失败: ${messageOf(err)}`)
    }
  })

  ctx.effect(() => {
    try {
      return registerControlRoute(ctx, {
        runtime: { session: sessionBridge!, webui: webuiBridge! },
        log,
      })
    } catch (err) {
      log.warn(`控制路由未注册: ${messageOf(err)}`)
      return () => undefined
    }
  })

  ctx.effect(() => registerRemoteCommand(ctx, controller, log))

  log.info(`remote-control 已加载：issuer=${resolved.issuerUrl} relay=${resolved.relayUrl}`)
}
