/**
 * `/remote` 命令注册与参数解析（契约 §6）：session / webui / stop / status /
 * approve / login / logout；所有结果统一为 `{ kind, text }`。
 */
import type { Context } from '@deepseek-ai/cordis'

import type { Logger } from './config.js'

export interface RemoteCommandResult {
  kind: 'success' | 'error'
  text: string
}

export interface RemoteCommandController {
  session(sessionId: string, enabled: boolean): Promise<RemoteCommandResult>
  webui(enabled: boolean): Promise<RemoteCommandResult>
  stop(): Promise<RemoteCommandResult>
  status(): Promise<RemoteCommandResult>
  approve(safetyNumber: string): Promise<RemoteCommandResult>
  reset(value: string): Promise<RemoteCommandResult>
  login(callbackUrl?: string): Promise<RemoteCommandResult>
  logout(): Promise<RemoteCommandResult>
}

interface CommandInvocationLike {
  readonly agent?: { readonly id: unknown }
  readonly rawInput: string
  readonly signal?: AbortSignal
}

interface CommandDefinitionLike {
  name: string
  description: string
  handler(invocation: CommandInvocationLike): RemoteCommandResult | Promise<RemoteCommandResult>
}

interface CommandsLike {
  register(definition: CommandDefinitionLike): () => void
}

const USAGE = [
  '用法：',
  '/remote [session] [off|stop]  开启或关闭当前会话的加密远控',
  '/remote webui [off|stop]      开启或关闭整机 WebUI 远控',
  '/remote stop                  关闭全部远控并断开隧道',
  '/remote status                查看登录、隧道、共享会话与安全码',
  '/remote approve <安全码>      批准首次连接的远控客户端',
  '/remote reset <clientId|安全码> 清理客户端密钥记录（小程序重装后重新配对）',
  '/remote login [callback-url]  OIDC 登录；无头环境粘贴回调 URL',
  '/remote logout                吊销令牌并清理凭据',
].join('\n')

function error(text: string): RemoteCommandResult {
  return { kind: 'error', text }
}

function parse(rawInput: string): { command: string; rest: string } {
  const text = rawInput.trim()
  if (!text) return { command: '', rest: '' }
  const match = /^(\S+)(?:\s+([\s\S]*))?$/.exec(text)
  return {
    command: (match?.[1] ?? '').toLowerCase(),
    rest: (match?.[2] ?? '').trim(),
  }
}

function parseToggle(rest: string): boolean | undefined {
  const value = rest.toLowerCase()
  if (!value || value === 'on') return true
  if (value === 'off' || value === 'stop') return false
  return undefined
}

function sessionIdOf(invocation: CommandInvocationLike): string | undefined {
  const id = invocation.agent?.id
  if (id === undefined || id === null) return undefined
  const text = String(id).trim()
  return text || undefined
}

export function registerRemoteCommand(
  ctx: Context,
  controller: RemoteCommandController,
  log: Logger,
): () => void {
  let commands: CommandsLike | undefined
  try {
    commands = ctx.get('commands') as CommandsLike | undefined
  } catch {
    commands = undefined
  }
  if (!commands?.register) {
    log.warn('commands 服务不可用，/remote 未注册')
    return () => undefined
  }

  return commands.register({
    name: 'remote',
    description: '远程控制：session | webui | stop | status | approve | reset | login | logout',
    async handler(invocation) {
      const { command, rest } = parse(invocation.rawInput)
      try {
        switch (command) {
          case '':
          case 'session': {
            const sessionId = sessionIdOf(invocation)
            if (!sessionId) return error('当前没有活动会话，无法开启会话远控。')
            const enabled = parseToggle(rest)
            if (enabled === undefined) return error(`未知的 session 参数：${rest}\n${USAGE}`)
            return await controller.session(sessionId, enabled)
          }
          case 'webui': {
            const enabled = parseToggle(rest)
            if (enabled === undefined) return error(`未知的 webui 参数：${rest}\n${USAGE}`)
            return await controller.webui(enabled)
          }
          case 'stop':
            return await controller.stop()
          case 'status':
            return await controller.status()
          case 'approve': {
            if (!rest) return error(`用法：/remote approve <安全码>\n${USAGE}`)
            return await controller.approve(rest)
          }
          case 'reset': {
            if (!rest) return error(`用法：/remote reset <clientId|安全码>\n${USAGE}`)
            return await controller.reset(rest)
          }
          case 'login':
            return await controller.login(rest || undefined)
          case 'logout':
            return await controller.logout()
          default:
            return error(`未知的 /remote 子命令：${command}\n${USAGE}`)
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        log.warn(`/remote ${command} 失败: ${message}`)
        return error(`/remote 失败：${message}`)
      }
    },
  })
}
