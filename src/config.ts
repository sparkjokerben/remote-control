/**
 * 插件配置与地址派生（契约 §6.1）：域名派生 `https://www.<domain>` 与
 * `wss://mp.<domain>`，显式 issuerUrl / relayUrl 优先。
 */
import { hostname } from 'node:os'

import z from '@deepseek-ai/schemastery'

/** Host 核心各模块共用的日志接口。 */
export type Logger = Pick<Console, 'debug' | 'info' | 'warn' | 'error'>

export interface Config {
  enabled: boolean
  domain: string
  issuerUrl?: string
  relayUrl?: string
  clientId: string
  nodeName?: string
  notifyOnTurnEnd: boolean
  notifyOnApproval: boolean
}

/** Schemastery 配置；字段与 {@link Config} 同名合并（类型 + 值）。 */
export const Config = z.object({
  enabled: z.boolean().default(true),
  domain: z.string().default(''),
  issuerUrl: z.string().default(''),
  relayUrl: z.string().default(''),
  clientId: z.string().default('dsh-remote'),
  nodeName: z.string().default(''),
  notifyOnTurnEnd: z.boolean().default(true),
  notifyOnApproval: z.boolean().default(true),
})

export interface ResolvedConfig {
  issuerUrl: string
  relayUrl: string
  clientId: string
  nodeName: string
  notifyOnTurnEnd: boolean
  notifyOnApproval: boolean
}

export type ConfigErrorCode =
  | 'REMOTE_CONFIG_MISSING_DOMAIN'
  | 'REMOTE_CONFIG_INVALID_DOMAIN'
  | 'REMOTE_CONFIG_INVALID_ISSUER'
  | 'REMOTE_CONFIG_INVALID_RELAY'

export class ConfigError extends Error {
  readonly code: ConfigErrorCode

  constructor(code: ConfigErrorCode, message: string) {
    super(message)
    this.name = 'ConfigError'
    this.code = code
  }
}

const HOST_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::\d{1,5})?$/

function nonEmpty(value: string | undefined): string | undefined {
  const text = value?.trim()
  return text ? text : undefined
}

function isLoopbackHostname(host: string): boolean {
  const value = host.toLowerCase().replace(/^\[|\]$/g, '')
  return value === 'localhost' || value === '::1' || value === '0:0:0:0:0:0:0:1' || /^127(?:\.\d{1,3}){3}$/.test(value)
}

function normalizeDomain(raw: string | undefined): string {
  const domain = nonEmpty(raw)?.toLowerCase()
  if (!domain) throw new ConfigError('REMOTE_CONFIG_MISSING_DOMAIN', 'domain is required: set config.domain or both issuerUrl and relayUrl')
  if (domain.includes('://') || domain.includes('/') || domain.includes('?') || domain.includes('#')) {
    throw new ConfigError('REMOTE_CONFIG_INVALID_DOMAIN', 'domain must be a bare host name without scheme or path')
  }
  const bare = domain.startsWith('www.') ? domain.slice(4) : domain
  if (!HOST_PATTERN.test(bare)) {
    throw new ConfigError('REMOTE_CONFIG_INVALID_DOMAIN', `domain is not a valid host name: ${raw}`)
  }
  return bare
}

function normalizeIssuer(raw: string): string {
  const text = raw.trim().replace(/\/+$/, '')
  let url: URL
  try {
    url = new URL(text)
  } catch {
    throw new ConfigError('REMOTE_CONFIG_INVALID_ISSUER', 'issuerUrl must be an absolute http(s) URL')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError('REMOTE_CONFIG_INVALID_ISSUER', 'issuerUrl must use http or https')
  }
  if (url.protocol === 'http:' && !isLoopbackHostname(url.hostname)) {
    throw new ConfigError('REMOTE_CONFIG_INVALID_ISSUER', 'issuerUrl must use https unless it points at loopback')
  }
  return text
}

function normalizeRelay(raw: string): string {
  const text = raw.trim().replace(/\/+$/, '')
  let url: URL
  try {
    url = new URL(text)
  } catch {
    throw new ConfigError('REMOTE_CONFIG_INVALID_RELAY', 'relayUrl must be an absolute ws(s) URL')
  }
  if (url.protocol !== 'wss:' && url.protocol !== 'ws:') {
    throw new ConfigError('REMOTE_CONFIG_INVALID_RELAY', 'relayUrl must use ws or wss')
  }
  if (url.protocol === 'ws:' && !isLoopbackHostname(url.hostname)) {
    throw new ConfigError('REMOTE_CONFIG_INVALID_RELAY', 'relayUrl must use wss unless it points at loopback')
  }
  return text
}

/**
 * 解析运行时配置：未显式给出的地址由 domain 派生。
 * issuerUrl / relayUrl 同时缺省且没有 domain 时抛出清晰的 ConfigError。
 */
export function resolveConfig(
  config: Config,
  fallbacks: { domain?: string; nodeName?: string } = {},
): ResolvedConfig {
  const domain = nonEmpty(config.domain) ?? nonEmpty(fallbacks.domain)
  const issuerOverride = nonEmpty(config.issuerUrl)
  const relayOverride = nonEmpty(config.relayUrl)

  let issuerUrl: string
  let relayUrl: string
  if (issuerOverride && relayOverride) {
    issuerUrl = normalizeIssuer(issuerOverride)
    relayUrl = normalizeRelay(relayOverride)
  } else {
    if (!domain) {
      throw new ConfigError('REMOTE_CONFIG_MISSING_DOMAIN', 'domain is required: set config.domain or both issuerUrl and relayUrl')
    }
    const bare = normalizeDomain(domain)
    issuerUrl = issuerOverride ? normalizeIssuer(issuerOverride) : `https://www.${bare}`
    relayUrl = relayOverride ? normalizeRelay(relayOverride) : `wss://mp.${bare}`
  }

  const clientId = nonEmpty(config.clientId) ?? 'dsh-remote'
  const nodeName = nonEmpty(config.nodeName) ?? nonEmpty(fallbacks.nodeName) ?? hostname() ?? 'dsh'

  return {
    issuerUrl,
    relayUrl,
    clientId,
    nodeName,
    notifyOnTurnEnd: config.notifyOnTurnEnd !== false,
    notifyOnApproval: config.notifyOnApproval !== false,
  }
}

/** 从显式 domain 或 issuer 推导用于凭据记录的部署域名。 */
export function resolveDomain(config: Config, issuerUrl: string): string {
  const configured = nonEmpty(config.domain)
  if (configured) {
    try {
      return normalizeDomain(configured)
    } catch {
      // 已由 resolveConfig 校验；这里只做兜底。
    }
  }
  try {
    return new URL(issuerUrl).host
  } catch {
    return issuerUrl
  }
}
