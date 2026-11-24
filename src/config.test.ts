import { describe, expect, it } from 'vitest'

import { Config, ConfigError, resolveConfig, resolveDomain } from './config'

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (err) {
    return (err as ConfigError).code
  }
  return undefined
}

describe('resolveConfig', () => {
  it('derives issuer and relay from the deployment domain', () => {
    const resolved = resolveConfig({ ...Config({}), domain: 'gooftoken.com', nodeName: 'dev-box' })
    expect(resolved.issuerUrl).toBe('https://www.gooftoken.com')
    expect(resolved.relayUrl).toBe('wss://mp.gooftoken.com')
    expect(resolved.clientId).toBe('dsh-remote')
    expect(resolved.nodeName).toBe('dev-box')
    expect(resolved.notifyOnTurnEnd).toBe(true)
    expect(resolved.notifyOnApproval).toBe(true)
  })

  it('strips a leading www and trailing slashes in overrides', () => {
    const resolved = resolveConfig({
      ...Config({}),
      domain: 'www.example.com',
      relayUrl: 'wss://relay.example.com/',
    })
    expect(resolved.issuerUrl).toBe('https://www.example.com')
    expect(resolved.relayUrl).toBe('wss://relay.example.com')
  })

  it('accepts explicit loopback overrides for local development', () => {
    const resolved = resolveConfig({
      ...Config({}),
      domain: '',
      issuerUrl: 'http://localhost:8080/',
      relayUrl: 'ws://127.0.0.1:8787',
    })
    expect(resolved.issuerUrl).toBe('http://localhost:8080')
    expect(resolved.relayUrl).toBe('ws://127.0.0.1:8787')
  })

  it('requires a domain when neither endpoint is overridden', () => {
    expect(codeOf(() => resolveConfig({ ...Config({}), domain: '' }))).toBe('REMOTE_CONFIG_MISSING_DOMAIN')
  })

  it('rejects a domain containing a scheme or path', () => {
    expect(codeOf(() => resolveConfig({ ...Config({}), domain: 'https://example.com' }))).toBe(
      'REMOTE_CONFIG_INVALID_DOMAIN',
    )
    expect(codeOf(() => resolveConfig({ ...Config({}), domain: 'example.com/path' }))).toBe(
      'REMOTE_CONFIG_INVALID_DOMAIN',
    )
  })

  it('rejects insecure non-loopback endpoints and wrong protocols', () => {
    expect(
      codeOf(() =>
        resolveConfig({
          ...Config({}),
          domain: 'example.com',
          issuerUrl: 'http://www.example.com',
          relayUrl: 'wss://mp.example.com',
        }),
      ),
    ).toBe('REMOTE_CONFIG_INVALID_ISSUER')
    expect(
      codeOf(() =>
        resolveConfig({
          ...Config({}),
          domain: 'example.com',
          relayUrl: 'https://mp.example.com',
        }),
      ),
    ).toBe('REMOTE_CONFIG_INVALID_RELAY')
  })

  it('keeps explicit false notification flags', () => {
    const resolved = resolveConfig({
      ...Config({}),
      domain: 'example.com',
      notifyOnTurnEnd: false,
      notifyOnApproval: false,
    })
    expect(resolved.notifyOnTurnEnd).toBe(false)
    expect(resolved.notifyOnApproval).toBe(false)
  })

  it('derives the grant domain from the issuer when domain is absent', () => {
    expect(resolveDomain({ ...Config({}), domain: '' }, 'https://www.example.com:8443')).toBe('www.example.com:8443')
  })
})
