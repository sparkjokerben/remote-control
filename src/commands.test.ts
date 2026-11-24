import type { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'

import type { Logger } from './config'
import { registerRemoteCommand, type RemoteCommandController, type RemoteCommandResult } from './commands'

const LOG: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
}

const OK: RemoteCommandResult = { kind: 'success', text: 'ok' }

function harness(overrides: Partial<RemoteCommandController> = {}) {
  const controller: RemoteCommandController = {
    session: vi.fn(async () => OK),
    webui: vi.fn(async () => OK),
    stop: vi.fn(async () => OK),
    status: vi.fn(async () => OK),
    approve: vi.fn(async () => OK),
    reset: vi.fn(async () => OK),
    login: vi.fn(async () => OK),
    logout: vi.fn(async () => OK),
    ...overrides,
  }
  let handler:
    | ((invocation: { agent?: { id: unknown }; rawInput: string }) => Promise<RemoteCommandResult>)
    | undefined
  const unregister = vi.fn()
  const commands = {
    register(definition: {
      handler: (invocation: { agent?: { id: unknown }; rawInput: string }) => Promise<RemoteCommandResult>
    }) {
      handler = definition.handler
      return unregister
    },
  }
  const ctx = {
    get: (serviceName: string) => (serviceName === 'commands' ? commands : undefined),
  } as unknown as Context
  const dispose = registerRemoteCommand(ctx, controller, LOG)
  return {
    controller,
    dispose,
    unregister,
    run: (rawInput: string, id: unknown = 'session-1') =>
      handler!({ rawInput, ...(id === null ? {} : { agent: { id } }) }),
  }
}

describe('/remote command', () => {
  it('toggles the current session by default and with off/stop', async () => {
    const harnessed = harness()
    expect((await harnessed.run('')).kind).toBe('success')
    expect(harnessed.controller.session).toHaveBeenCalledWith('session-1', true)

    await harnessed.run(' session ')
    expect(harnessed.controller.session).toHaveBeenLastCalledWith('session-1', true)

    await harnessed.run('session off')
    expect(harnessed.controller.session).toHaveBeenLastCalledWith('session-1', false)

    await harnessed.run('session stop')
    expect(harnessed.controller.session).toHaveBeenLastCalledWith('session-1', false)
  })

  it('rejects unknown arguments and missing sessions', async () => {
    const harnessed = harness()
    expect((await harnessed.run('session maybe')).kind).toBe('error')
    expect((await harnessed.run('webui maybe')).kind).toBe('error')
    expect((await harnessed.run('nope')).kind).toBe('error')
    expect((await harnessed.run('', null)).kind).toBe('error')
    expect(harnessed.controller.session).not.toHaveBeenCalled()
  })

  it('routes webui, stop, status, login, logout', async () => {
    const harnessed = harness()
    await harnessed.run('webui')
    expect(harnessed.controller.webui).toHaveBeenLastCalledWith(true)
    await harnessed.run('webui off')
    expect(harnessed.controller.webui).toHaveBeenLastCalledWith(false)

    await harnessed.run('stop')
    expect(harnessed.controller.stop).toHaveBeenCalledTimes(1)

    await harnessed.run('status')
    expect(harnessed.controller.status).toHaveBeenCalledTimes(1)

    await harnessed.run('approve 12345 67890 12345 67890')
    expect(harnessed.controller.approve).toHaveBeenLastCalledWith('12345 67890 12345 67890')
    expect((await harnessed.run('approve')).kind).toBe('error')
    expect(harnessed.controller.approve).toHaveBeenCalledTimes(1)

    await harnessed.run('login')
    expect(harnessed.controller.login).toHaveBeenLastCalledWith(undefined)
    await harnessed.run('login http://127.0.0.1:9/callback?code=x&state=y')
    expect(harnessed.controller.login).toHaveBeenLastCalledWith('http://127.0.0.1:9/callback?code=x&state=y')

    await harnessed.run('logout')
    expect(harnessed.controller.logout).toHaveBeenCalledTimes(1)
  })

  it('turns controller exceptions into error results and unregisters', async () => {
    const harnessed = harness({
      status: async () => {
        throw new Error('boom')
      },
    })
    const result = await harnessed.run('status')
    expect(result).toEqual({ kind: 'error', text: '/remote 失败：boom' })
    harnessed.dispose()
    expect(harnessed.unregister).toHaveBeenCalledTimes(1)
  })
})
