import { existsSync } from 'node:fs'
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import type { Context } from '@deepseek-ai/cordis'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import type { Logger } from './config'
import {
  createCredentialStore,
  type DeviceIdentity,
  type Grant,
} from './credentials'

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
  expiresAt: 1_700_000_000_000,
  domain: 'example.com',
}

const IDENTITY: DeviceIdentity = {
  bundle: {
    keyId: 'kid',
    ikSignPub: 'ikSignPub',
    ikDhPub: 'ikDhPub',
    spkPub: 'spkPub',
    spkSig: 'spkSig',
  },
  privateKeys: {
    ikSignPriv: 'ikSignPriv',
    ikDhPriv: 'ikDhPriv',
    spkPriv: 'spkPriv',
  },
}

function fakeContext(credentials: unknown): Context {
  return {
    get: (serviceName: string) => (serviceName === 'credentials' ? credentials : undefined),
  } as unknown as Context
}

let home: string
let previousHome: string | undefined

beforeEach(async () => {
  previousHome = process.env.DSH_HOME
  home = await mkdtemp(join(tmpdir(), 'gt-remote-creds-'))
  process.env.DSH_HOME = home
})

afterEach(async () => {
  if (previousHome === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = previousHome
  await rm(home, { recursive: true, force: true })
})

describe('file credential store', () => {
  it('round-trips grant, identity and pins with 0600 permissions', async () => {
    const store = createCredentialStore(fakeContext(undefined), LOG)
    await store.saveGrant(GRANT)
    await store.saveIdentity(IDENTITY)
    await store.setPin('peer-1', 'hash-1')

    const path = join(home, 'gooftoken-remote.json')
    expect(existsSync(path)).toBe(true)
    expect((await stat(path)).mode & 0o777).toBe(0o600)

    const reopened = createCredentialStore(fakeContext(undefined), LOG)
    expect(await reopened.load()).toEqual({
      grant: GRANT,
      identity: IDENTITY,
      pins: { 'peer-1': 'hash-1' },
    })

    await reopened.clear()
    expect(existsSync(path)).toBe(false)
    expect(await reopened.load()).toEqual({ pins: {} })
  })

  it('serializes concurrent pin writes without losing entries', async () => {
    const store = createCredentialStore(fakeContext(undefined), LOG)
    await Promise.all(Array.from({ length: 8 }, (_, index) => store.setPin(`peer-${index}`, `hash-${index}`)))
    const state = await store.load()
    expect(Object.keys(state.pins)).toHaveLength(8)
    expect(state.pins['peer-7']).toBe('hash-7')
  })

  it('rejects a corrupt document instead of treating it as empty', async () => {
    await writeFile(join(home, 'gooftoken-remote.json'), '{not json', 'utf8')
    const store = createCredentialStore(fakeContext(undefined), LOG)
    await expect(store.load()).rejects.toMatchObject({
      name: 'CredentialStoreError',
      code: 'REMOTE_CREDENTIALS_CORRUPT',
    })
  })
})

describe('credentials service store', () => {
  it('prefers ctx.credentials records and never touches the file', async () => {
    let record: unknown
    const calls: string[] = []
    const provider = {
      async readRecord(key: string) {
        calls.push(`read:${key}`)
        return record
      },
      async modifyRecord(key: string, mutate: (current: unknown) => Promise<unknown>) {
        calls.push(`modify:${key}`)
        record = await mutate(record)
        return record
      },
      async deleteRecord(key: string) {
        calls.push(`delete:${key}`)
        record = undefined
      },
    }
    const store = createCredentialStore(fakeContext(provider), LOG)
    await store.saveGrant(GRANT)
    await store.saveIdentity(IDENTITY)
    await store.setPin('peer-1', 'hash-1')

    expect(record).toMatchObject({ kind: 'grant' })
    expect((record as { payload: unknown }).payload).toMatchObject({
      grant: { accessToken: 'at_1' },
      identity: { bundle: { keyId: 'kid' } },
      pins: { 'peer-1': 'hash-1' },
    })
    expect(calls).toContain('modify:remote-control/state')
    expect(existsSync(join(home, 'gooftoken-remote.json'))).toBe(false)

    expect(await store.load()).toEqual({ grant: GRANT, identity: IDENTITY, pins: { 'peer-1': 'hash-1' } })
    expect(calls).toContain('read:remote-control/state')
    await store.clear()
    expect(record).toBeUndefined()
  })

  it('rejects a foreign record tag', async () => {
    const provider = {
      async readRecord() {
        return { kind: 'api-key', key: 'sk-x' }
      },
      async modifyRecord() {
        return undefined
      },
      async deleteRecord() {},
    }
    const store = createCredentialStore(fakeContext(provider), LOG)
    await expect(store.load()).rejects.toMatchObject({ code: 'REMOTE_CREDENTIALS_CORRUPT' })
  })
})
